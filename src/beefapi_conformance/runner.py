from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from pathlib import Path

from .clients import ClientCommand, assistant_text, resolve_binary
from .model import CellResult, MatrixCell, Route, TurnResult
from .redact import redact
from .wire import (
    RecordingProxy,
    crosstalk,
    latency_stats,
    parse_sse,
    sse_text,
    termination,
    wire_summary,
)
from .wire import wire_verdict as _wire_verdict

SERVER_EVIDENCE_FIELDS = {"status", "commit", "route", "terminal", "receipt", "usage"}
PROXY_ADAPTERS = {"claude-code", "codex", "grok-build"}
MARKER_BYTES = b"BEEFAPI_CONFORMANCE_FILE_OK\n"
AGENT_V1_RESPONSE_ID = re.compile(
    r'"id"\s*:\s*"resp_bf_agentv1_u[0-9]+_c[0-9]+_([A-Za-z0-9]+)"'
)


def _now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass
class _Worker:
    """One logical user in a cell: its own nonce, workspace, and outcome."""

    index: int
    nonce: str
    turns: list[TurnResult] = field(default_factory=list)
    answers: list[str] = field(default_factory=list)
    request_ids: set[str] = field(default_factory=set)
    duration_ms: int = 0

    @property
    def passed(self) -> bool:
        return bool(self.turns) and all(item.status == "pass" for item in self.turns)


def _nonce(index: int) -> str:
    return f"BEEFAPI-NONCE-{uuid.uuid4().hex[:8].upper()}-{index}"


def _render(text: str, nonce: str, workspace: Path | None = None) -> str:
    text = text.replace("{{nonce}}", nonce)
    if workspace is not None:
        text = text.replace("{{workspace}}", str(workspace))
    return text


def run_cell(
    cell: MatrixCell,
    allow_local_tools: bool = False,
    require_server_evidence: bool = False,
    routes: dict[str, Route] | None = None,
    capture_dir: Path | None = None,
) -> CellResult:
    started = time.monotonic()
    started_epoch = int(time.time())
    started_at = _now()
    base_token = (
        os.environ.get(cell.route.token_env or "") if cell.route.token_env else None
    )
    evidence_fence = _evidence_fence(cell, base_token)
    if cell.client.adapter == "raw-http":
        return _run_http_cell(
            cell,
            started_at,
            started,
            started_epoch,
            base_token,
            evidence_fence,
            require_server_evidence,
            routes,
        )
    binary = resolve_binary(cell.client)
    if not binary:
        return _result(
            cell, "skip", started_at, started, None, [], "client binary not found"
        )
    version = _version(binary, cell)
    if cell.scenario.requires_local_tools and not allow_local_tools:
        return _result(
            cell,
            "skip",
            started_at,
            started,
            version,
            [],
            "local tools require --allow-local-tools",
        )
    if cell.route.auth_mode == "gateway_token" and not base_token:
        return _result(
            cell,
            "skip",
            started_at,
            started,
            version,
            [],
            f"missing {cell.route.token_env}",
        )
    base_url = (
        os.environ.get(cell.route.base_url_env or "")
        if cell.route.base_url_env
        else cell.route.base_url
    )
    if cell.route.auth_mode == "gateway_token" and not base_url:
        return _result(
            cell, "skip", started_at, started, version, [], "route base URL is missing"
        )

    proxy: RecordingProxy | None = None
    if base_url and cell.client.adapter in PROXY_ADAPTERS:
        proxy = RecordingProxy(
            base_url,
            timeout_seconds=cell.scenario.timeout_seconds,
            capture_bodies=capture_dir is not None,
        )
    try:
        # Clients can leave background children writing into their isolated
        # home (codex clones plugins there); never fail a cell on cleanup.
        with tempfile.TemporaryDirectory(
            prefix="beefapi-conformance-", ignore_cleanup_errors=True
        ) as tmp:
            token = _request_token(cell, base_token)
            client_base_url = proxy.base_url if proxy else base_url
            workers = [
                _Worker(index, _nonce(index))
                for index in range(1, cell.scenario.concurrency + 1)
            ]
            if len(workers) == 1:
                _run_client_worker(
                    cell, workers[0], binary, Path(tmp), token, client_base_url
                )
            else:
                with ThreadPoolExecutor(max_workers=len(workers)) as pool:
                    list(
                        pool.map(
                            lambda worker: _run_client_worker(
                                cell,
                                worker,
                                binary,
                                Path(tmp) / f"user-{worker.index}",
                                token,
                                client_base_url,
                            ),
                            workers,
                        )
                    )
            turn_results = [turn for worker in workers for turn in worker.turns]
            observed_request_ids = set().union(*(w.request_ids for w in workers))
            status = "pass" if all(worker.passed for worker in workers) else "fail"
            detail = ""
            evidence: dict[str, object] = {
                "workspace_marker_sha256": hashlib.sha256(MARKER_BYTES).hexdigest(),
                "route_auth_mode": cell.route.auth_mode,
            }
            if len(workers) > 1:
                problems = crosstalk(
                    {worker.nonce: "\n".join(worker.answers) for worker in workers}
                )
                evidence["concurrency"] = {
                    "users": len(workers),
                    "passed": sum(1 for worker in workers if worker.passed),
                    "latency": latency_stats([w.duration_ms for w in workers]),
                    "crosstalk": problems,
                }
                if problems and status == "pass":
                    status = "fail"
                    detail = "concurrent responses leaked across users"
            if proxy:
                exchanges = proxy.exchanges()
                verdict = _wire_verdict(
                    exchanges, cell.scenario.expect_wire, cell.scenario.concurrency
                )
                evidence["wire"] = {**wire_summary(exchanges), "verdict": verdict}
                if status == "pass" and verdict["status"] != "pass":
                    status = "fail"
                    detail = f"wire evidence failed: {verdict['detail']}"
                if capture_dir is not None:
                    evidence["wire"]["capture"] = str(
                        _write_capture(cell, exchanges, capture_dir, token)
                    )
            server_evidence = _server_evidence(
                cell,
                base_token,
                started_epoch,
                evidence_fence,
                observed_request_ids or None,
            )
            evidence["server_evidence"] = server_evidence
            if (
                require_server_evidence
                and cell.route.release_evidence_required
                and server_evidence.get("status") != "pass"
            ):
                status = "fail"
                detail = detail or "this tier requires passing server evidence"
            return _result(
                cell,
                status,
                started_at,
                started,
                version,
                turn_results,
                detail,
                evidence,
            )
    finally:
        if proxy:
            proxy.stop()


def _write_capture(
    cell: MatrixCell, exchanges: list, capture_dir: Path, token: str | None
) -> Path:
    """Persist the full redacted wire exchanges of a native cell as JSONL so
    real client request shapes can be promoted into replay fixtures."""
    capture_dir.mkdir(parents=True, exist_ok=True)
    path = capture_dir / (cell.id.replace("/", "__") + ".jsonl")
    with path.open("w", encoding="utf-8") as handle:
        for exchange in exchanges:
            record = {
                **exchange.summary(),
                "request_body": exchange.request_body,
                "response_body": exchange.response_body,
            }
            handle.write(redact(json.dumps(record, ensure_ascii=False), (token or "",)))
            handle.write("\n")
    return path


def _run_client_worker(
    cell: MatrixCell,
    worker: _Worker,
    binary: str,
    root: Path,
    token: str | None,
    base_url: str | None,
) -> None:
    """Drive one real client session through every turn of the scenario."""
    worker_started = time.monotonic()
    workspace = root / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    (workspace / "marker.txt").write_bytes(MARKER_BYTES)
    command = ClientCommand(cell, binary, root, token, base_url)
    command.prepare()
    env = command.environment()
    for index, turn in enumerate(cell.scenario.turns, 1):
        turn_started = time.monotonic()
        marker = _render(turn.marker, worker.nonce)
        try:
            prompt = _render(turn.prompt, worker.nonce, workspace)
            # stdin must be closed: codex exec (and potentially other
            # headless clients) block waiting for piped stdin input.
            completed = subprocess.run(
                command.command(prompt, index),
                cwd=workspace,
                env=env,
                text=True,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=cell.scenario.timeout_seconds,
                check=False,
            )
            output = redact(completed.stdout or "", (token or "",))
            worker.request_ids.update(AGENT_V1_RESPONSE_ID.findall(output))
            command.observe_output(output)
            missing = [event for event in turn.expected_events if event not in output]
            missing.extend(
                "any:" + "|".join(group)
                for group in turn.expected_any_events
                if not any(event in output for event in group)
            )
            answer = assistant_text(cell.client.adapter, output)
            worker.answers.append(answer)
            status = (
                "pass"
                if completed.returncode == 0 and marker in answer and not missing
                else "fail"
            )
            worker.turns.append(
                TurnResult(
                    index=index,
                    status=status,
                    duration_ms=int((time.monotonic() - turn_started) * 1000),
                    returncode=completed.returncode,
                    marker=marker,
                    missing_events=missing,
                    output_tail=output[-4000:],
                )
            )
            if status != "pass":
                break
        except subprocess.TimeoutExpired as exc:
            raw = exc.stdout if isinstance(exc.stdout, str) else ""
            worker.turns.append(
                TurnResult(
                    index,
                    "fail",
                    int((time.monotonic() - turn_started) * 1000),
                    None,
                    marker,
                    ["terminal"],
                    redact(raw, (token or "",))[-4000:],
                )
            )
            break
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            worker.turns.append(
                TurnResult(
                    index,
                    "fail",
                    int((time.monotonic() - turn_started) * 1000),
                    None,
                    marker,
                    ["client_execution"],
                    redact(str(exc), (token or "",))[-4000:],
                )
            )
            break
    worker.duration_ms = int((time.monotonic() - worker_started) * 1000)


@dataclass
class _HttpOutcome:
    status_code: int | None
    request_id: str | None
    output: str
    text: str
    duration_ms: int
    stream_detail: str


def _http_request(
    cell: MatrixCell,
    base_url: str,
    token: str | None,
    prompt: str,
    payload: object | None = None,
    *,
    stream: bool | None = None,
    protocol: str | None = None,
    endpoint: str | None = None,
) -> _HttpOutcome:
    protocol = protocol or cell.scenario.protocol
    stream = cell.scenario.stream if stream is None else stream
    if payload is None:
        payload = _http_payload(cell, cell.model.client_model(cell.client.id), prompt)
    request = urllib.request.Request(
        base_url.rstrip("/") + (endpoint or cell.scenario.http_endpoint or ""),
        data=json.dumps(payload).encode(),
        headers=_http_headers(protocol, token),
        method="POST",
    )
    started = time.monotonic()
    status_code: int | None = None
    request_id: str | None = None
    try:
        with urllib.request.urlopen(
            request, timeout=cell.scenario.timeout_seconds
        ) as response:
            status_code = response.status
            request_id = response.headers.get("X-Oneapi-Request-Id")
            output = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        request_id = exc.headers.get("X-Oneapi-Request-Id") if exc.headers else None
        output = exc.read().decode("utf-8", "replace")
    except (OSError, TimeoutError) as exc:
        output = str(exc)
    duration_ms = int((time.monotonic() - started) * 1000)
    stream_detail = ""
    if stream:
        events = parse_sse(output)
        text = sse_text(protocol, events)
        ended = termination(
            [name for name, _ in events],
            any(data == "[DONE]" for _, data in events),
        )
        if ended != "clean":
            stream_detail = f"stream terminated {ended}"
    else:
        text = _http_response_text(protocol, output)
    return _HttpOutcome(
        status_code, request_id, output, text, duration_ms, stream_detail
    )


def _route_endpoint(route: Route) -> tuple[str | None, str | None]:
    """Resolve (base_url, token) for a route from its manifest/environment."""
    base_url = (
        os.environ.get(route.base_url_env or "")
        if route.base_url_env
        else route.base_url
    )
    token = os.environ.get(route.token_env or "") if route.token_env else None
    return base_url, token


def _seed_history(
    cell: MatrixCell,
    base_url: str,
    token: str | None,
    routes: dict[str, Route] | None,
) -> tuple[object | None, dict[str, object], str]:
    """Run phase one of a history scenario against the source route/model and
    return the phase-two payload, evidence, and an error detail if it failed."""
    source = cell.scenario.history_source
    assert source is not None
    protocol = cell.scenario.protocol
    # Placeholders let a committed scenario stay route-agnostic; the local
    # route manifest names the actual "other" route/model to switch from.
    source_route = (source.route or "").replace(
        "{{history_route}}", cell.route.history_route or ""
    ) or None
    source_model = (source.model or "").replace(
        "{{history_model}}", cell.route.history_model or ""
    ) or None
    source = replace(source, route=source_route, model=source_model)
    seed_base_url, seed_token = base_url, token
    if source.route and source.route != cell.route.id:
        seed_route = (routes or {}).get(source.route)
        if seed_route is None:
            return None, {}, f"history_source route {source.route!r} is not loaded"
        seed_base_url, seed_token = _route_endpoint(seed_route)
        if not seed_base_url or (
            seed_route.auth_mode == "gateway_token" and not seed_token
        ):
            return None, {}, f"history_source route {source.route!r} lacks URL or token"
        seed_token = _request_token(
            MatrixCell(cell.client, seed_route, cell.model, cell.scenario), seed_token
        )
    seed_model = source.model or cell.model.client_model(cell.client.id)
    target_model = cell.model.client_model(cell.client.id)
    evidence: dict[str, object] = {
        "route": source.route or cell.route.id,
        "model": seed_model,
        "mode": source.mode,
    }

    if protocol == "messages":
        seed_payload: dict[str, object] = {
            "model": seed_model,
            "max_tokens": 2048,
            "messages": [{"role": "user", "content": source.seed_prompt}],
            "stream": False,
        }
        if source.thinking:
            seed_payload["thinking"] = {"type": "enabled", "budget_tokens": 1024}
        seed = _http_request(
            cell, seed_base_url, seed_token, "", seed_payload, stream=False
        )
        evidence["seed_status"] = seed.status_code
        try:
            body = json.loads(seed.output)
        except json.JSONDecodeError:
            body = {}
        content = body.get("content") if isinstance(body, dict) else None
        if not (seed.status_code and 200 <= seed.status_code < 300 and content):
            return None, evidence, f"history seed failed with HTTP {seed.status_code}"
        evidence["block_types"] = [
            item.get("type") for item in content if isinstance(item, dict)
        ]
        payload: dict[str, object] = {
            "model": target_model,
            "max_tokens": 2048,
            "messages": [
                {"role": "user", "content": source.seed_prompt},
                {"role": "assistant", "content": content},
                {"role": "user", "content": "{{prompt}}"},
            ],
        }
        if source.thinking:
            payload["thinking"] = {"type": "enabled", "budget_tokens": 1024}
        return payload, evidence, ""

    seed_payload = {
        "model": seed_model,
        "input": source.seed_prompt,
        "stream": False,
        "store": source.mode == "previous_response_id",
    }
    if source.thinking:
        seed_payload["reasoning"] = {"effort": "low"}
        seed_payload["include"] = ["reasoning.encrypted_content"]
    seed = _http_request(
        cell, seed_base_url, seed_token, "", seed_payload, stream=False
    )
    evidence["seed_status"] = seed.status_code
    try:
        body = json.loads(seed.output)
    except json.JSONDecodeError:
        body = {}
    output_items = body.get("output") if isinstance(body, dict) else None
    response_id = body.get("id") if isinstance(body, dict) else None
    if not (seed.status_code and 200 <= seed.status_code < 300 and output_items):
        return None, evidence, f"history seed failed with HTTP {seed.status_code}"
    evidence["block_types"] = [
        item.get("type") for item in output_items if isinstance(item, dict)
    ]
    evidence["response_id"] = response_id
    if source.mode == "previous_response_id":
        payload = {
            "model": target_model,
            "previous_response_id": response_id,
            "input": "{{prompt}}",
        }
    else:
        payload = {
            "model": target_model,
            "input": [
                {"role": "user", "content": source.seed_prompt},
                *output_items,
                {"role": "user", "content": "{{prompt}}"},
            ],
            "store": False,
        }
    if source.thinking:
        payload["reasoning"] = {"effort": "low"}
        payload["include"] = ["reasoning.encrypted_content"]
    return payload, evidence, ""


def _grade_http(
    cell: MatrixCell, outcome: _HttpOutcome, marker: str, token: str | None, index: int
) -> TurnResult:
    turn = cell.scenario.turns[0]
    sanitized = redact(outcome.output, (token or "",))
    missing = [item for item in turn.expected_events if item not in sanitized]
    missing.extend(
        "any:" + "|".join(group)
        for group in turn.expected_any_events
        if not any(event in sanitized for event in group)
    )
    if outcome.stream_detail:
        missing.append(outcome.stream_detail)
    passed = (
        outcome.status_code is not None
        and 200 <= outcome.status_code < 300
        and marker in outcome.text
        and not missing
    )
    return TurnResult(
        index,
        "pass" if passed else "fail",
        outcome.duration_ms,
        outcome.status_code,
        marker,
        missing,
        sanitized[-4000:],
    )


def _run_http_cell(
    cell: MatrixCell,
    started_at: str,
    started: float,
    started_epoch: int,
    base_token: str | None,
    evidence_fence: set[str] | None,
    require_server_evidence: bool,
    routes: dict[str, Route] | None = None,
) -> CellResult:
    base_url = (
        os.environ.get(cell.route.base_url_env or "")
        if cell.route.base_url_env
        else cell.route.base_url
    )
    if cell.route.auth_mode == "gateway_token" and not base_token:
        return _result(
            cell,
            "skip",
            started_at,
            started,
            "python-urllib",
            [],
            f"missing {cell.route.token_env}",
        )
    if not base_url or not cell.scenario.http_endpoint:
        return _result(
            cell,
            "skip",
            started_at,
            started,
            "python-urllib",
            [],
            "HTTP route or endpoint missing",
        )
    turn = cell.scenario.turns[0]
    token = _request_token(cell, base_token)
    concurrency = cell.scenario.concurrency
    nonces = [_nonce(index) for index in range(1, concurrency + 1)]
    evidence: dict[str, object] = {"route_auth_mode": cell.route.auth_mode}
    detail = ""

    if cell.scenario.history_source is not None:
        template, seed_evidence, seed_detail = _seed_history(
            cell, base_url, token, routes
        )
        evidence["history_source"] = seed_evidence
        if template is None:
            return _result(
                cell,
                "fail",
                started_at,
                started,
                "python-urllib",
                [],
                seed_detail,
                evidence,
            )
        prompt = _render(turn.prompt, nonces[0])
        payload = _render_http_payload(
            template, cell.model.client_model(cell.client.id), prompt
        )
        if isinstance(payload, dict):
            payload["stream"] = cell.scenario.stream
        outcome = _http_request(cell, base_url, token, prompt, payload)
        results = [
            _grade_http(cell, outcome, _render(turn.marker, nonces[0]), token, 1)
        ]
        outcomes = [outcome]
        evidence["http_status"] = outcome.status_code
    elif concurrency == 1:
        outcome = _http_request(cell, base_url, token, _render(turn.prompt, nonces[0]))
        results = [
            _grade_http(cell, outcome, _render(turn.marker, nonces[0]), token, 1)
        ]
        outcomes = [outcome]
        evidence["http_status"] = outcome.status_code
    else:
        # A serial baseline request first, then the concurrent burst. The
        # baseline is what one user sees alone; the burst is what they see
        # when everyone else is online.
        baseline = _http_request(cell, base_url, token, _render(turn.prompt, _nonce(0)))
        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            outcomes = list(
                pool.map(
                    lambda nonce: _http_request(
                        cell, base_url, token, _render(turn.prompt, nonce)
                    ),
                    nonces,
                )
            )
        results = [
            _grade_http(cell, outcome, _render(turn.marker, nonce), token, index)
            for index, (outcome, nonce) in enumerate(zip(outcomes, nonces), 1)
        ]
        stats = latency_stats([item.duration_ms for item in outcomes])
        slowdown = (
            round(stats["p95_ms"] / baseline.duration_ms, 2)
            if baseline.duration_ms
            else None
        )
        problems = crosstalk(dict(zip(nonces, (item.text for item in outcomes))))
        evidence["concurrency"] = {
            "users": concurrency,
            "passed": sum(1 for item in results if item.status == "pass"),
            "baseline_ms": baseline.duration_ms,
            "baseline_status": baseline.status_code,
            "latency": stats,
            "p95_slowdown": slowdown,
            "crosstalk": problems,
            "http_statuses": sorted({str(item.status_code) for item in outcomes}),
        }
        if problems:
            detail = "concurrent responses leaked across users"
        elif (
            cell.scenario.max_slowdown
            and slowdown is not None
            and slowdown > cell.scenario.max_slowdown
        ):
            detail = (
                f"p95 under load is {slowdown}x the serial baseline "
                f"(limit {cell.scenario.max_slowdown}x)"
            )
    status = "pass" if all(item.status == "pass" for item in results) else "fail"
    if detail:
        status = "fail"

    request_ids = {item.request_id for item in outcomes if item.request_id}
    server_evidence = _server_evidence(
        cell, base_token, started_epoch, evidence_fence, request_ids or None
    )
    evidence["server_evidence"] = server_evidence
    if (
        require_server_evidence
        and cell.route.release_evidence_required
        and server_evidence.get("status") != "pass"
    ):
        status = "fail"
        detail = detail or "this tier requires passing server evidence"
    return _result(
        cell, status, started_at, started, "python-urllib", results, detail, evidence
    )


def _http_payload(cell: MatrixCell, model: str, prompt: str) -> object:
    if cell.scenario.http_payload is not None:
        payload = _render_http_payload(cell.scenario.http_payload, model, prompt)
    elif cell.scenario.protocol == "messages":
        payload = {
            "model": model,
            "max_tokens": 4096,
            "messages": [{"role": "user", "content": prompt}],
        }
    elif cell.scenario.protocol == "chat":
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
        }
    else:
        payload = {"model": model, "input": prompt}
    if isinstance(payload, dict):
        payload["stream"] = cell.scenario.stream
    return payload


def _http_headers(protocol: str | None, token: str | None) -> dict[str, str]:
    if protocol == "messages":
        return {
            "content-type": "application/json",
            "x-api-key": token or "",
            "anthropic-version": "2023-06-01",
        }
    return {
        "content-type": "application/json",
        "authorization": f"Bearer {token or ''}",
    }


def _render_http_payload(value: object, model: str, prompt: str) -> object:
    if isinstance(value, dict):
        return {
            key: _render_http_payload(item, model, prompt)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_render_http_payload(item, model, prompt) for item in value]
    if isinstance(value, str):
        return value.replace("{{model}}", model).replace("{{prompt}}", prompt)
    return value


def _http_response_text(protocol: str | None, output: str) -> str:
    try:
        body = json.loads(output)
    except json.JSONDecodeError:
        return ""
    values: list[str] = []
    if protocol == "messages":
        content = body.get("content", []) if isinstance(body, dict) else []
        for item in content if isinstance(content, list) else []:
            if (
                isinstance(item, dict)
                and item.get("type") == "text"
                and isinstance(item.get("text"), str)
            ):
                values.append(item["text"])
    elif protocol == "chat":
        choices = body.get("choices", []) if isinstance(body, dict) else []
        for choice in choices if isinstance(choices, list) else []:
            message = choice.get("message", {}) if isinstance(choice, dict) else {}
            if message.get("role") == "assistant" and isinstance(
                message.get("content"), str
            ):
                values.append(message["content"])
    elif isinstance(body, dict):
        if isinstance(body.get("output_text"), str):
            values.append(body["output_text"])
        output_items = body.get("output", [])
        for item in output_items if isinstance(output_items, list) else []:
            if (
                not isinstance(item, dict)
                or item.get("type") != "message"
                or item.get("role") != "assistant"
            ):
                continue
            content_items = item.get("content", [])
            for content in content_items if isinstance(content_items, list) else []:
                if isinstance(content, dict) and isinstance(content.get("text"), str):
                    values.append(content["text"])
    return "\n".join(values)


def _server_evidence(
    cell: MatrixCell,
    token: str | None,
    started_epoch: int,
    evidence_fence: set[str] | None,
    expected_request_ids: set[str] | None,
) -> dict[str, object]:
    if cell.route.evidence_provider == "beefapi_token_log":
        return _beefapi_token_log_evidence(
            cell,
            token,
            started_epoch,
            evidence_fence,
            expected_request_ids,
        )
    env_name = cell.route.evidence_command_env
    command = os.environ.get(env_name or "") if env_name else None
    if not command:
        return {"status": "not_configured"}
    try:
        argv = json.loads(command)
        if not isinstance(argv, list) or not all(
            isinstance(item, str) for item in argv
        ):
            raise ValueError("evidence command must be a JSON argv array")
        completed = subprocess.run(
            argv,
            env={
                **os.environ,
                "BEEFAPI_CONFORMANCE_CELL_ID": cell.id,
                "BEEFAPI_CONFORMANCE_ROUTE_ID": cell.route.id,
                "BEEFAPI_CONFORMANCE_MODEL_ID": cell.model.id,
                "BEEFAPI_CONFORMANCE_SCENARIO_ID": cell.scenario.id,
            },
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=60,
            check=False,
        )
        payload = json.loads(completed.stdout) if completed.returncode == 0 else None
        if payload is not None:
            payload = json.loads(redact(json.dumps(payload), (token or "",)))
        valid = (
            isinstance(payload, dict)
            and payload.get("status") == "pass"
            and SERVER_EVIDENCE_FIELDS.issubset(payload)
        )
        detail = "" if valid else "evidence payload missing required pass fields"
        return {
            "status": "pass" if valid else "fail",
            "payload": payload,
            "detail": detail,
        }
    except (ValueError, json.JSONDecodeError, subprocess.SubprocessError) as exc:
        return {"status": "fail", "detail": redact(str(exc))}


def _request_token(cell: MatrixCell, token: str | None) -> str | None:
    if not token or not cell.route.pin_channel or not cell.route.channel_id:
        return token
    suffix = f"-{cell.route.channel_id}"
    if token.endswith(suffix):
        return token
    tail = token.rsplit("-", 1)
    if len(tail) == 2 and tail[1].isdigit():
        raise RuntimeError(
            f"credential is already pinned to channel {tail[1]}, requested {cell.route.channel_id}"
        )
    return token + suffix


def _beefapi_token_log_evidence(
    cell: MatrixCell,
    token: str | None,
    started_epoch: int,
    evidence_fence: set[str] | None,
    expected_request_ids: set[str] | None = None,
) -> dict[str, object]:
    if not token or not cell.route.base_url:
        return {
            "status": "fail",
            "detail": "token-log evidence lacks token or base URL",
        }
    if evidence_fence is None:
        return {"status": "fail", "detail": "pre-call token-log fence was unavailable"}
    if cell.client.adapter == "raw-http" and not expected_request_ids:
        return {
            "status": "fail",
            "detail": "raw HTTP response did not expose X-Oneapi-Request-Id",
        }
    minimum_count = (
        len(expected_request_ids) if expected_request_ids else len(cell.scenario.turns)
    )
    last_detail = "matching usage log not found"
    for attempt in range(8):
        try:
            logs, commit = _fetch_token_logs(cell.route.base_url, token)
            matches = _matching_usage_logs(
                cell,
                logs,
                started_epoch,
                evidence_fence,
                expected_request_ids,
            )
            if len(matches) >= minimum_count:
                payloads = [_usage_log_payload(cell, item, commit) for item in matches]
                final = [item for item in payloads if item.get("status") == "pass"]
                search_ok = cell.scenario.id != "web-search" or any(
                    int(item["usage"]["web_search_call_count"]) > 0 for item in payloads
                )
                if len(final) >= minimum_count and search_ok:
                    result = dict(final[0])
                    if len(final) > 1:
                        result["requests"] = final
                    return result
                last_detail = (
                    "native web search has no observed search call"
                    if not search_ok
                    else "matching usage receipt is not final"
                )
        except (OSError, TimeoutError, json.JSONDecodeError, RuntimeError) as exc:
            last_detail = redact(str(exc), (token,))
        if attempt < 7:
            time.sleep(1)
    return {"status": "fail", "detail": last_detail}


def _matching_usage_logs(
    cell: MatrixCell,
    logs: object,
    started_epoch: int,
    excluded_request_ids: set[str] | None = None,
    expected_request_ids: set[str] | None = None,
) -> list[dict[str, object]]:
    if not isinstance(logs, list):
        return []
    model_names = {cell.model.id, cell.model.client_model(cell.client.id)}
    matches: list[dict[str, object]] = []
    seen_request_ids: set[str] = set()
    for log in logs:
        if not isinstance(log, dict):
            continue
        if int(log.get("created_at", 0) or 0) < started_epoch - 3:
            continue
        request_id = str(log.get("request_id", "")).strip()
        if not request_id or request_id in (excluded_request_ids or set()):
            continue
        if expected_request_ids and request_id not in expected_request_ids:
            continue
        if int(log.get("type", 0) or 0) != 2:
            continue
        if str(log.get("model_name", "")) not in model_names:
            continue
        if (
            cell.route.channel_id
            and int(log.get("channel", 0) or 0) != cell.route.channel_id
        ):
            continue
        if cell.route.group and str(log.get("group", "")) != cell.route.group:
            continue
        if request_id in seen_request_ids:
            continue
        seen_request_ids.add(request_id)
        matches.append(log)
    return matches


def _evidence_fence(cell: MatrixCell, token: str | None) -> set[str] | None:
    if cell.route.evidence_provider != "beefapi_token_log":
        return set()
    if not token or not cell.route.base_url:
        return None
    try:
        logs, _ = _fetch_token_logs(cell.route.base_url, token)
        return {
            str(log.get("request_id", "")).strip()
            for log in logs
            if str(log.get("request_id", "")).strip()
        }
    except (OSError, TimeoutError, json.JSONDecodeError, RuntimeError):
        return None


def _fetch_token_logs(base_url: str, token: str) -> tuple[list[dict[str, object]], str]:
    request = urllib.request.Request(
        base_url.rstrip("/") + "/api/log/token",
        headers={"authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        commit = response.headers.get("X-New-Api-Commit", "")
        body = json.loads(response.read())
    if not isinstance(body, dict) or body.get("success") is not True:
        message = body.get("message", "") if isinstance(body, dict) else ""
        raise RuntimeError(f"token-log API failed: {message or 'success was not true'}")
    logs = body.get("data", [])
    if not isinstance(logs, list):
        raise TypeError("token-log API data is not an array")
    return [item for item in logs if isinstance(item, dict)], commit


def _usage_log_payload(
    cell: MatrixCell, log: dict[str, object], commit: str
) -> dict[str, object]:
    try:
        other = json.loads(str(log.get("other", "{}")))
    except json.JSONDecodeError:
        other = {}
    if not isinstance(other, dict):
        other = {}
    receipt_id = other.get("usage_receipt_id")
    receipt_state = other.get("usage_receipt_state")
    if cell.route.channel_type == 64:
        web_search_call_count = int(
            other.get("cursor_agent_v1_hosted_search_call_count", 0) or 0
        )
    else:
        web_search_call_count = int(other.get("web_search_call_count", 0) or 0)
    valid = bool(commit and receipt_id and receipt_state == "final")
    return {
        "status": "pass" if valid else "fail",
        "commit": commit,
        "route": {
            "id": cell.route.id,
            "channel_id": int(log.get("channel", 0) or 0),
            "group": str(log.get("group", "")),
        },
        "terminal": {
            "status": "completed" if int(log.get("type", 0) or 0) == 2 else "failed",
            "request_id": str(log.get("request_id", "")),
        },
        "receipt": {
            "id": str(receipt_id or ""),
            "provider": str(other.get("usage_receipt_provider", "")),
            "state": str(receipt_state or ""),
        },
        "usage": {
            "prompt_tokens": int(log.get("prompt_tokens", 0) or 0),
            "completion_tokens": int(log.get("completion_tokens", 0) or 0),
            "quota": int(log.get("quota", 0) or 0),
            "use_time": int(log.get("use_time", 0) or 0),
            "web_search_call_count": web_search_call_count,
        },
        "detail": "" if valid else "usage receipt is missing or not final",
    }


def _version(binary: str, cell: MatrixCell) -> str | None:
    try:
        completed = subprocess.run(
            [binary, *cell.client.version_args],
            text=True,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
            check=False,
        )
        return redact((completed.stdout or "").strip()[:300])
    except (OSError, subprocess.SubprocessError):
        return None


def _result(
    cell: MatrixCell,
    status: str,
    started_at: str,
    started: float,
    version: str | None,
    turns: list[TurnResult],
    detail: str,
    evidence: dict[str, object] | None = None,
) -> CellResult:
    return CellResult(
        cell_id=cell.id,
        status=status,
        client_version=version,
        started_at=started_at,
        duration_ms=int((time.monotonic() - started) * 1000),
        route_id=cell.route.id,
        model_id=cell.model.id,
        scenario_id=cell.scenario.id,
        turns=turns,
        evidence=evidence or {},
        detail=detail,
    )
