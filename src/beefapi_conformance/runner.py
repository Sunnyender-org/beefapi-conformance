from __future__ import annotations

import hashlib
import json
import os
import subprocess
import tempfile
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

from .clients import ClientCommand, assistant_text, resolve_binary
from .model import CellResult, MatrixCell, TurnResult
from .redact import redact

SERVER_EVIDENCE_FIELDS = {"status", "commit", "route", "terminal", "receipt", "usage"}


def _now() -> str:
    return datetime.now(UTC).isoformat()


def run_cell(
    cell: MatrixCell,
    allow_local_tools: bool = False,
    require_server_evidence: bool = False,
    defer_server_evidence: bool = False,
) -> CellResult:
    started = time.monotonic()
    started_epoch = int(time.time())
    started_at = _now()
    base_token = (
        os.environ.get(cell.route.token_env or "") if cell.route.token_env else None
    )
    evidence_fence = (
        set() if defer_server_evidence else _evidence_fence(cell, base_token)
    )
    if cell.client.adapter == "raw-http":
        return _run_http_cell(
            cell,
            started_at,
            started,
            started_epoch,
            base_token,
            evidence_fence,
            require_server_evidence,
            defer_server_evidence,
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

    with tempfile.TemporaryDirectory(prefix="beefapi-conformance-") as tmp:
        root = Path(tmp)
        workspace = root / "workspace"
        workspace.mkdir()
        marker_bytes = b"BEEFAPI_CONFORMANCE_FILE_OK\n"
        (workspace / "marker.txt").write_bytes(marker_bytes)
        token = _request_token(cell, base_token)
        command = ClientCommand(cell, binary, root, token, base_url)
        command.prepare()
        env = command.environment()
        turn_results: list[TurnResult] = []
        for index, turn in enumerate(cell.scenario.turns, 1):
            turn_started = time.monotonic()
            try:
                prompt = turn.prompt.replace("{{workspace}}", str(workspace))
                completed = subprocess.run(
                    command.command(prompt, index),
                    cwd=workspace,
                    env=env,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    timeout=cell.scenario.timeout_seconds,
                    check=False,
                )
                output = redact(completed.stdout or "", (token or "",))
                command.observe_output(output)
                missing = [
                    event for event in turn.expected_events if event not in output
                ]
                missing.extend(
                    "any:" + "|".join(group)
                    for group in turn.expected_any_events
                    if not any(event in output for event in group)
                )
                answer = assistant_text(cell.client.adapter, output)
                status = (
                    "pass"
                    if completed.returncode == 0
                    and turn.marker in answer
                    and not missing
                    else "fail"
                )
                turn_results.append(
                    TurnResult(
                        index=index,
                        status=status,
                        duration_ms=int((time.monotonic() - turn_started) * 1000),
                        returncode=completed.returncode,
                        marker=turn.marker,
                        missing_events=missing,
                        output_tail=output[-4000:],
                    )
                )
                if status != "pass":
                    break
            except subprocess.TimeoutExpired as exc:
                raw = exc.stdout if isinstance(exc.stdout, str) else ""
                turn_results.append(
                    TurnResult(
                        index,
                        "fail",
                        int((time.monotonic() - turn_started) * 1000),
                        None,
                        turn.marker,
                        ["terminal"],
                        redact(raw, (token or "",))[-4000:],
                    )
                )
                break
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                turn_results.append(
                    TurnResult(
                        index,
                        "fail",
                        int((time.monotonic() - turn_started) * 1000),
                        None,
                        turn.marker,
                        ["client_execution"],
                        redact(str(exc), (token or "",))[-4000:],
                    )
                )
                break
        status = (
            "pass"
            if len(turn_results) == len(cell.scenario.turns)
            and all(item.status == "pass" for item in turn_results)
            else "fail"
        )
        server_evidence = (
            {"status": "deferred"}
            if defer_server_evidence
            else _server_evidence(cell, base_token, started_epoch, evidence_fence, None)
        )
        evidence = {
            "workspace_marker_sha256": hashlib.sha256(marker_bytes).hexdigest(),
            "route_auth_mode": cell.route.auth_mode,
            "server_evidence": server_evidence,
        }
        if defer_server_evidence:
            evidence["_server_window"] = {
                "started_epoch": started_epoch,
                "finished_epoch": int(time.time()),
            }
        detail = ""
        if (
            require_server_evidence
            and not defer_server_evidence
            and cell.route.release_evidence_required
            and server_evidence.get("status") != "pass"
        ):
            status = "fail"
            detail = "release tier requires passing server evidence"
        return _result(
            cell, status, started_at, started, version, turn_results, detail, evidence
        )


def _run_http_cell(
    cell: MatrixCell,
    started_at: str,
    started: float,
    started_epoch: int,
    base_token: str | None,
    evidence_fence: set[str] | None,
    require_server_evidence: bool,
    defer_server_evidence: bool,
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
    model = cell.model.client_model(cell.client.id)
    if cell.scenario.http_payload is not None:
        payload = _render_http_payload(cell.scenario.http_payload, model, turn.prompt)
    elif cell.scenario.protocol == "messages":
        payload = {
            "model": model,
            "max_tokens": 128,
            "messages": [{"role": "user", "content": turn.prompt}],
        }
    elif cell.scenario.protocol == "chat":
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": turn.prompt}],
            "stream": False,
        }
    else:
        payload = {"model": model, "input": turn.prompt, "stream": False}
    if cell.scenario.protocol == "messages":
        headers = {
            "content-type": "application/json",
            "x-api-key": token or "",
            "anthropic-version": "2023-06-01",
        }
    elif cell.scenario.protocol == "chat":
        headers = {
            "content-type": "application/json",
            "authorization": f"Bearer {token or ''}",
        }
    else:
        headers = {
            "content-type": "application/json",
            "authorization": f"Bearer {token or ''}",
        }
    request = urllib.request.Request(
        base_url.rstrip("/") + cell.scenario.http_endpoint,
        data=json.dumps(payload).encode(),
        headers=headers,
        method="POST",
    )
    turn_started = time.monotonic()
    status_code: int | None = None
    response_request_id: str | None = None
    try:
        with urllib.request.urlopen(
            request, timeout=cell.scenario.timeout_seconds
        ) as response:
            status_code = response.status
            response_request_id = response.headers.get("X-Oneapi-Request-Id")
            output = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        response_request_id = (
            exc.headers.get("X-Oneapi-Request-Id") if exc.headers else None
        )
        output = exc.read().decode("utf-8", "replace")
    except (OSError, TimeoutError) as exc:
        output = str(exc)
    sanitized = redact(output, (token or "",))
    response_text = _http_response_text(cell.scenario.protocol, output)
    missing = [item for item in turn.expected_events if item not in sanitized]
    passed = (
        status_code is not None
        and 200 <= status_code < 300
        and turn.marker in response_text
        and not missing
    )
    result = TurnResult(
        1,
        "pass" if passed else "fail",
        int((time.monotonic() - turn_started) * 1000),
        status_code,
        turn.marker,
        missing,
        sanitized[-4000:],
    )
    server_evidence = (
        {"status": "deferred"}
        if defer_server_evidence
        else _server_evidence(
            cell,
            base_token,
            started_epoch,
            evidence_fence,
            response_request_id,
        )
    )
    evidence = {
        "http_status": status_code,
        "route_auth_mode": cell.route.auth_mode,
        "server_evidence": server_evidence,
    }
    if defer_server_evidence:
        evidence["_response_request_id"] = response_request_id
        evidence["_server_window"] = {
            "started_epoch": started_epoch,
            "finished_epoch": int(time.time()),
        }
    detail = ""
    if (
        require_server_evidence
        and not defer_server_evidence
        and cell.route.release_evidence_required
        and server_evidence.get("status") != "pass"
    ):
        result.status = "fail"
        detail = "release tier requires passing server evidence"
    return _result(
        cell,
        result.status,
        started_at,
        started,
        "python-urllib",
        [result],
        detail,
        evidence,
    )


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
    expected_request_id: str | None,
) -> dict[str, object]:
    if cell.route.evidence_provider == "beefapi_token_log":
        return _beefapi_token_log_evidence(
            cell,
            token,
            started_epoch,
            evidence_fence,
            expected_request_id,
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
    expected_request_id: str | None = None,
) -> dict[str, object]:
    if not token or not cell.route.base_url:
        return {
            "status": "fail",
            "detail": "token-log evidence lacks token or base URL",
        }
    if evidence_fence is None:
        return {"status": "fail", "detail": "pre-call token-log fence was unavailable"}
    if cell.client.adapter == "raw-http" and not expected_request_id:
        return {
            "status": "fail",
            "detail": "raw HTTP response did not expose X-Oneapi-Request-Id",
        }
    url = cell.route.base_url.rstrip("/") + "/api/log/token"
    last_detail = "matching usage log not found"
    for attempt in range(8):
        try:
            request = urllib.request.Request(
                url, headers={"authorization": f"Bearer {token}"}
            )
            with urllib.request.urlopen(request, timeout=20) as response:
                commit = response.headers.get("X-New-Api-Commit", "")
                body = json.loads(response.read())
            if not isinstance(body, dict) or body.get("success") is not True:
                last_detail = "token-log API did not return success=true"
                continue
            logs = body.get("data", []) if isinstance(body, dict) else []
            matches = _matching_usage_logs(
                cell,
                logs,
                started_epoch,
                evidence_fence,
                expected_request_id,
            )
            minimum_count = 1 if expected_request_id else len(cell.scenario.turns)
            if len(matches) >= minimum_count:
                payloads = [_usage_log_payload(cell, item, commit) for item in matches]
                if all(item.get("status") == "pass" for item in payloads):
                    result = dict(payloads[0])
                    if len(payloads) > 1:
                        result["requests"] = payloads
                    return result
                last_detail = "matching usage receipt is not final"
        except (OSError, TimeoutError, json.JSONDecodeError) as exc:
            last_detail = redact(str(exc), (token,))
        if attempt < 7:
            time.sleep(1)
    return {"status": "fail", "detail": last_detail}


def _matching_usage_logs(
    cell: MatrixCell,
    logs: object,
    started_epoch: int,
    excluded_request_ids: set[str] | None = None,
    expected_request_id: str | None = None,
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
        if expected_request_id and request_id != expected_request_id:
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


def _matching_usage_log(
    cell: MatrixCell,
    logs: object,
    started_epoch: int,
    excluded_request_ids: set[str] | None = None,
    expected_request_id: str | None = None,
) -> dict[str, object] | None:
    matches = _matching_usage_logs(
        cell,
        logs,
        started_epoch,
        excluded_request_ids,
        expected_request_id,
    )
    return matches[0] if matches else None


def _evidence_fence(cell: MatrixCell, token: str | None) -> set[str] | None:
    if cell.route.evidence_provider != "beefapi_token_log":
        return set()
    if not token or not cell.route.base_url:
        return None
    try:
        request = urllib.request.Request(
            cell.route.base_url.rstrip("/") + "/api/log/token",
            headers={"authorization": f"Bearer {token}"},
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            body = json.loads(response.read())
        if not isinstance(body, dict) or body.get("success") is not True:
            return None
        logs = body.get("data", []) if isinstance(body, dict) else []
        if not isinstance(logs, list):
            return None
        return {
            str(log.get("request_id", ""))
            for log in logs
            if isinstance(log, dict) and log.get("request_id")
        }
    except (OSError, TimeoutError, json.JSONDecodeError):
        return None


def prepare_batch_server_evidence(
    cells: list[MatrixCell],
) -> dict[tuple[str, str], dict[str, object]]:
    """Take one pre-run token-log snapshot per credential/base URL pair."""
    sessions: dict[tuple[str, str], dict[str, object]] = {}
    for cell in cells:
        if cell.route.evidence_provider != "beefapi_token_log":
            continue
        token_env = cell.route.token_env or ""
        token = os.environ.get(token_env, "")
        base_url = (
            os.environ.get(cell.route.base_url_env or "")
            if cell.route.base_url_env
            else cell.route.base_url
        ).rstrip("/")
        if not token or not base_url:
            raise RuntimeError(
                f"batch evidence lacks token or base URL for route {cell.route.id}"
            )
        key = (base_url, token_env)
        if key in sessions:
            continue
        logs, commit = _fetch_token_logs(base_url, token)
        sessions[key] = {
            "token": token,
            "commit": commit,
            "fence": {
                str(item.get("request_id", "")).strip()
                for item in logs
                if isinstance(item, dict) and str(item.get("request_id", "")).strip()
            },
        }
    return sessions


def finalize_batch_server_evidence(
    cells: list[MatrixCell],
    results: list[CellResult],
    sessions: dict[tuple[str, str], dict[str, object]],
) -> None:
    """Resolve a serialized production run with one bounded post-run snapshot."""
    final_logs: dict[tuple[str, str], list[dict[str, object]]] = {}
    final_commits: dict[tuple[str, str], str] = {}
    last_error = "batch token-log evidence was unavailable"
    for attempt in range(8):
        try:
            for key, session in sessions.items():
                logs, commit = _fetch_token_logs(key[0], str(session["token"]))
                typed_logs = [item for item in logs if isinstance(item, dict)]
                final_logs[key] = typed_logs
                final_commits[key] = commit
            break
        except (OSError, TimeoutError, json.JSONDecodeError, RuntimeError) as exc:
            last_error = redact(str(exc))
        if attempt < 7:
            time.sleep(1)
    else:
        for result in results:
            _set_batch_evidence_failure(result, last_error)
        return

    result_by_id = {result.cell_id: result for result in results}
    used_request_ids: dict[tuple[str, str], set[str]] = {key: set() for key in sessions}

    # Allocate in serialized execution order. Every row in a native cell's
    # execution window is reserved, including rows from failed cells, so a tool
    # loop cannot leak leftover evidence into the following cell.
    for cell in cells:
        result = result_by_id[cell.id]
        if cell.route.evidence_provider != "beefapi_token_log":
            continue
        key = _batch_session_key(cell)
        window = result.evidence.pop("_server_window", {})
        started_epoch = int(window.get("started_epoch", 0) or 0)
        finished_epoch = int(window.get("finished_epoch", 0) or 0)
        request_id = str(result.evidence.pop("_response_request_id", "") or "")

        if cell.client.adapter == "raw-http":
            matches = (
                _matching_usage_logs(
                    cell,
                    final_logs[key],
                    0,
                    sessions[key]["fence"],
                    request_id,
                )
                if request_id
                else []
            )
            used_request_ids[key].update(
                str(item.get("request_id", "")) for item in matches
            )
            if result.status != "pass":
                continue
            if not request_id:
                _set_batch_evidence_failure(
                    result, "raw HTTP response did not expose X-Oneapi-Request-Id"
                )
                continue
            if len(matches) != 1:
                _set_batch_evidence_failure(
                    result,
                    "raw HTTP request id did not resolve to exactly one consume log",
                )
                continue
            payload = _usage_log_payload(cell, matches[0], final_commits[key])
            result.evidence["server_evidence"] = payload
            if payload.get("status") != "pass":
                _set_batch_evidence_failure(result, str(payload.get("detail", "")))
            continue

        candidates = _matching_usage_logs(
            cell,
            final_logs[key],
            started_epoch,
            sessions[key]["fence"],
        )
        candidates = [
            item
            for item in candidates
            if str(item.get("request_id", "")) not in used_request_ids[key]
            and int(item.get("created_at", 0) or 0) <= finished_epoch
        ]
        candidates.sort(key=lambda item: int(item.get("created_at", 0) or 0))
        used_request_ids[key].update(
            str(item.get("request_id", "")) for item in candidates
        )
        if result.status != "pass":
            continue
        required = len(cell.scenario.turns)
        if len(candidates) < required:
            _set_batch_evidence_failure(
                result,
                f"batch evidence found {len(candidates)} consume logs; {required} required",
            )
            continue
        payloads = [
            _usage_log_payload(cell, item, final_commits[key]) for item in candidates
        ]
        final_payloads = [item for item in payloads if item.get("status") == "pass"]
        if len(final_payloads) < required:
            _set_batch_evidence_failure(
                result,
                f"batch evidence found {len(final_payloads)} final receipts; {required} required",
            )
            continue
        payload = dict(final_payloads[0])
        if len(final_payloads) > 1:
            payload["requests"] = final_payloads
        payload["provisional_count"] = len(payloads) - len(final_payloads)
        result.evidence["server_evidence"] = payload


def _batch_session_key(cell: MatrixCell) -> tuple[str, str]:
    base_url = (
        os.environ.get(cell.route.base_url_env or "")
        if cell.route.base_url_env
        else cell.route.base_url
    ).rstrip("/")
    return base_url, cell.route.token_env or ""


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


def _set_batch_evidence_failure(result: CellResult, detail: str) -> None:
    result.evidence.pop("_response_request_id", None)
    result.evidence.pop("_server_window", None)
    result.evidence["server_evidence"] = {"status": "fail", "detail": detail}
    if result.status == "pass":
        result.status = "fail"
        result.detail = "nightly/release tier requires passing server evidence"


def _usage_log_payload(
    cell: MatrixCell, log: dict[str, object], commit: str
) -> dict[str, object]:
    try:
        other = json.loads(str(log.get("other", "{}")))
    except json.JSONDecodeError:
        other = {}
    receipt_id = other.get("usage_receipt_id") if isinstance(other, dict) else None
    receipt_state = (
        other.get("usage_receipt_state") if isinstance(other, dict) else None
    )
    if isinstance(other, dict) and cell.route.channel_type == 64:
        web_search_call_count = int(
            other.get("cursor_agent_v1_hosted_search_call_count", 0) or 0
        )
    else:
        web_search_call_count = (
            int(other.get("web_search_call_count", 0) or 0)
            if isinstance(other, dict)
            else 0
        )
    search_evidence_valid = (
        web_search_call_count > 0 if cell.scenario.id == "native-web-search" else True
    )
    valid = bool(
        commit and receipt_id and receipt_state == "final" and search_evidence_valid
    )
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
            "provider": str(other.get("usage_receipt_provider", ""))
            if isinstance(other, dict)
            else "",
            "state": str(receipt_state or ""),
        },
        "usage": {
            "prompt_tokens": int(log.get("prompt_tokens", 0) or 0),
            "completion_tokens": int(log.get("completion_tokens", 0) or 0),
            "quota": int(log.get("quota", 0) or 0),
            "use_time": int(log.get("use_time", 0) or 0),
            "web_search_call_count": web_search_call_count,
        },
        "detail": ""
        if valid
        else (
            "native web search has no observed search call"
            if not search_evidence_valid
            else "usage receipt is missing or not final"
        ),
    }


def _version(binary: str, cell: MatrixCell) -> str | None:
    try:
        completed = subprocess.run(
            [binary, *cell.client.version_args],
            text=True,
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
