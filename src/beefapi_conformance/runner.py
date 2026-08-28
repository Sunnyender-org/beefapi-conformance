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
) -> CellResult:
    started = time.monotonic()
    started_at = _now()
    if cell.client.adapter == "raw-http":
        return _run_http_cell(cell, started_at, started, require_server_evidence)
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
    token = os.environ.get(cell.route.token_env or "") if cell.route.token_env else None
    if cell.route.auth_mode == "gateway_token" and not token:
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
        command = ClientCommand(cell, binary, root, token, base_url)
        command.prepare()
        env = command.environment()
        turn_results: list[TurnResult] = []
        for index, turn in enumerate(cell.scenario.turns, 1):
            turn_started = time.monotonic()
            try:
                completed = subprocess.run(
                    command.command(turn.prompt, index),
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
        server_evidence = _server_evidence(cell, token)
        evidence = {
            "workspace_marker_sha256": hashlib.sha256(marker_bytes).hexdigest(),
            "route_auth_mode": cell.route.auth_mode,
            "server_evidence": server_evidence,
        }
        detail = ""
        if (
            require_server_evidence
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
    require_server_evidence: bool,
) -> CellResult:
    token = os.environ.get(cell.route.token_env or "") if cell.route.token_env else None
    base_url = (
        os.environ.get(cell.route.base_url_env or "")
        if cell.route.base_url_env
        else cell.route.base_url
    )
    if cell.route.auth_mode == "gateway_token" and not token:
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
    model = cell.model.client_model(cell.client.id)
    if cell.scenario.protocol == "messages":
        payload = {
            "model": model,
            "max_tokens": 128,
            "messages": [{"role": "user", "content": turn.prompt}],
        }
        headers = {
            "content-type": "application/json",
            "x-api-key": token or "",
            "anthropic-version": "2023-06-01",
        }
    elif cell.scenario.protocol == "chat":
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": turn.prompt}],
            "stream": False,
        }
        headers = {
            "content-type": "application/json",
            "authorization": f"Bearer {token or ''}",
        }
    else:
        payload = {"model": model, "input": turn.prompt, "stream": False}
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
    try:
        with urllib.request.urlopen(
            request, timeout=cell.scenario.timeout_seconds
        ) as response:
            status_code = response.status
            output = response.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        status_code = exc.code
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
    server_evidence = _server_evidence(cell, token)
    evidence = {
        "http_status": status_code,
        "route_auth_mode": cell.route.auth_mode,
        "server_evidence": server_evidence,
    }
    detail = ""
    if (
        require_server_evidence
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


def _server_evidence(cell: MatrixCell, token: str | None) -> dict[str, object]:
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
