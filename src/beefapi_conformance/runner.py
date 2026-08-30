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
from datetime import UTC, datetime
from pathlib import Path

from .clients import ClientCommand, assistant_text, resolve_binary
from .cursor_agent_v1 import (
    NON_HOSTED_WEB_CLIENTS,
    attach_completion_metadata,
    correlate_id,
    evaluate_hosted_search,
    evaluate_public_artifacts,
    evaluate_usage_quality,
    hosted_search_counts,
    redact_correlation_ids,
    redact_known_ids,
    type64_usage_fields,
)
from .model import CellResult, MatrixCell, TurnResult
from .redact import redact
from .tool_replay import (
    evaluate_mcp_spans,
    evaluate_replay_identity,
    execute_tool_replay,
    parse_assistant_text,
    parse_json_objects,
    sleep_deltas,
)

SERVER_EVIDENCE_FIELDS = {"status", "commit", "route", "terminal", "receipt", "usage"}
AGENT_V1_RESPONSE_ID = re.compile(
    r'"id"\s*:\s*"resp_bf_agentv1_u[0-9]+_c[0-9]+_([A-Za-z0-9]+)"'
)


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _route_base_url(cell: MatrixCell) -> str | None:
    if cell.route.base_url_env:
        return os.environ.get(cell.route.base_url_env or "")
    return cell.route.base_url


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
    base_url = _route_base_url(cell)
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
        observed_request_ids: set[str] = set()
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
                output = redact_correlation_ids(
                    redact(completed.stdout or "", (token or "",))
                )
                observed_request_ids.update(AGENT_V1_RESPONSE_ID.findall(output))
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
                        redact_correlation_ids(redact(raw, (token or "",)))[-4000:],
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
                        redact_correlation_ids(redact(str(exc), (token or "",)))[
                            -4000:
                        ],
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
        combined_output = "\n".join(item.output_tail for item in turn_results)
        permission_mode = (
            "auto"
            if "client.classifier" in cell.scenario.required_capabilities
            else "bypassPermissions"
        )
        public = evaluate_public_artifacts(
            cell,
            output=combined_output,
            evidence=server_evidence if isinstance(server_evidence, dict) else {},
            permission_mode=permission_mode,
        )
        detail = ""
        if public.status != "pass":
            status = "fail"
            detail = public.detail
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
            evidence["_response_request_ids"] = sorted(observed_request_ids)
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
    base_url = _route_base_url(cell)
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
    token = _request_token(cell, base_token)
    model = cell.model.client_model(cell.client.id)
    url = base_url.rstrip("/") + cell.scenario.http_endpoint
    headers = _http_headers(cell.scenario.protocol, token)
    if cell.scenario.tool_replay:
        return _run_tool_replay_http_cell(
            cell,
            started_at,
            started,
            started_epoch,
            base_token,
            evidence_fence,
            require_server_evidence,
            defer_server_evidence,
            token,
            model,
            url,
            headers,
        )
    turn_results: list[TurnResult] = []
    observed_request_ids: list[str] = []
    attempts: list[dict[str, object]] = []
    last_status: int | None = None
    last_output = ""
    stream_meta: dict[str, object] = {
        "first_byte_ms": None,
        "keepalive_count": 0,
        "progress_event_count": 0,
    }
    public_mcp: dict[str, object] = {}
    disconnect = "lifecycle.disconnect" in cell.scenario.evidence_requirements
    for index, turn in enumerate(cell.scenario.turns, 1):
        payload = _http_payload_for_turn(cell, model, turn.prompt)
        turn_started = time.monotonic()
        if disconnect and index == 1:
            aborted_status, _aborted_output, aborted_id, aborted_stream = (
                _http_exchange(
                    url,
                    payload,
                    headers,
                    min(cell.scenario.timeout_seconds, 5),
                    abort_after_bytes=1,
                )
            )
            attempts.append(
                {
                    "aborted": True,
                    "http_status": aborted_status,
                    "http_request_id_hash": correlate_id(aborted_id or ""),
                    "receipt_hash": "",
                    "stream": aborted_stream,
                }
            )
        status_code, output, response_request_id, stream = _http_exchange(
            url, payload, headers, cell.scenario.timeout_seconds
        )
        last_status = status_code
        last_output = output
        stream_meta = stream
        if isinstance(response_request_id, str) and response_request_id:
            observed_request_ids.append(response_request_id)
        request_hash = hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode()
        ).hexdigest()
        attempts.append(
            {
                "offset_seconds": 0,
                "aborted": False,
                "http_status": status_code,
                "request_hash": request_hash,
                "http_request_id_hash": correlate_id(response_request_id or ""),
                "receipt_hash": "",
            }
        )
        if cell.scenario.retry_offsets_seconds and require_server_evidence:
            for offset, delta in zip(
                cell.scenario.retry_offsets_seconds,
                sleep_deltas(cell.scenario.retry_offsets_seconds),
                strict=True,
            ):
                time.sleep(delta)
                retry_status, retry_output, retry_id, retry_stream = _http_exchange(
                    url, payload, headers, cell.scenario.timeout_seconds
                )
                last_status = retry_status
                last_output = retry_output
                stream_meta = retry_stream
                if isinstance(retry_id, str) and retry_id:
                    observed_request_ids.append(retry_id)
                attempts.append(
                    {
                        "offset_seconds": offset,
                        "aborted": False,
                        "http_status": retry_status,
                        "request_hash": request_hash,
                        "http_request_id_hash": correlate_id(retry_id or ""),
                        "receipt_hash": "",
                    }
                )
        sanitized = redact_correlation_ids(redact(output, (token or "",)))
        response_text = _http_response_text(cell.scenario.protocol, output)
        missing = [item for item in turn.expected_events if item not in sanitized]
        passed = (
            status_code is not None
            and 200 <= status_code < 300
            and (turn.marker in response_text or turn.marker in sanitized)
            and not missing
        )
        mcp = _mcp_from_http_body(output)
        if mcp:
            public_mcp = mcp
        turn_results.append(
            TurnResult(
                index,
                "pass" if passed else "fail",
                int((time.monotonic() - turn_started) * 1000),
                status_code,
                turn.marker,
                missing,
                sanitized[-4000:],
            )
        )
        if not passed:
            break
    status = (
        "pass"
        if len(turn_results) == len(cell.scenario.turns)
        and all(item.status == "pass" for item in turn_results)
        else "fail"
    )
    primary_request_id = (
        observed_request_ids[-1] if len(observed_request_ids) == 1 else None
    )
    server_evidence = (
        {"status": "deferred"}
        if defer_server_evidence
        else _server_evidence(
            cell,
            base_token,
            started_epoch,
            evidence_fence,
            primary_request_id,
        )
    )
    public_evidence: dict[str, object] = (
        dict(server_evidence) if isinstance(server_evidence, dict) else {}
    )
    if public_mcp:
        public_evidence["mcp"] = public_mcp
    public = evaluate_public_artifacts(
        cell,
        http_status=last_status,
        output=redact_correlation_ids(redact(last_output, (token or "",))),
        evidence=public_evidence,
        stream=stream_meta,
        attempts=attempts,
    )
    detail = ""
    if public.status != "pass":
        status = "fail"
        detail = public.detail
    evidence: dict[str, object] = {
        "http_status": last_status,
        "route_auth_mode": cell.route.auth_mode,
        "server_evidence": server_evidence,
        "stream": stream_meta,
    }
    if public_mcp:
        evidence["mcp"] = public_mcp
    if defer_server_evidence:
        if len(observed_request_ids) == 1:
            evidence["_response_request_id"] = observed_request_ids[0]
        evidence["_response_request_ids"] = observed_request_ids
        evidence["_server_window"] = {
            "started_epoch": started_epoch,
            "finished_epoch": int(time.time()),
        }
    if (
        require_server_evidence
        and not defer_server_evidence
        and cell.route.release_evidence_required
        and server_evidence.get("status") != "pass"
    ):
        status = "fail"
        detail = "release tier requires passing server evidence"
    return _result(
        cell,
        status,
        started_at,
        started,
        "python-urllib",
        turn_results,
        detail,
        evidence,
    )


def _run_tool_replay_http_cell(
    cell: MatrixCell,
    started_at: str,
    started: float,
    started_epoch: int,
    base_token: str | None,
    evidence_fence: set[str] | None,
    require_server_evidence: bool,
    defer_server_evidence: bool,
    token: str | None,
    model: str,
    url: str,
    headers: dict[str, str],
) -> CellResult:
    turn = cell.scenario.turns[0]
    spec = dict(cell.scenario.tool_replay or {})
    offsets = cell.scenario.retry_offsets_seconds

    def exchange(
        payload: dict[str, object],
    ) -> tuple[int | None, str, str | None, dict[str, object]]:
        return _http_exchange(url, payload, headers, cell.scenario.timeout_seconds)

    replay = execute_tool_replay(
        spec=spec,
        model=model,
        prompt=turn.prompt,
        marker=turn.marker,
        offsets=offsets,
        exchange=exchange,
        sleeper=time.sleep if offsets else None,
    )
    sanitized = redact_correlation_ids(redact(replay.last_output, (token or "",)))
    response_text = parse_assistant_text(replay.last_output)
    missing = [item for item in turn.expected_events if item not in sanitized]
    http_ok = replay.last_status is not None and 200 <= replay.last_status < 300
    marker_ok = turn.marker in response_text or turn.marker in sanitized
    status = replay.status
    detail = replay.detail
    if status == "pass" and not (http_ok and marker_ok and not missing):
        status = "fail"
        detail = (
            detail or "tool_result round trip did not complete with the expected marker"
        )
    public_mcp: dict[str, object] = {}
    for body in parse_json_objects(replay.last_output):
        mcp = body.get("mcp")
        if isinstance(mcp, dict):
            public_mcp = mcp
    if cell.scenario.mcp_mode and status == "pass":
        spans = (
            public_mcp.get("spans") if isinstance(public_mcp.get("spans"), list) else []
        )
        typed_spans = [item for item in spans if isinstance(item, dict)]
        mcp_eval = evaluate_mcp_spans(
            cell.scenario.mcp_mode,
            typed_spans,
            replay.tool_uses,
            replay.tool_use_id_hashes,
        )
        if mcp_eval.status == "blocked":
            status = "blocked"
            detail = mcp_eval.detail
        elif not mcp_eval.ok:
            status = "fail"
            detail = mcp_eval.detail
    raw_request_ids = [
        str(item.get("_http_request_id") or "")
        for item in replay.attempts
        if item.get("_http_request_id")
    ]
    known_ids = [
        *raw_request_ids,
        *(item.id for item in replay.tool_uses),
    ]
    sanitized = redact_known_ids(sanitized, known_ids)
    server_evidence: dict[str, object]
    if defer_server_evidence:
        server_evidence = {"status": "deferred"}
    elif cell.route.evidence_provider == "beefapi_token_log":
        server_evidence = _bind_replay_server_evidence(
            cell,
            replay.attempts,
            base_token,
            started_epoch,
            evidence_fence,
        )
        if offsets:
            identity = evaluate_replay_identity(
                replay.attempts, require_receipts=require_server_evidence
            )
        elif require_server_evidence:
            identity = _evaluate_single_stage_receipts(replay.attempts)
        else:
            identity = None
        if identity is not None and not identity.ok and status == "pass":
            status = "fail"
            detail = identity.detail
    else:
        server_evidence = _server_evidence(
            cell,
            base_token,
            started_epoch,
            evidence_fence,
            raw_request_ids[-1] if len(raw_request_ids) == 1 else None,
        )
    public_evidence: dict[str, object] = (
        dict(server_evidence) if isinstance(server_evidence, dict) else {}
    )
    public_evidence.update(replay.evidence)
    if public_mcp:
        public_evidence["mcp"] = public_mcp
    public = evaluate_public_artifacts(
        cell,
        http_status=replay.last_status,
        output=sanitized,
        evidence=public_evidence,
        stream=replay.stream,
        attempts=replay.attempts,
    )
    if public.status != "pass" and status == "pass":
        status = "fail"
        detail = public.detail
    evidence: dict[str, object] = {
        "http_status": replay.last_status,
        "route_auth_mode": cell.route.auth_mode,
        "server_evidence": server_evidence,
        "stream": replay.stream,
        **replay.evidence,
    }
    if public_mcp:
        evidence["mcp"] = public_mcp
    if defer_server_evidence:
        evidence["_response_request_ids"] = raw_request_ids
        evidence["_replay_attempts"] = replay.attempts
        evidence["_server_window"] = {
            "started_epoch": started_epoch,
            "finished_epoch": int(time.time()),
        }
    else:
        _scrub_private_replay_fields(evidence, replay.attempts)
    if (
        require_server_evidence
        and not defer_server_evidence
        and cell.route.release_evidence_required
        and server_evidence.get("status") != "pass"
        and status == "pass"
    ):
        status = "fail"
        detail = "release tier requires passing server evidence"
    turn_result = TurnResult(
        1,
        "pass" if status == "pass" else status if status == "blocked" else "fail",
        int((time.monotonic() - started) * 1000),
        replay.last_status,
        turn.marker,
        missing,
        sanitized[-4000:],
    )
    return _result(
        cell,
        status,
        started_at,
        started,
        "python-urllib",
        [turn_result],
        detail,
        evidence,
    )


def bind_replay_attempt_receipts(
    cell: MatrixCell,
    attempts: list[dict[str, object]],
    logs: object,
    commit: str,
    started_epoch: int = 0,
    fence: set[str] | None = None,
) -> None:
    """Attach the Stage B receipt from an exact request-id log match.

    Stage C duplicate request ids must resolve to zero consume logs. Do not copy
    Stage B's receipt onto C; mark C as replay_without_consume / no_new_charge.
    Stage A provisional rows are ignored for this replay assertion.
    """
    for attempt in attempts:
        if not isinstance(attempt, dict) or attempt.get("stage") not in {"b", "c"}:
            continue
        raw_id = str(attempt.get("_http_request_id") or "")
        if not raw_id:
            attempt["consume_match_count"] = 0
            attempt["receipt_hash"] = ""
            attempt.pop("_bound_payload", None)
            _mark_stage_c_replay(attempt, zero_consume=True)
            continue
        matches = _matching_usage_logs(cell, logs, started_epoch, fence, raw_id)
        attempt["consume_match_count"] = len(matches)
        if attempt.get("stage") == "c":
            attempt["receipt_hash"] = ""
            attempt.pop("_bound_payload", None)
            _mark_stage_c_replay(attempt, zero_consume=len(matches) == 0)
            continue
        if len(matches) != 1:
            attempt["receipt_hash"] = ""
            attempt.pop("_bound_payload", None)
            continue
        payload = _usage_log_payload(cell, matches[0], commit)
        receipt = (
            payload.get("receipt") if isinstance(payload.get("receipt"), dict) else {}
        )
        if payload.get("status") != "pass":
            attempt["receipt_hash"] = ""
            attempt["receipt_state"] = str(receipt.get("state") or "")
            attempt.pop("_bound_payload", None)
            continue
        attempt["receipt_hash"] = str(receipt.get("id_hash") or "")
        attempt["receipt_state"] = str(receipt.get("state") or "")
        attempt["_bound_payload"] = payload


def _mark_stage_c_replay(attempt: dict[str, object], *, zero_consume: bool) -> None:
    if attempt.get("stage") != "c":
        return
    attempt["replay_without_consume"] = zero_consume
    attempt["no_new_charge"] = zero_consume


def _replay_no_new_charge_evidence(
    attempts: list[dict[str, object]],
) -> dict[str, object]:
    return {
        "stage_c": [
            {
                "http_request_id_hash": item.get("http_request_id_hash"),
                "consume_match_count": item.get("consume_match_count"),
                "replay_without_consume": bool(item.get("replay_without_consume")),
                "no_new_charge": bool(item.get("no_new_charge")),
            }
            for item in attempts
            if isinstance(item, dict) and item.get("stage") == "c"
        ]
    }


def _bind_replay_server_evidence(
    cell: MatrixCell,
    attempts: list[dict[str, object]],
    token: str | None,
    started_epoch: int,
    fence: set[str] | None,
) -> dict[str, object]:
    base_url = _route_base_url(cell)
    if not token or not base_url:
        return {
            "status": "fail",
            "detail": "token-log evidence lacks token or base URL",
        }
    if fence is None:
        return {"status": "fail", "detail": "pre-call token-log fence was unavailable"}
    last_detail = "matching usage log not found"
    for attempt in range(8):
        try:
            logs, commit = _fetch_token_logs(base_url.rstrip("/"), token)
            bind_replay_attempt_receipts(
                cell, attempts, logs, commit, started_epoch, fence
            )
            bound = [
                item.get("_bound_payload")
                for item in attempts
                if isinstance(item, dict)
                and item.get("stage") == "b"
                and isinstance(item.get("_bound_payload"), dict)
            ]
            if bound:
                payload = dict(bound[0])
                payload["replay"] = _replay_no_new_charge_evidence(attempts)
                return payload
            last_detail = (
                "stage B request id did not resolve to exactly one final receipt"
            )
        except (
            OSError,
            TimeoutError,
            json.JSONDecodeError,
            RuntimeError,
            TypeError,
        ) as exc:
            last_detail = redact(str(exc), (token,))
        if attempt < 7:
            time.sleep(1)
    return {"status": "fail", "detail": last_detail}


def _scrub_private_replay_fields(
    evidence: dict[str, object],
    attempts: list[dict[str, object]] | None = None,
) -> None:
    evidence.pop("_response_request_id", None)
    evidence.pop("_response_request_ids", None)
    evidence.pop("_server_window", None)
    evidence.pop("_replay_attempts", None)
    for attempt in attempts or []:
        if isinstance(attempt, dict):
            attempt.pop("_http_request_id", None)
            attempt.pop("_bound_payload", None)


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


def _http_payload_for_turn(cell: MatrixCell, model: str, prompt: str) -> object:
    if cell.scenario.http_payload is not None:
        return _render_http_payload(cell.scenario.http_payload, model, prompt)
    if cell.scenario.protocol == "messages":
        return {
            "model": model,
            "max_tokens": 128,
            "messages": [{"role": "user", "content": prompt}],
        }
    if cell.scenario.protocol == "chat":
        return {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
        }
    return {"model": model, "input": prompt, "stream": False}


def _http_exchange(
    url: str,
    payload: object,
    headers: dict[str, str],
    timeout: int,
    abort_after_bytes: int | None = None,
) -> tuple[int | None, str, str | None, dict[str, object]]:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode(),
        headers=headers,
        method="POST",
    )
    started = time.monotonic()
    status_code: int | None = None
    response_request_id: str | None = None
    output = ""
    stream: dict[str, object] = {
        "first_byte_ms": None,
        "keepalive_count": 0,
        "progress_event_count": 0,
        "aborted": False,
    }
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status_code = response.status
            response_request_id = response.headers.get("X-Oneapi-Request-Id")
            output, stream = _read_http_body(response, started, abort_after_bytes)
            _attach_response_receipt_hash(stream, response.headers)
    except urllib.error.HTTPError as exc:
        status_code = exc.code
        response_request_id = (
            exc.headers.get("X-Oneapi-Request-Id") if exc.headers else None
        )
        output = exc.read().decode("utf-8", "replace")
        stream["first_byte_ms"] = int((time.monotonic() - started) * 1000)
        stream["aborted"] = abort_after_bytes is not None
        _attach_response_receipt_hash(stream, exc.headers)
    except (OSError, TimeoutError) as exc:
        output = str(exc)
        stream["aborted"] = abort_after_bytes is not None
    return status_code, output, response_request_id, stream


def _attach_response_receipt_hash(stream: dict[str, object], headers: object) -> None:
    hashed = _header_receipt_hash(headers)
    if hashed:
        stream["response_receipt_hash"] = hashed


def _header_receipt_hash(headers: object) -> str:
    """Hash a client-visible receipt header only when the gateway actually sent one.

    Absence is not failure; BeefAPI's external response is not assumed to expose
    a receipt id. Do not persist the raw value.
    """
    if headers is None:
        return ""
    getter = getattr(headers, "get", None)
    if not callable(getter):
        return ""
    for name in ("X-Usage-Receipt-Id", "X-Beefapi-Usage-Receipt-Id"):
        raw = getter(name)
        if isinstance(raw, str) and raw.strip():
            return correlate_id(raw.strip())
    return ""


def _read_http_body(
    response: object,
    started: float,
    abort_after_bytes: int | None,
) -> tuple[str, dict[str, object]]:
    first_byte_ms: int | None = None
    chunks: list[bytes] = []
    aborted = False
    while True:
        remaining = None
        if abort_after_bytes is not None:
            remaining = abort_after_bytes - sum(len(item) for item in chunks)
            if remaining <= 0:
                aborted = True
                break
        chunk = response.read(64 if remaining is None else min(64, remaining))
        if not chunk:
            break
        if first_byte_ms is None:
            first_byte_ms = int((time.monotonic() - started) * 1000)
        chunks.append(chunk)
        if (
            abort_after_bytes is not None
            and sum(len(item) for item in chunks) >= abort_after_bytes
        ):
            aborted = True
            break
    text = b"".join(chunks).decode("utf-8", "replace")
    return text, {
        "first_byte_ms": first_byte_ms,
        "keepalive_count": (
            text.count("event: ping")
            + text.count("event: keepalive")
            + text.count(": ping")
            + text.count(": keepalive")
        ),
        "progress_event_count": (
            text.count("event: content_block_delta")
            + text.count("event: message_delta")
            + text.count("event: thinking")
            + text.count('"type": "thinking"')
            + text.count('"type":"thinking"')
        ),
        "aborted": aborted,
    }


def _mcp_from_http_body(output: str) -> dict[str, object]:
    try:
        body = json.loads(output)
    except json.JSONDecodeError:
        return {}
    mcp = body.get("mcp") if isinstance(body, dict) else None
    return mcp if isinstance(mcp, dict) else {}


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
        fragments: list[str] = []
        for line in output.splitlines():
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if not data or data == "[DONE]":
                continue
            fragment = _http_response_text(protocol, data)
            if fragment:
                fragments.append(fragment)
        return "\n".join(fragments)
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
    base_url = _route_base_url(cell)
    if not token or not base_url:
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
    url = base_url.rstrip("/") + "/api/log/token"
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
        if request_id in seen_request_ids and expected_request_id is None:
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
    base_url = _route_base_url(cell)
    if not token or not base_url:
        return None
    try:
        request = urllib.request.Request(
            base_url.rstrip("/") + "/api/log/token",
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
        base_url = (_route_base_url(cell) or "").rstrip("/")
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
        request_ids = result.evidence.pop("_response_request_ids", [])

        if cell.client.adapter == "raw-http" and cell.scenario.tool_replay:
            _finalize_replay_batch_evidence(
                cell,
                result,
                final_logs[key],
                final_commits[key],
                sessions[key]["fence"],
                used_request_ids[key],
                request_id,
                request_ids,
            )
            continue

        if cell.client.adapter == "raw-http":
            exact_ids = (
                [request_id]
                if request_id
                else [
                    str(item).strip()
                    for item in request_ids
                    if isinstance(item, str) and str(item).strip()
                ]
            )
            matches = [
                log
                for exact in exact_ids
                for log in _matching_usage_logs(
                    cell,
                    final_logs[key],
                    0,
                    sessions[key]["fence"],
                    exact,
                )
            ]
            used_request_ids[key].update(
                str(item.get("request_id", "")) for item in matches
            )
            if result.status != "pass":
                continue
            if not exact_ids:
                _set_batch_evidence_failure(
                    result, "raw HTTP response did not expose X-Oneapi-Request-Id"
                )
                continue
            if len(matches) != len(exact_ids):
                _set_batch_evidence_failure(
                    result,
                    "raw HTTP request id did not resolve to exactly one consume log",
                )
                continue
            payloads = [
                _usage_log_payload(cell, item, final_commits[key]) for item in matches
            ]
            payload = dict(payloads[0])
            if len(payloads) > 1:
                payload["requests"] = payloads
            result.evidence["server_evidence"] = payload
            if any(item.get("status") != "pass" for item in payloads):
                _set_batch_evidence_failure(result, str(payload.get("detail", "")))
            else:
                _apply_public_artifact_gate(cell, result)
            continue

        exact_request_ids = [
            str(item).strip()
            for item in request_ids
            if isinstance(item, str) and str(item).strip()
        ]
        if exact_request_ids:
            candidates = [
                log
                for exact_request_id in exact_request_ids
                for log in _matching_usage_logs(
                    cell,
                    final_logs[key],
                    0,
                    sessions[key]["fence"],
                    exact_request_id,
                )
            ]
        else:
            candidates = _matching_usage_logs(
                cell,
                final_logs[key],
                started_epoch,
                sessions[key]["fence"],
            )
            candidates = [
                item
                for item in candidates
                if int(item.get("created_at", 0) or 0) <= finished_epoch
            ]
        candidates = [
            item
            for item in candidates
            if str(item.get("request_id", "")) not in used_request_ids[key]
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
        _apply_public_artifact_gate(cell, result)


def _batch_session_key(cell: MatrixCell) -> tuple[str, str]:
    base_url = (_route_base_url(cell) or "").rstrip("/")
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


def _finalize_replay_batch_evidence(
    cell: MatrixCell,
    result: CellResult,
    logs: list[dict[str, object]],
    commit: str,
    fence: object,
    used_request_ids: set[str],
    request_id: str,
    request_ids: object,
) -> None:
    exact_ids = (
        [request_id]
        if request_id
        else [
            str(item).strip()
            for item in (request_ids or [])
            if isinstance(item, str) and str(item).strip()
        ]
    )
    attempts = result.evidence.get("_replay_attempts")
    typed_attempts = (
        [item for item in attempts if isinstance(item, dict)]
        if isinstance(attempts, list)
        else []
    )
    typed_fence = fence if isinstance(fence, set) else set()
    bind_replay_attempt_receipts(cell, typed_attempts, logs, commit, 0, typed_fence)
    used_request_ids.update(exact_ids)
    if result.status == "pass":
        if not exact_ids:
            _set_batch_evidence_failure(
                result, "raw HTTP response did not expose X-Oneapi-Request-Id"
            )
        else:
            identity = (
                evaluate_replay_identity(typed_attempts, require_receipts=True)
                if cell.scenario.retry_offsets_seconds
                else _evaluate_single_stage_receipts(typed_attempts)
            )
            if identity is not None and not identity.ok:
                _set_batch_evidence_failure(result, identity.detail)
            else:
                bound = [
                    item.get("_bound_payload")
                    for item in typed_attempts
                    if item.get("stage") == "b"
                    and isinstance(item.get("_bound_payload"), dict)
                ]
                if bound:
                    payload = dict(bound[0])
                    payload["replay"] = _replay_no_new_charge_evidence(typed_attempts)
                    result.evidence["server_evidence"] = payload
                _apply_public_artifact_gate(cell, result, typed_attempts)
    _scrub_private_replay_fields(result.evidence, typed_attempts)


def _evaluate_single_stage_receipts(attempts: list[dict[str, object]]):
    from .cursor_agent_v1 import Evaluation

    stage_b = [
        item for item in attempts if isinstance(item, dict) and item.get("stage") == "b"
    ]
    if not stage_b:
        return Evaluation("fail", "stage B completion is missing")
    for item in stage_b:
        if item.get("consume_match_count") != 1 or not item.get("receipt_hash"):
            return Evaluation(
                "fail",
                "stage B request id did not resolve to exactly one final receipt",
            )
    return Evaluation("pass")


def _apply_public_artifact_gate(
    cell: MatrixCell,
    result: CellResult,
    attempts: list[dict[str, object]] | None = None,
) -> None:
    evidence = result.evidence.get("server_evidence")
    if not isinstance(evidence, dict):
        return
    stream = result.evidence.get("stream")
    merged = dict(evidence)
    replay_meta = result.evidence.get("tool_replay")
    if isinstance(replay_meta, dict):
        merged["tool_replay"] = replay_meta
    public = evaluate_public_artifacts(
        cell,
        http_status=result.evidence.get("http_status")
        if isinstance(result.evidence.get("http_status"), int)
        else None,
        output="\n".join(item.output_tail for item in result.turns),
        evidence=merged,
        stream=stream if isinstance(stream, dict) else None,
        attempts=attempts,
        permission_mode=(
            "auto"
            if "client.classifier" in cell.scenario.required_capabilities
            else "bypassPermissions"
        ),
    )
    if public.status != "pass":
        result.status = "fail"
        result.detail = public.detail


def _set_batch_evidence_failure(result: CellResult, detail: str) -> None:
    result.evidence.pop("_response_request_id", None)
    result.evidence.pop("_response_request_ids", None)
    result.evidence.pop("_replay_attempts", None)
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
    other_dict = other if isinstance(other, dict) else {}
    citation_count = 0
    progress_event_count = 0
    if cell.route.channel_type == 64:
        web_search_call_count, citation_count, progress_event_count = (
            hosted_search_counts(other_dict)
        )
    else:
        web_search_call_count = int(other_dict.get("web_search_call_count", 0) or 0)
    search_evidence_valid = True
    search_detail = "native web search has no observed search call"
    if cell.scenario.id == "native-web-search":
        if (
            cell.route.channel_type == 64
            and cell.client.id not in NON_HOSTED_WEB_CLIENTS
        ):
            hosted = evaluate_hosted_search(
                web_search_call_count=web_search_call_count,
                citation_count=citation_count,
                progress_event_count=progress_event_count,
            )
            search_evidence_valid = hosted.ok
            search_detail = hosted.detail or search_detail
        else:
            search_evidence_valid = web_search_call_count > 0
    valid = bool(
        commit and receipt_id and receipt_state == "final" and search_evidence_valid
    )
    if cell.route.channel_type == 64:
        usage: dict[str, object] = type64_usage_fields(
            log,
            other_dict,
            web_search_call_count,
            citation_count,
            progress_event_count,
        )
    else:
        usage = {
            "prompt_tokens": int(log.get("prompt_tokens", 0) or 0),
            "completion_tokens": int(log.get("completion_tokens", 0) or 0),
            "quota": int(log.get("quota", 0) or 0),
            "use_time": int(log.get("use_time", 0) or 0),
            "web_search_call_count": web_search_call_count,
        }
    payload = {
        "status": "pass" if valid else "fail",
        "commit": commit,
        "route": {
            "id": cell.route.id,
            "channel_id": int(log.get("channel", 0) or 0),
            "group": str(log.get("group", "")),
        },
        "terminal": {
            "status": "completed" if int(log.get("type", 0) or 0) == 2 else "failed",
            "http_request_id_hash": correlate_id(str(log.get("request_id", ""))),
        },
        "receipt": {
            "id_hash": correlate_id(str(receipt_id or "")),
            "provider": str(other_dict.get("usage_receipt_provider", "")),
            "state": str(receipt_state or ""),
        },
        "usage": usage,
        "detail": ""
        if valid
        else (
            search_detail
            if not search_evidence_valid
            else "usage receipt is missing or not final"
        ),
    }
    if cell.route.channel_type == 64:
        quality = evaluate_usage_quality(payload, channel_type=64)
        if not quality.ok:
            payload["status"] = "fail"
            payload["detail"] = quality.detail
        mcp_spans = other_dict.get("cursor_agent_v1_mcp_spans")
        mcp_mode = other_dict.get("cursor_agent_v1_mcp_mode")
        if mcp_spans or mcp_mode:
            payload["mcp"] = {"mode": mcp_mode, "spans": mcp_spans or []}
    return payload


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
    merged = dict(evidence or {})
    for key, value in attach_completion_metadata(cell).items():
        merged.setdefault(key, value)
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
        evidence=merged,
        detail=detail,
    )
