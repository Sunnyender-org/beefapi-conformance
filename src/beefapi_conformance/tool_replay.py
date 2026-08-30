"""Black-box Anthropic Messages tool_use/tool_result replay driver.

Stage A asks the model to select a declared canary tool. Stage B sends the
exact assistant history plus real tool_result blocks. Stage C repeats Stage B
after a delay. HTTP request ids may change. Stage B settles one consume log and one final
receipt; Stage C exact duplicate request ids must add zero consume logs.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .cursor_agent_v1 import Evaluation, correlate_id

STATIC_TOOL_USE_ID = re.compile(r"^toolu_(conformance_|historical_routed_)")
CANARY_TOOL_NAME = "beefapi_conformance_canary"
CANARY_TOOL_B_NAME = "beefapi_conformance_canary_b"
MCP_ALPHA = "beefapi_mcp_alpha"
MCP_BETA = "beefapi_mcp_beta"

ExchangeFn = Callable[
    [dict[str, Any]], tuple[int | None, str, str | None, dict[str, Any]]
]


@dataclass(frozen=True)
class ToolUse:
    id: str
    name: str
    input: dict[str, Any]
    raw: dict[str, Any]


@dataclass
class ReplayResult:
    status: str
    detail: str = ""
    attempts: list[dict[str, Any]] = field(default_factory=list)
    tool_use_id_hashes: list[str] = field(default_factory=list)
    tool_uses: list[ToolUse] = field(default_factory=list)
    stage_b_payload: dict[str, Any] | None = None
    last_output: str = ""
    last_status: int | None = None
    stream: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)


def canary_tool(name: str = CANARY_TOOL_NAME) -> dict[str, Any]:
    return {
        "name": name,
        "description": "Caller-local conformance canary. Echo the marker field.",
        "input_schema": {
            "type": "object",
            "properties": {"marker": {"type": "string"}},
        },
    }


def mcp_tool(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "description": f"MCP canary {name}.",
        "input_schema": {"type": "object", "properties": {}},
    }


def tools_for_spec(spec: dict[str, Any]) -> list[dict[str, Any]]:
    mode = str(spec.get("mode") or "")
    if mode == "mcp":
        return [mcp_tool(MCP_ALPHA), mcp_tool(MCP_BETA)]
    if mode == "covering":
        return [canary_tool(), canary_tool(CANARY_TOOL_B_NAME)]
    return [canary_tool()]


def tool_choice_for_spec(spec: dict[str, Any]) -> dict[str, Any]:
    mode = str(spec.get("mode") or "")
    if mode in {"covering", "mcp"}:
        return {"type": "any"}
    return {"type": "tool", "name": CANARY_TOOL_NAME}


def is_static_tool_use_id(value: str) -> bool:
    return bool(STATIC_TOOL_USE_ID.match(value))


def payload_contains_static_tool_ids(payload: object) -> bool:
    return "toolu_conformance_" in json.dumps(payload, default=str)


def parse_json_objects(output: str) -> list[dict[str, Any]]:
    objects: list[dict[str, Any]] = []
    if not output:
        return objects
    try:
        parsed = json.loads(output)
        if isinstance(parsed, dict):
            objects.append(parsed)
        elif isinstance(parsed, list):
            objects.extend(item for item in parsed if isinstance(item, dict))
    except json.JSONDecodeError:
        pass
    for line in output.splitlines():
        data = line
        if line.startswith("data:"):
            data = line[5:].strip()
            if not data or data == "[DONE]":
                continue
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, dict):
            objects.append(parsed)
    return objects


def parse_tool_uses(output: str) -> list[ToolUse]:
    uses: list[ToolUse] = []
    seen: set[str] = set()
    for body in parse_json_objects(output):
        for block in _content_blocks(body):
            if not isinstance(block, dict) or block.get("type") != "tool_use":
                continue
            tool_id = block.get("id")
            name = block.get("name")
            if not isinstance(tool_id, str) or not tool_id or not isinstance(name, str):
                continue
            if tool_id in seen:
                continue
            seen.add(tool_id)
            raw_input = block.get("input")
            uses.append(
                ToolUse(
                    id=tool_id,
                    name=name,
                    input=raw_input if isinstance(raw_input, dict) else {},
                    raw=block,
                )
            )
    return uses


def parse_assistant_message(output: str) -> dict[str, Any] | None:
    for body in parse_json_objects(output):
        content = body.get("content")
        role = body.get("role")
        if (
            role == "assistant"
            and isinstance(content, list)
            and any(isinstance(item, dict) for item in content)
        ):
            return {"role": "assistant", "content": content}
        if body.get("type") == "message" and isinstance(content, list):
            return {"role": "assistant", "content": content}
    uses = parse_tool_uses(output)
    if uses:
        return {"role": "assistant", "content": [item.raw for item in uses]}
    return None


def parse_assistant_text(output: str) -> str:
    values: list[str] = []
    for body in _assistant_message_bodies(output):
        content = body.get("content")
        if isinstance(content, list):
            for item in content:
                if (
                    isinstance(item, dict)
                    and item.get("type") == "text"
                    and isinstance(item.get("text"), str)
                ):
                    values.append(item["text"])
        if isinstance(body.get("output_text"), str):
            values.append(body["output_text"])
    return "\n".join(values)


def parse_stop_reason(output: str) -> str:
    for body in _assistant_message_bodies(output):
        reason = body.get("stop_reason")
        if isinstance(reason, str) and reason:
            return reason
    return ""


def raw_tool_use_blocks(output: str) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    for body in parse_json_objects(output):
        for block in _content_blocks(body):
            if isinstance(block, dict) and block.get("type") == "tool_use":
                blocks.append(block)
    return blocks


def _assistant_message_bodies(output: str) -> list[dict[str, Any]]:
    bodies: list[dict[str, Any]] = []
    for body in parse_json_objects(output):
        role = body.get("role")
        if role != "assistant":
            continue
        content = body.get("content")
        if role == "assistant" and isinstance(content, list):
            bodies.append(body)
            continue
    return bodies


def stage_a_payload(spec: dict[str, Any], model: str, prompt: str) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "model": model,
        "max_tokens": int(spec.get("max_tokens") or 256),
        "tools": tools_for_spec(spec),
        "tool_choice": tool_choice_for_spec(spec),
        "messages": [{"role": "user", "content": prompt}],
    }
    extra = spec.get("stage_a_extra")
    if isinstance(extra, dict):
        payload.update(extra)
    return payload


def tool_results_for_uses(
    uses: list[ToolUse], *, marker: str | None = None
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for item in uses:
        content = marker or str(item.input.get("marker") or item.name)
        results.append(
            {
                "type": "tool_result",
                "tool_use_id": item.id,
                "content": content,
            }
        )
    return results


def covering_tool_results(uses: list[ToolUse], *, marker: str) -> list[dict[str, Any]]:
    """Covering-set tool_result blocks for ids returned by the parked Run."""
    return tool_results_for_uses(uses, marker=marker)


def mixed_followup_text(marker: str) -> str:
    """Ordinary consume-the-tool-result follow-up. Do not repeat a must-call prompt."""
    return f"Consume the tool result and reply exactly {marker}."


def stage_b_payload(
    stage_a: dict[str, Any],
    assistant: dict[str, Any],
    uses: list[ToolUse],
    spec: dict[str, Any],
    prompt: str,
    marker: str,
) -> dict[str, Any]:
    mode = str(spec.get("mode") or "")
    if mode == "covering":
        results = covering_tool_results(uses, marker=marker)
    else:
        results = tool_results_for_uses(uses, marker=marker)
    user_content: list[dict[str, Any]] = list(results)
    if mode == "mixed":
        user_content.append({"type": "text", "text": mixed_followup_text(marker)})
    payload = {
        "model": stage_a.get("model"),
        "max_tokens": stage_a.get("max_tokens", 256),
        "tools": stage_a.get("tools"),
        "tool_choice": {"type": "none"},
        "messages": [
            stage_a["messages"][0],
            assistant,
            {"role": "user", "content": user_content},
        ],
    }
    return payload


def payload_hash(payload: object) -> str:
    encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return correlate_id(encoded.decode("utf-8"))[7:]


def evaluate_none_terminal(output: str, marker: str) -> Evaluation:
    """Stage B/C under tool_choice none: no tool_use, end_turn, marker in assistant text."""
    if raw_tool_use_blocks(output):
        return Evaluation("fail", "tool_choice none produced a tool_use")
    if not _assistant_message_bodies(output):
        return Evaluation("fail", "tool_choice none lacked an assistant message")
    if parse_stop_reason(output) != "end_turn":
        return Evaluation("fail", "tool_choice none did not stop with end_turn")
    if marker not in parse_assistant_text(output):
        return Evaluation(
            "fail",
            "assistant text did not contain the expected marker",
        )
    return Evaluation("pass")


def terminal_semantics(output: str, status_code: int | None) -> dict[str, Any]:
    klass = (
        "2xx"
        if status_code is not None and 200 <= status_code < 300
        else str(status_code)
    )
    return {
        "http_status_class": klass,
        "stop_reason": parse_stop_reason(output),
        "text": parse_assistant_text(output),
        "tool_use_count": len(parse_tool_uses(output)),
    }


def evaluate_live_tool_ids(uses: list[ToolUse]) -> Evaluation:
    if not uses:
        return Evaluation("fail", "stage A returned no tool_use blocks")
    static = [item.id for item in uses if is_static_tool_use_id(item.id)]
    if static:
        return Evaluation(
            "fail",
            "static synthetic tool_use ids are not live evidence",
        )
    return Evaluation("pass")


def sleep_deltas(offsets: tuple[int, ...], *, origin: int = 0) -> list[int]:
    """Convert absolute elapsed offsets into successive sleep deltas."""
    previous = origin
    deltas: list[int] = []
    for offset in offsets:
        value = int(offset)
        deltas.append(max(0, value - previous))
        previous = max(previous, value)
    return deltas


def evaluate_replay_identity(
    attempts: list[dict[str, Any]], *, require_receipts: bool = False
) -> Evaluation:
    replay = [
        item
        for item in attempts
        if item.get("stage") in {"b", "c"} and not item.get("aborted")
    ]
    if len(replay) < 2:
        return Evaluation(
            "fail", "stage C replay of the completed tool_result is missing"
        )
    payloads = {str(item.get("request_hash") or "") for item in replay}
    if "" in payloads or len(payloads) != 1:
        return Evaluation(
            "fail", "retry payload drifted from the completed tool_result"
        )
    for item in replay:
        status = item.get("http_status")
        if not isinstance(status, int) or not 200 <= status < 300:
            return Evaluation(
                "fail",
                f"completed tool_result retry at +{item.get('offset_seconds')}s "
                f"was not idempotent HTTP {status}",
            )
    terminals = [
        str(item.get("terminal_hash") or "")
        for item in replay
        if item.get("terminal_hash")
    ]
    if terminals and len(set(terminals)) != 1:
        return Evaluation("fail", "terminal semantics drifted across replay")
    stage_b = [item for item in replay if item.get("stage") == "b"]
    stage_c = [item for item in replay if item.get("stage") == "c"]
    if not stage_b:
        return Evaluation("fail", "stage B completion is missing")
    if require_receipts:
        if any(not item.get("terminal_hash") for item in replay):
            return Evaluation("fail", "terminal semantics drifted across replay")
        settled = _release_stage_b_receipts(stage_b)
        if not settled.ok:
            return settled
    extra = _stage_c_consume_violation(stage_c, require_receipts=require_receipts)
    if extra is not None:
        return extra
    header = _response_receipt_header_violation(stage_b, replay)
    if header is not None:
        return header
    if not require_receipts:
        present = [
            str(item.get("receipt_hash") or "")
            for item in stage_b
            if item.get("receipt_hash")
        ]
        if present and len(set(present)) != 1:
            return Evaluation(
                "fail",
                "billing receipt identity drifted across replay; "
                "HTTP request ids are not receipts",
            )
    if require_receipts:
        return evaluate_generation_receipts(attempts)
    return Evaluation("pass")


def evaluate_generation_receipts(attempts: list[dict[str, Any]]) -> Evaluation:
    """Each new model generation A/B owns one exact, distinct final receipt."""
    receipts: dict[str, str] = {}
    for stage in ("b", "a"):
        rows = [item for item in attempts if item.get("stage") == stage]
        if len(rows) != 1:
            return Evaluation("fail", f"stage {stage.upper()} is missing or ambiguous")
        item = rows[0]
        if (
            item.get("consume_match_count") != 1
            or item.get("receipt_state") != "final"
            or not item.get("receipt_hash")
            or not item.get("http_request_id_hash")
        ):
            return Evaluation(
                "fail", f"stage {stage.upper()} lacks exactly one final receipt"
            )
        receipts[stage] = str(item["receipt_hash"])
        header = item.get("response_receipt_hash")
        if header and header != receipts[stage]:
            return Evaluation(
                "fail", f"stage {stage.upper()} response receipt header drifted"
            )
    if receipts["a"] == receipts["b"]:
        return Evaluation("fail", "new generation stages A and B reused one receipt")
    request_ids = {
        item.get("http_request_id_hash")
        for item in attempts
        if item.get("stage") in {"a", "b"}
    }
    if len(request_ids) != 2:
        return Evaluation(
            "fail", "generation stages A and B reused one HTTP request id"
        )
    return Evaluation("pass")


def generation_receipt_gap(attempts: list[dict[str, Any]]) -> str:
    """Polling hint only; the same generation evaluator owns the pass decision."""
    if evaluate_generation_receipts(attempts).ok:
        return "ok"
    for stage in ("a", "b"):
        rows = [item for item in attempts if item.get("stage") == stage]
        if len(rows) != 1:
            return "conflict"
        item = rows[0]
        count = item.get("consume_match_count")
        if isinstance(count, int) and count > 1:
            return "conflict"
    if any(
        item.get("stage") in {"a", "b"}
        and (
            item.get("consume_match_count") in {None, 0}
            or item.get("receipt_state") == "provisional"
        )
        for item in attempts
    ):
        return "missing"
    return "conflict"


def _stage_c_consume_violation(
    stage_c: list[dict[str, Any]], *, require_receipts: bool
) -> Evaluation | None:
    for item in stage_c:
        offset = item.get("offset_seconds")
        matches = item.get("consume_match_count")
        if require_receipts and not item.get("http_request_id_hash"):
            return Evaluation(
                "fail", f"stage C at +{offset}s lacks an exact request id"
            )
        if require_receipts and matches is None:
            return Evaluation(
                "fail",
                f"stage C at +{offset}s request id was not resolved against consume logs",
            )
        if require_receipts and matches != 0:
            return Evaluation(
                "fail",
                f"stage C at +{offset}s created a new consume log",
            )
        if not require_receipts and isinstance(matches, int) and matches > 0:
            return Evaluation(
                "fail",
                f"stage C at +{offset}s created a new consume log",
            )
        if item.get("receipt_hash"):
            return Evaluation(
                "fail",
                f"stage C at +{offset}s has a new or copied usage receipt",
            )
    return None


def _release_stage_b_receipts(stage_b: list[dict[str, Any]]) -> Evaluation:
    for item in stage_b:
        offset = item.get("offset_seconds")
        matches = item.get("consume_match_count")
        if matches != 1:
            return Evaluation(
                "fail",
                f"stage B at +{offset}s request id did not resolve to "
                "exactly one consume log",
            )
        if not item.get("receipt_hash"):
            return Evaluation(
                "fail",
                f"stage B at +{offset}s lacks a final usage receipt",
            )
    receipts = {str(item.get("receipt_hash") or "") for item in stage_b}
    if len(receipts) != 1 or "" in receipts:
        return Evaluation(
            "fail",
            "billing receipt identity drifted across replay; "
            "HTTP request ids are not receipts",
        )
    return Evaluation("pass")


def _response_receipt_header_violation(
    stage_b: list[dict[str, Any]], replay: list[dict[str, Any]]
) -> Evaluation | None:
    expected = str(stage_b[0].get("receipt_hash") or "") or str(
        stage_b[0].get("response_receipt_hash") or ""
    )
    if not expected:
        return None
    for item in replay:
        header = str(item.get("response_receipt_hash") or "")
        if header and header != expected:
            return Evaluation(
                "fail",
                "response receipt header hash drifted from stage B",
            )
    return None


def evaluate_mcp_spans(
    declared: str,
    spans: list[dict[str, Any]],
    tool_uses: list[ToolUse],
    tool_use_id_hashes: list[str] | None = None,
) -> Evaluation:
    from .cursor_agent_v1 import evaluate_mcp_mode

    live_ids = {item.id for item in tool_uses}
    live_hashes = {correlate_id(item.id) for item in tool_uses if item.id}
    live_hashes.update(item for item in (tool_use_id_hashes or []) if item)
    if len(live_ids) < 2 and len(live_hashes) < 2:
        return Evaluation(
            "blocked",
            "blocked: two-MCP live evidence requires a real parked batch of tool_use ids",
        )
    correlated: list[dict[str, Any]] = []
    for span in spans:
        if not isinstance(span, dict):
            continue
        raw_id = span.get("tool_use_id")
        hashed = span.get("tool_use_id_hash")
        if (
            raw_id in live_ids
            or hashed in live_hashes
            or (isinstance(raw_id, str) and correlate_id(raw_id) in live_hashes)
        ):
            correlated.append(span)
    if len(correlated) < 2:
        return Evaluation(
            "fail",
            "MCP spans are not correlated to returned tool_use ids",
        )
    return evaluate_mcp_mode(declared, correlated)


def execute_tool_replay(
    *,
    spec: dict[str, Any],
    model: str,
    prompt: str,
    marker: str,
    offsets: tuple[int, ...] = (),
    exchange: ExchangeFn,
    sleeper: Callable[[float], None] | None = None,
) -> ReplayResult:
    mode = str(spec.get("mode") or "")
    min_uses = int(
        spec.get("min_tool_uses") or (2 if mode in {"covering", "mcp"} else 1)
    )
    stage_a = stage_a_payload(spec, model, prompt)
    status_a, output_a, req_a, stream_a = exchange(stage_a)
    uses = parse_tool_uses(output_a)
    live = (
        evaluate_live_tool_ids(uses)
        if uses
        else Evaluation("fail", "stage A returned no tool_use blocks")
    )
    hashes = [correlate_id(item.id) for item in uses]
    attempts: list[dict[str, Any]] = [
        _attempt(
            "a",
            0,
            stage_a,
            status_a,
            output_a,
            req_a,
            stream_a,
        )
    ]
    if mode == "custom" and marker in parse_assistant_text(output_a) and not uses:
        return ReplayResult(
            status="fail",
            detail="custom-tool canary accepted a marker-only final answer without a tool_result round trip",
            attempts=attempts,
            tool_uses=uses,
            last_output=output_a,
            last_status=status_a,
            stream=stream_a,
            evidence={"tool_replay": {"stage": "a", "tool_use_id_hashes": []}},
        )
    if not live.ok:
        status = "blocked" if mode in {"covering", "mcp"} else "fail"
        detail = live.detail
        if mode in {"covering", "mcp"}:
            detail = (
                f"blocked: {mode} requires a real parked batch of at least "
                f"{min_uses} tool_use ids; static history is not live evidence"
            )
        return ReplayResult(
            status=status,
            detail=detail,
            attempts=attempts,
            tool_use_id_hashes=hashes,
            tool_uses=uses,
            last_output=output_a,
            last_status=status_a,
            stream=stream_a,
            evidence={"tool_replay": {"stage": "a", "tool_use_id_hashes": hashes}},
        )
    if len(uses) < min_uses:
        return ReplayResult(
            status="blocked",
            detail=(
                f"blocked: {mode} Stage A returned {len(uses)} tool_use blocks; "
                f"{min_uses} required from a real parked Run"
            ),
            attempts=attempts,
            tool_use_id_hashes=hashes,
            tool_uses=uses,
            last_output=output_a,
            last_status=status_a,
            stream=stream_a,
            evidence={"tool_replay": {"stage": "a", "tool_use_id_hashes": hashes}},
        )
    assistant = parse_assistant_message(output_a)
    if assistant is None:
        return ReplayResult(
            status="fail",
            detail="stage A assistant message could not be parsed for replay",
            attempts=attempts,
            tool_use_id_hashes=hashes,
            tool_uses=uses,
            last_output=output_a,
            last_status=status_a,
            stream=stream_a,
        )
    stage_b = stage_b_payload(stage_a, assistant, uses, spec, prompt, marker)
    status_b, output_b, req_b, stream_b = exchange(stage_b)
    attempts.append(_attempt("b", 0, stage_b, status_b, output_b, req_b, stream_b))
    last_status = status_b
    last_output = output_b
    stream = stream_b
    none_terminal = evaluate_none_terminal(output_b, marker)
    if not none_terminal.ok:
        return ReplayResult(
            status="fail",
            detail=none_terminal.detail,
            attempts=attempts,
            tool_use_id_hashes=hashes,
            tool_uses=uses,
            stage_b_payload=stage_b,
            last_output=last_output,
            last_status=last_status,
            stream=stream,
            evidence={
                "tool_replay": {
                    "stage": "b",
                    "tool_use_id_hashes": hashes,
                }
            },
        )
    if offsets:
        pause = sleeper or _default_sleep
        for offset, delta in zip(offsets, sleep_deltas(offsets), strict=True):
            pause(delta)
            status_c, output_c, req_c, stream_c = exchange(stage_b)
            attempts.append(
                _attempt("c", offset, stage_b, status_c, output_c, req_c, stream_c)
            )
            last_status = status_c
            last_output = output_c
            stream = stream_c
        replay = evaluate_replay_identity(attempts, require_receipts=False)
        if not replay.ok:
            return ReplayResult(
                status="fail",
                detail=replay.detail,
                attempts=attempts,
                tool_use_id_hashes=hashes,
                tool_uses=uses,
                stage_b_payload=stage_b,
                last_output=last_output,
                last_status=last_status,
                stream=stream,
                evidence={
                    "tool_replay": {
                        "stage": "c",
                        "tool_use_id_hashes": hashes,
                    }
                },
            )
    return ReplayResult(
        status="pass",
        attempts=attempts,
        tool_use_id_hashes=hashes,
        tool_uses=uses,
        stage_b_payload=stage_b,
        last_output=last_output,
        last_status=last_status,
        stream=stream,
        evidence={
            "tool_replay": {
                "mode": mode,
                "tool_use_id_hashes": hashes,
                "http_request_id_hashes": [
                    item.get("http_request_id_hash")
                    for item in attempts
                    if item.get("http_request_id_hash")
                ],
            }
        },
    )


def _attempt(
    stage: str,
    offset: int,
    payload: dict[str, Any],
    status: int | None,
    output: str,
    request_id: str | None,
    stream: dict[str, Any] | None = None,
) -> dict[str, Any]:
    semantics = terminal_semantics(output, status)
    response_receipt_hash = ""
    if isinstance(stream, dict):
        response_receipt_hash = str(stream.pop("response_receipt_hash", "") or "")
    return {
        "stage": stage,
        "offset_seconds": offset,
        "http_status": status,
        "request_hash": payload_hash(payload),
        "http_request_id_hash": correlate_id(request_id or ""),
        "_http_request_id": request_id or "",
        "receipt_hash": "",
        "response_receipt_hash": response_receipt_hash,
        "consume_match_count": None,
        "replay_without_consume": False,
        "no_new_charge": False,
        "terminal_hash": correlate_id(json.dumps(semantics, sort_keys=True)),
        "stop_reason": semantics["stop_reason"],
        "aborted": False,
    }


def _content_blocks(value: object) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    if isinstance(value, list):
        for item in value:
            blocks.extend(_content_blocks(item))
        return blocks
    if not isinstance(value, dict):
        return blocks
    content = value.get("content")
    if isinstance(content, list):
        for item in content:
            if isinstance(item, dict):
                blocks.append(item)
                blocks.extend(_content_blocks(item))
    if value.get("type") == "tool_use":
        blocks.append(value)
    inner = value.get("content_block")
    if isinstance(inner, dict):
        blocks.append(inner)
    for key, item in value.items():
        if key in {"content", "content_block"}:
            continue
        if isinstance(item, (dict, list)):
            blocks.extend(_content_blocks(item))
    return blocks


def _default_sleep(seconds: float) -> None:
    import time

    time.sleep(seconds)
