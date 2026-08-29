"""Cursor Agent v1 (channel type 64) completion contract.

Evaluates public client output and sanitized server evidence. It does not
inspect BeefAPI internals or persist raw request/receipt identifiers.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

from .model import CellResult, ContractError, MatrixCell

ROOT = Path(__file__).resolve().parents[2]
INVENTORY_PATH = ROOT / "manifests/cursor-agent-v1-completion.json"
COMPLETION_TIERS = {"nightly", "release"}
UNOBSERVABLE_FIELDS = ("prompt_tokens", "cache_tokens")
ALLOWED_UNOBSERVABLE_QUALITIES = frozenset({"unknown", "estimated"})
LOCAL_WEB_TOOLS = frozenset({"WebSearch", "WebFetch", "web_search", "web_fetch"})
CLASSIFIER_MARKERS = (
    "classifier",
    '"permissionMode": "default"',
    '"permissionMode":"default"',
    "auto_mode",
    "auto-mode",
)
AGENT_V1_PUBLIC_ID = re.compile(r"resp_bf_agentv1_u[0-9]+_c[0-9]+_[A-Za-z0-9]+")
RAW_ID_KEYS = frozenset(
    {
        "request_id",
        "usage_receipt_id",
        "receipt_id",
        "request_id_raw",
        "http_request_id",
        "tool_use_id",
    }
)
APPLICABLE_CLIENT_SCENARIOS = frozenset(
    {"text-turn", "local-tool-read", "session-resume"}
)
REQUIRED_NATIVE_CLIENTS = frozenset(
    {"claude-code", "codex-cli", "grok-build", "workbuddy-cli"}
)
NON_HOSTED_WEB_CLIENTS = frozenset({"codex-cli", "grok-build", "workbuddy-cli"})


@dataclass(frozen=True)
class Evaluation:
    status: str
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.status == "pass"


@dataclass(frozen=True)
class CompletionItem:
    id: str
    scenario: str | None
    weight: str
    capabilities: frozenset[str]
    evidence: tuple[str, ...]
    gate: str | None = None


@dataclass(frozen=True)
class CompletionInventory:
    family: str
    channel_type: int
    family_capability: str
    caller_tool_canaries: tuple[str, ...]
    hidden_native_tools: tuple[str, ...]
    items: tuple[CompletionItem, ...]
    by_scenario: dict[str, CompletionItem] = field(default_factory=dict)

    def critical_scenario_items(self) -> tuple[CompletionItem, ...]:
        return tuple(
            item for item in self.items if item.weight == "critical" and item.scenario
        )


def correlate_id(value: str) -> str:
    if not value:
        return ""
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]
    return f"sha256:{digest}"


def redact_correlation_ids(text: str) -> str:
    if not text:
        return text
    return AGENT_V1_PUBLIC_ID.sub(lambda match: correlate_id(match.group(0)), text)


def sanitize_report_value(
    value: Any, key: str | None = None, parent: str | None = None
) -> Any:
    sensitive = key in RAW_ID_KEYS or (parent == "receipt" and key == "id")
    if sensitive and isinstance(value, str):
        if value.startswith("sha256:"):
            return value
        return correlate_id(value)
    if isinstance(value, str):
        return redact_correlation_ids(value)
    if isinstance(value, list):
        return [sanitize_report_value(item, key, parent=parent) for item in value]
    if isinstance(value, dict):
        return {
            inner_key: sanitize_report_value(inner, inner_key, parent=key)
            for inner_key, inner in value.items()
        }
    return value


def sanitize_server_evidence(payload: dict[str, Any]) -> dict[str, Any]:
    sanitized = sanitize_report_value(payload)
    return sanitized if isinstance(sanitized, dict) else {"status": "fail"}


@lru_cache(maxsize=1)
def load_completion_inventory(path: str | None = None) -> CompletionInventory:
    inventory_path = Path(path) if path else INVENTORY_PATH
    try:
        raw = json.loads(inventory_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read {inventory_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ContractError("completion inventory must be an object")
    items_raw = raw.get("items")
    if not isinstance(items_raw, list) or not items_raw:
        raise ContractError("completion inventory.items must be a non-empty array")
    items: list[CompletionItem] = []
    by_scenario: dict[str, CompletionItem] = {}
    for entry in items_raw:
        if not isinstance(entry, dict):
            raise ContractError("completion inventory item must be an object")
        weight = entry.get("weight")
        if weight not in {"critical", "major"}:
            raise ContractError(f"completion item weight invalid: {weight!r}")
        scenario = entry.get("scenario")
        if scenario is not None and (not isinstance(scenario, str) or not scenario):
            raise ContractError("completion item.scenario must be a string or null")
        capabilities = entry.get("capabilities")
        if not isinstance(capabilities, list) or not all(
            isinstance(item, str) and item for item in capabilities
        ):
            raise ContractError("completion item.capabilities must be a string array")
        evidence = entry.get("evidence", [])
        if not isinstance(evidence, list) or not all(
            isinstance(item, str) for item in evidence
        ):
            raise ContractError("completion item.evidence must be a string array")
        item = CompletionItem(
            id=str(entry.get("id") or ""),
            scenario=scenario,
            weight=weight,
            capabilities=frozenset(capabilities),
            evidence=tuple(evidence),
            gate=entry.get("gate") if isinstance(entry.get("gate"), str) else None,
        )
        if not item.id:
            raise ContractError("completion item.id is required")
        items.append(item)
        if item.scenario:
            by_scenario[item.scenario] = item
    canaries = raw.get("caller_tool_canaries", [])
    hidden = raw.get("hidden_native_tools", [])
    if not isinstance(canaries, list) or not isinstance(hidden, list):
        raise ContractError("completion tool canary lists must be arrays")
    return CompletionInventory(
        family=str(raw.get("family") or "cursor-agent-v1"),
        channel_type=int(raw.get("channel_type") or 64),
        family_capability=str(raw.get("family_capability") or "cursor.agent_v1"),
        caller_tool_canaries=tuple(str(item) for item in canaries),
        hidden_native_tools=tuple(str(item) for item in hidden),
        items=tuple(items),
        by_scenario=by_scenario,
    )


def validate_completion_references(scenario_ids: set[str]) -> None:
    missing = sorted(
        item.scenario
        for item in load_completion_inventory().items
        if item.scenario and item.scenario not in scenario_ids
    )
    if missing:
        raise ContractError(
            "completion inventory references unknown scenarios: " + ", ".join(missing)
        )


def lookup_item(scenario_id: str) -> CompletionItem | None:
    return load_completion_inventory().by_scenario.get(scenario_id)


def client_coverage_required(cell: MatrixCell) -> bool:
    if cell.scenario.id not in APPLICABLE_CLIENT_SCENARIOS:
        return False
    if cell.client.id not in REQUIRED_NATIVE_CLIENTS:
        return False
    if cell.client.id == "workbuddy-cli":
        return True
    return cell.route.channel_type == 64


def attach_completion_metadata(cell: MatrixCell) -> dict[str, Any]:
    completion: dict[str, Any] = {}
    if cell.route.channel_type == 64:
        item = lookup_item(cell.scenario.id)
        if item is not None:
            completion = {
                "family": "cursor-agent-v1",
                "item": item.id,
                "weight": item.weight,
                "required_release": item.weight == "critical",
                "capabilities": sorted(item.capabilities),
            }
    if client_coverage_required(cell):
        if completion:
            completion["required_release"] = True
            completion["client_coverage"] = True
        else:
            completion = {
                "family": "cursor-agent-v1",
                "item": f"client-coverage:{cell.client.id}:{cell.scenario.id}",
                "weight": "critical",
                "required_release": True,
                "client_coverage": True,
            }
    if not completion:
        return {}
    return {"completion": completion}


def forced_representative_cell(cell: MatrixCell) -> bool:
    if client_coverage_required(cell):
        if cell.client.id == "workbuddy-cli":
            return True
        return cell.model.id == cell.route.test_model
    if cell.route.channel_type != 64:
        return False
    if cell.model.id != cell.route.test_model:
        return False
    item = lookup_item(cell.scenario.id)
    if item is None or item.weight != "critical":
        return False
    if cell.scenario.kind == "http":
        return cell.client.adapter == "raw-http"
    return cell.client.id == "claude-code"


def type64_usage_fields(
    log: dict[str, Any],
    other: dict[str, Any],
    web_search_call_count: int,
    citation_count: int,
    progress_event_count: int,
) -> dict[str, Any]:
    prompt = int(log.get("prompt_tokens", 0) or 0)
    completion = int(log.get("completion_tokens", 0) or 0)
    cache = int(other.get("cache_tokens", other.get("cached_tokens", 0)) or 0)
    quota = int(log.get("quota", 0) or 0)
    use_time = int(log.get("use_time", 0) or 0)
    observed_completion: dict[str, Any]
    if completion == 0:
        observed_completion = {"value": None, "quality": "unknown"}
    else:
        observed_completion = {"value": completion, "quality": "measured"}
    observed_search: dict[str, Any]
    if web_search_call_count:
        observed_search = {"value": web_search_call_count, "quality": "measured"}
    else:
        observed_search = {"value": None, "quality": "unknown"}
    return {
        "observed_usage": {
            "prompt_tokens": {"value": None, "quality": "unknown"},
            "cache_tokens": {"value": None, "quality": "unknown"},
            "completion_tokens": observed_completion,
            "web_search_call_count": observed_search,
        },
        "billing_estimate": {
            "prompt_tokens": {"value": prompt, "quality": "estimated"},
            "cache_tokens": {"value": cache, "quality": "estimated"},
            "completion_tokens": {"value": completion, "quality": "estimated"},
            "quota": {"value": quota, "quality": "estimated"},
            "use_time": {"value": use_time, "quality": "measured"},
        },
        "web_search_call_count": web_search_call_count,
        "citation_count": citation_count,
        "progress_event_count": progress_event_count,
    }


def evaluate_usage_quality(
    payload: dict[str, Any], *, channel_type: int | None = None
) -> Evaluation:
    usage = payload.get("usage")
    if not isinstance(usage, dict):
        return Evaluation("fail", "usage evidence is missing")
    observed = usage.get("observed_usage")
    estimate = usage.get("billing_estimate")
    type64 = channel_type == 64 or isinstance(observed, dict)
    if not type64:
        return Evaluation("pass")
    if not isinstance(observed, dict) or not isinstance(estimate, dict):
        zeros = [
            key
            for key in UNOBSERVABLE_FIELDS
            if int(usage.get(key, 0) or 0) == 0 and not isinstance(usage.get(key), dict)
        ]
        if zeros:
            return Evaluation(
                "fail",
                "type64 input/cache must not be reported as measured zero; "
                "use observed_usage quality unknown/estimated vs billing_estimate",
            )
        return Evaluation(
            "fail",
            "type64 evidence must distinguish observed_usage from billing_estimate",
        )
    for field_name in UNOBSERVABLE_FIELDS:
        item = observed.get(field_name)
        if not isinstance(item, dict):
            return Evaluation(
                "fail", f"type64 observed_usage.{field_name} is missing quality"
            )
        quality = item.get("quality")
        if quality not in ALLOWED_UNOBSERVABLE_QUALITIES:
            return Evaluation(
                "fail",
                f"type64 observed_usage.{field_name} quality must be "
                "unknown or estimated, not measured",
            )
        if quality == "measured":
            return Evaluation(
                "fail",
                f"type64 observed_usage.{field_name} is unobservable and cannot be measured",
            )
        if quality == "estimated" and item.get("value") is None:
            return Evaluation(
                "fail",
                f"type64 observed_usage.{field_name} estimate is missing a value",
            )
    if observed == estimate:
        return Evaluation(
            "fail", "observed_usage and billing_estimate must be distinct"
        )
    return Evaluation("pass")


def hosted_search_counts(other: dict[str, Any]) -> tuple[int, int, int]:
    count = int(other.get("cursor_agent_v1_hosted_search_call_count", 0) or 0)
    citations = int(other.get("cursor_agent_v1_hosted_search_citation_count", 0) or 0)
    progress = int(other.get("cursor_agent_v1_hosted_search_progress_events", 0) or 0)
    return count, citations, progress


def evaluate_hosted_search(
    *,
    web_search_call_count: int,
    citation_count: int,
    progress_event_count: int,
    client_output: str = "",
) -> Evaluation:
    local_web = _local_web_tools_executed(client_output)
    if local_web:
        return Evaluation(
            "fail",
            "Cursor native WebSearch/WebFetch must surface as server-tool "
            f"progress; client executed {sorted(local_web)}",
        )
    if web_search_call_count < 1:
        return Evaluation("fail", "native web search has no observed search call")
    if progress_event_count < 1:
        return Evaluation("fail", "native web search has no server-tool progress")
    if citation_count < 1:
        return Evaluation("fail", "native web search has no citations")
    return Evaluation("pass")


def parse_tools_from_output(output: str) -> list[str]:
    names: list[str] = []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(event, dict):
            continue
        tools = event.get("tools")
        if event.get("type") == "system" and isinstance(tools, list):
            names.extend(_tool_name(item) for item in tools)
            continue
        message = event.get("message")
        if isinstance(message, dict) and isinstance(message.get("tools"), list):
            names.extend(_tool_name(item) for item in message["tools"])
    return [item for item in names if item]


def evaluate_tool_catalog(tools: Iterable[str]) -> Evaluation:
    inventory = load_completion_inventory()
    visible = {item for item in tools if item}
    missing = [name for name in inventory.caller_tool_canaries if name not in visible]
    leaked = [name for name in inventory.hidden_native_tools if name in visible]
    if missing and not any(name in visible for name in inventory.caller_tool_canaries):
        return Evaluation(
            "fail",
            "caller local tools are not visible: " + ", ".join(missing),
        )
    if leaked:
        return Evaluation(
            "fail",
            "Cursor native shell/fs tools leaked into the catalog: "
            + ", ".join(leaked),
        )
    required_local = [
        name for name in ("Bash", "Read") if name in inventory.caller_tool_canaries
    ]
    if required_local and not any(name in visible for name in required_local):
        return Evaluation(
            "fail",
            "caller local tools Bash/Read must remain visible/executable",
        )
    return Evaluation("pass")


def evaluate_http_status(status_code: int | None) -> Evaluation:
    if status_code is None:
        return Evaluation("fail", "no HTTP status")
    if 400 <= status_code < 500:
        return Evaluation("fail", f"tool_result protocol returned {status_code}")
    if 200 <= status_code < 300:
        return Evaluation("pass")
    return Evaluation("fail", f"unexpected HTTP {status_code}")


def evaluate_idempotent_retries(attempts: list[dict[str, Any]]) -> Evaluation:
    from .tool_replay import evaluate_replay_identity

    replay = [
        item
        for item in attempts
        if item.get("stage") in {"b", "c"} or item.get("offset_seconds")
    ]
    if any(item.get("stage") in {"b", "c"} for item in attempts):
        return evaluate_replay_identity(attempts)
    if len(replay) < 2:
        if len(attempts) < 2:
            return Evaluation(
                "fail", "identical tool_result retry attempts are missing"
            )
        replay = [item for item in attempts if not item.get("aborted")]
    hashes = {str(item.get("request_hash") or "") for item in replay}
    if "" in hashes or len(hashes) != 1:
        return Evaluation(
            "fail", "retry payload drifted from the completed tool_result"
        )
    for item in replay:
        status = evaluate_http_status(
            item.get("http_status")
            if isinstance(item.get("http_status"), int)
            else None
        )
        if not status.ok:
            offset = item.get("offset_seconds")
            return Evaluation(
                "fail",
                f"completed tool_result retry at +{offset}s was not idempotent: {status.detail}",
            )
    receipts = {
        str(item.get("receipt_hash") or "")
        for item in replay
        if item.get("receipt_hash")
    }
    if receipts and len(receipts) != 1:
        return Evaluation(
            "fail",
            "billing receipt identity drifted across replay; HTTP request ids are not receipts",
        )
    return Evaluation("pass")


def evaluate_mcp_mode(declared: str, spans: list[dict[str, Any]]) -> Evaluation:
    if declared not in {"serial", "parallel"}:
        return Evaluation("fail", f"unsupported MCP mode {declared!r}")
    if len(spans) < 2:
        return Evaluation("fail", "two-MCP evidence requires at least two spans")
    overlap = any(
        _spans_overlap(left, right)
        for index, left in enumerate(spans)
        for right in spans[index + 1 :]
    )
    if declared == "serial" and overlap:
        return Evaluation("fail", "declared serial MCP contract but spans overlapped")
    if declared == "parallel" and not overlap:
        return Evaluation(
            "fail", "declared parallel MCP contract but spans were serial"
        )
    return Evaluation("pass")


def evaluate_stream_progress(stream: dict[str, Any] | None) -> Evaluation:
    if not isinstance(stream, dict):
        return Evaluation("fail", "thinking-only stream produced no timing evidence")
    if stream.get("first_byte_ms") is None:
        return Evaluation(
            "fail", "thinking-only stream produced no measurable first-byte"
        )
    keepalive = int(stream.get("keepalive_count") or 0)
    progress = int(stream.get("progress_event_count") or 0)
    if keepalive + progress < 1:
        return Evaluation("fail", "thinking-only time produced no progress/keepalive")
    return Evaluation("pass")


def evaluate_classifier(
    output: str,
    evidence: dict[str, Any] | None = None,
    permission_mode: str | None = None,
) -> Evaluation:
    if permission_mode == "bypassPermissions":
        return Evaluation(
            "fail",
            "Claude Code auto-mode classifier cannot run under bypassPermissions",
        )
    payload = evidence or {}
    classifier = payload.get("classifier")
    if isinstance(classifier, dict) and classifier.get("invoked") is True:
        return Evaluation("pass")
    lowered = output.lower()
    if any(marker.lower() in lowered for marker in CLASSIFIER_MARKERS):
        return Evaluation("pass")
    return Evaluation("fail", "Claude Code auto-mode classifier was not observed")


def evaluate_disconnect(attempts: list[dict[str, Any]]) -> Evaluation:
    if len(attempts) < 2:
        return Evaluation(
            "fail", "disconnect evidence requires abort plus a completed retry"
        )
    aborted, completed = attempts[0], attempts[1]
    if not aborted.get("aborted"):
        return Evaluation(
            "fail", "client disconnect did not abort an in-flight request"
        )
    status = evaluate_http_status(
        completed.get("http_status")
        if isinstance(completed.get("http_status"), int)
        else None
    )
    if not status.ok:
        return Evaluation("fail", f"post-disconnect request failed: {status.detail}")
    first = str(aborted.get("receipt_hash") or "")
    second = str(completed.get("receipt_hash") or "")
    if first and second and first == second:
        return Evaluation("fail", "disconnect reused the prior receipt correlation")
    return Evaluation("pass")


def evaluate_receipt_uniqueness(results: list[CellResult]) -> list[str]:
    seen: dict[str, str] = {}
    collisions: list[str] = []
    for result in results:
        if result.status not in {"pass", "fail"}:
            continue
        payloads = _receipt_payloads(result)
        for hashed in payloads:
            previous = seen.get(hashed)
            if previous and previous != result.cell_id:
                collisions.append(hashed)
                if result.status == "pass":
                    result.status = "fail"
                    result.detail = "receipt correlation is not unique"
            else:
                seen[hashed] = result.cell_id
    return collisions


def missing_critical_executions(
    planned: list[MatrixCell],
    results: list[CellResult] | None = None,
) -> list[str]:
    inventory = load_completion_inventory()
    by_route: dict[str, list[MatrixCell]] = {}
    for cell in planned:
        if cell.route.channel_type != 64:
            continue
        by_route.setdefault(cell.route.id, []).append(cell)
    missing: list[str] = []
    result_index: dict[tuple[str, str], list[CellResult]] = {}
    for result in results or []:
        result_index.setdefault((result.route_id, result.scenario_id), []).append(
            result
        )
    for route_id, cells in by_route.items():
        advertised = cells[0].route.capabilities
        planned_scenarios = {cell.scenario.id for cell in cells}
        for item in inventory.critical_scenario_items():
            if not item.scenario or not item.capabilities.issubset(advertised):
                continue
            if item.scenario not in planned_scenarios:
                missing.append(f"{route_id}/{item.scenario}")
                continue
            if results is None:
                continue
            matching = result_index.get((route_id, item.scenario), [])
            executed = [result for result in matching if result.status not in {"skip"}]
            if not executed:
                missing.append(f"{route_id}/{item.scenario}")
    missing.extend(_missing_client_coverage(planned, results))
    return missing


def _missing_client_coverage(
    planned: list[MatrixCell],
    results: list[CellResult] | None,
) -> list[str]:
    missing: list[str] = []
    by_route: dict[str, list[MatrixCell]] = {}
    for cell in planned:
        by_route.setdefault(cell.route.id, []).append(cell)
    for route_id, cells in by_route.items():
        route_clients = cells[0].route.clients
        planned_scenarios = {cell.scenario.id for cell in cells}
        type64 = cells[0].route.channel_type == 64
        for client_id in sorted(REQUIRED_NATIVE_CLIENTS & route_clients):
            if client_id != "workbuddy-cli" and not type64:
                continue
            for scenario_id in sorted(APPLICABLE_CLIENT_SCENARIOS):
                if scenario_id not in planned_scenarios:
                    continue
                matching = [
                    cell
                    for cell in cells
                    if cell.client.id == client_id and cell.scenario.id == scenario_id
                ]
                if not matching:
                    missing.append(f"{route_id}/{client_id}/{scenario_id}")
                    continue
                if results is None:
                    continue
                hits = [
                    result
                    for result in results
                    if result.route_id == route_id
                    and result.scenario_id == scenario_id
                    and result.cell_id.startswith(f"{client_id}/")
                ]
                if not hits or all(item.status == "skip" for item in hits):
                    missing.append(f"{route_id}/{client_id}/{scenario_id}")
    return missing


def apply_completion_gates(
    results: list[CellResult],
    *,
    tier: str | None = None,
) -> list[CellResult]:
    release_like = tier in COMPLETION_TIERS
    for result in results:
        completion = result.evidence.get("completion")
        required = (
            isinstance(completion, dict) and completion.get("required_release") is True
        )
        if release_like and required and result.status == "skip":
            result.status = "fail"
            prefix = "required release cell was skipped or unexecuted"
            result.detail = f"{prefix}: {result.detail}" if result.detail else prefix
    evaluate_receipt_uniqueness(results)
    return results


def evaluate_public_artifacts(
    cell: MatrixCell,
    *,
    http_status: int | None = None,
    output: str = "",
    evidence: dict[str, Any] | None = None,
    stream: dict[str, Any] | None = None,
    attempts: list[dict[str, Any]] | None = None,
    permission_mode: str | None = None,
) -> Evaluation:
    details: list[str] = []
    requirements = cell.scenario.evidence_requirements
    payload = evidence or {}

    if cell.route.channel_type == 64 and payload.get("status") == "pass":
        quality = evaluate_usage_quality(payload, channel_type=64)
        if not quality.ok:
            details.append(quality.detail)

    if "http.not_4xx" in requirements or cell.scenario.retry_offsets_seconds:
        status = evaluate_http_status(http_status)
        if not status.ok:
            details.append(status.detail)

    if cell.scenario.retry_offsets_seconds:
        retry = evaluate_idempotent_retries(attempts or [])
        if not retry.ok:
            details.append(retry.detail)

    if "tool.catalog" in requirements:
        catalog = evaluate_tool_catalog(parse_tools_from_output(output))
        if not catalog.ok:
            details.append(catalog.detail)

    if "tool.custom.round_trip" in requirements:
        replay = (
            payload.get("tool_replay")
            if isinstance(payload.get("tool_replay"), dict)
            else {}
        )
        hashes = replay.get("tool_use_id_hashes") if isinstance(replay, dict) else []
        if not hashes:
            details.append(
                "custom-tool canary did not prove tool selection plus tool_result round trip"
            )

    if (
        cell.scenario.id == "native-web-search"
        and cell.route.channel_type == 64
        and cell.client.id not in NON_HOSTED_WEB_CLIENTS
    ):
        usage = payload.get("usage") if isinstance(payload.get("usage"), dict) else {}
        if payload.get("status") in {"pass", "fail"} or usage:
            hosted = evaluate_hosted_search(
                web_search_call_count=int(usage.get("web_search_call_count") or 0),
                citation_count=int(usage.get("citation_count") or 0),
                progress_event_count=int(usage.get("progress_event_count") or 0),
                client_output=output,
            )
            if not hosted.ok:
                details.append(hosted.detail)

    if cell.scenario.mcp_mode:
        from .tool_replay import evaluate_mcp_spans, parse_tool_uses

        mcp = payload.get("mcp") if isinstance(payload.get("mcp"), dict) else {}
        spans = mcp.get("spans") if isinstance(mcp.get("spans"), list) else []
        typed_spans = [item for item in spans if isinstance(item, dict)]
        replay_meta = (
            payload.get("tool_replay")
            if isinstance(payload.get("tool_replay"), dict)
            else {}
        )
        hashed_ids = (
            [str(item) for item in replay_meta.get("tool_use_id_hashes") or []]
            if isinstance(replay_meta, dict)
            else []
        )
        uses = parse_tool_uses(output)
        if typed_spans or uses or hashed_ids:
            mode = evaluate_mcp_spans(
                cell.scenario.mcp_mode,
                typed_spans,
                uses,
                hashed_ids,
            )
            if mode.status == "blocked" or not mode.ok:
                details.append(mode.detail)
        elif "mcp.serial" in requirements or "mcp.parallel" in requirements:
            if payload.get("status") in {"pass", "fail"}:
                details.append(
                    "two-MCP execution spans missing from sanitized evidence"
                )

    if "stream.first_byte" in requirements or "stream.keepalive" in requirements:
        progress = evaluate_stream_progress(stream)
        if not progress.ok:
            details.append(progress.detail)

    if "client.classifier" in requirements:
        classifier = evaluate_classifier(output, payload, permission_mode)
        if not classifier.ok:
            details.append(classifier.detail)

    if "lifecycle.disconnect" in requirements:
        disconnect = evaluate_disconnect(attempts or [])
        if not disconnect.ok:
            details.append(disconnect.detail)

    if not details:
        return Evaluation("pass")
    return Evaluation("fail", "; ".join(details))


def _tool_name(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        name = value.get("name")
        return name if isinstance(name, str) else ""
    return ""


def _local_web_tools_executed(output: str) -> set[str]:
    names: set[str] = set()
    if not output:
        return names
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        for name in _walk_tool_names(event):
            if name in LOCAL_WEB_TOOLS:
                names.add(name)
    return names


def _walk_tool_names(value: Any) -> list[str]:
    names: list[str] = []
    if isinstance(value, list):
        for item in value:
            names.extend(_walk_tool_names(item))
        return names
    if not isinstance(value, dict):
        return names
    name = value.get("name")
    event_type = str(value.get("type") or "")
    if (
        isinstance(name, str)
        and name in LOCAL_WEB_TOOLS
        and event_type in {"tool_use", "tool_result", "function_call"}
    ):
        names.append(name)
    for item in value.values():
        names.extend(_walk_tool_names(item))
    return names


def _spans_overlap(left: dict[str, Any], right: dict[str, Any]) -> bool:
    try:
        left_start = int(left["start"])
        left_end = int(left["end"])
        right_start = int(right["start"])
        right_end = int(right["end"])
    except (KeyError, TypeError, ValueError):
        return False
    return left_start < right_end and right_start < left_end


def _receipt_payloads(result: CellResult) -> list[str]:
    evidence = result.evidence.get("server_evidence")
    if not isinstance(evidence, dict):
        return []
    rows = [evidence]
    extra = evidence.get("requests")
    if isinstance(extra, list):
        rows.extend(item for item in extra if isinstance(item, dict))
    hashes: list[str] = []
    for row in rows:
        receipt = row.get("receipt")
        if not isinstance(receipt, dict):
            continue
        hashed = receipt.get("id_hash")
        if isinstance(hashed, str) and hashed:
            hashes.append(hashed)
    return hashes
