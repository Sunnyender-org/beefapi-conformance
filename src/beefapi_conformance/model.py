from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

TIERS = {"pr": 0, "merge": 1, "nightly": 2, "release": 3}
SENSITIVE_HTTP_PAYLOAD_KEYS = {
    "accesstoken",
    "apikey",
    "authorization",
    "authtoken",
    "bearertoken",
    "clientsecret",
    "cookie",
    "idtoken",
    "password",
    "proxyauthorization",
    "refreshtoken",
    "setcookie",
    "token",
    "xapikey",
}
TOKEN_LITERAL = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
BEARER_LITERAL = re.compile(r"\bBearer\s+[A-Za-z0-9._~+/-]{8,}\b", re.IGNORECASE)


class ContractError(ValueError):
    pass


def _strings(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ContractError(f"{field_name} must be a non-empty string array")
    return tuple(value)


def _required(raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise ContractError(f"{key} is required")
    return value


def _validate_http_payload_credentials(value: Any) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            normalized = re.sub(r"[^a-z0-9]", "", str(key).strip().lower())
            if normalized in SENSITIVE_HTTP_PAYLOAD_KEYS:
                raise ContractError(
                    f"scenario.http_payload must not persist credential key {key!r}"
                )
            _validate_http_payload_credentials(item)
        return
    if isinstance(value, list):
        for item in value:
            _validate_http_payload_credentials(item)
        return
    if isinstance(value, str) and (
        TOKEN_LITERAL.search(value) or BEARER_LITERAL.search(value)
    ):
        raise ContractError(
            "scenario.http_payload must not persist credential literals"
        )


@dataclass(frozen=True)
class Client:
    id: str
    name: str
    adapter: str
    binary_candidates: tuple[str, ...]
    version_args: tuple[str, ...]
    capabilities: frozenset[str]
    platforms: frozenset[str]

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> Client:
        return cls(
            id=_required(raw, "id"),
            name=_required(raw, "name"),
            adapter=_required(raw, "adapter"),
            binary_candidates=_strings(
                raw.get("binary_candidates"), "client.binary_candidates"
            ),
            version_args=tuple(raw.get("version_args", ["--version"])),
            capabilities=frozenset(
                _strings(raw.get("capabilities"), "client.capabilities")
            ),
            platforms=frozenset(_strings(raw.get("platforms"), "client.platforms")),
        )


@dataclass(frozen=True)
class Route:
    id: str
    name: str
    auth_mode: str
    base_url: str | None
    base_url_env: str | None
    token_env: str | None
    clients: frozenset[str]
    protocols: frozenset[str]
    capabilities: frozenset[str]
    evidence_command_env: str | None
    release_evidence_required: bool = True
    group: str | None = None
    channel_id: int | None = None
    pin_channel: bool = False
    evidence_provider: str | None = None
    test_model: str | None = None
    channel_type: int | None = None
    history_route: str | None = None
    history_model: str | None = None

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> Route:
        auth_mode = _required(raw, "auth_mode")
        if auth_mode not in {"gateway_token", "managed_session"}:
            raise ContractError(f"route.auth_mode invalid: {auth_mode}")
        token_env = raw.get("token_env")
        if auth_mode == "gateway_token" and not token_env:
            raise ContractError("gateway_token route requires token_env")
        if token_env and (not isinstance(token_env, str) or "sk-" in token_env.lower()):
            raise ContractError(
                "route.token_env must name an environment variable, not contain a token"
            )
        channel_id = (
            int(raw["channel_id"]) if raw.get("channel_id") is not None else None
        )
        pin_channel = bool(raw.get("pin_channel", False))
        if pin_channel and (channel_id is None or channel_id <= 0):
            raise ContractError("pinned route requires a positive channel_id")
        evidence_provider = raw.get("evidence_provider")
        if evidence_provider not in {None, "beefapi_token_log"}:
            raise ContractError(f"route.evidence_provider invalid: {evidence_provider}")
        capabilities = frozenset(
            _strings(raw.get("capabilities"), "route.capabilities")
        )
        history_route = raw.get("history_route")
        history_model = raw.get("history_model")
        if "cross_route_history" in capabilities and not history_route:
            raise ContractError(
                "route.cross_route_history capability requires history_route"
            )
        if "cross_model_history" in capabilities and not history_model:
            raise ContractError(
                "route.cross_model_history capability requires history_model"
            )
        return cls(
            id=_required(raw, "id"),
            name=_required(raw, "name"),
            auth_mode=auth_mode,
            base_url=raw.get("base_url"),
            base_url_env=raw.get("base_url_env"),
            token_env=token_env,
            clients=frozenset(_strings(raw.get("clients"), "route.clients")),
            protocols=frozenset(_strings(raw.get("protocols"), "route.protocols")),
            capabilities=capabilities,
            evidence_command_env=raw.get("evidence_command_env"),
            release_evidence_required=bool(raw.get("release_evidence_required", True)),
            group=raw.get("group"),
            channel_id=channel_id,
            pin_channel=pin_channel,
            evidence_provider=evidence_provider,
            test_model=raw.get("test_model"),
            channel_type=(
                int(raw["channel_type"])
                if raw.get("channel_type") is not None
                else None
            ),
            history_route=history_route,
            history_model=history_model,
        )


@dataclass(frozen=True)
class Model:
    id: str
    name: str
    routes: frozenset[str]
    clients: frozenset[str]
    capabilities: frozenset[str]
    aliases: dict[str, str]

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> Model:
        aliases = raw.get("aliases", {})
        if not isinstance(aliases, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in aliases.items()
        ):
            raise ContractError("model.aliases must be a string map")
        return cls(
            id=_required(raw, "id"),
            name=_required(raw, "name"),
            routes=frozenset(_strings(raw.get("routes"), "model.routes")),
            clients=frozenset(_strings(raw.get("clients"), "model.clients")),
            capabilities=frozenset(
                _strings(raw.get("capabilities"), "model.capabilities")
            ),
            aliases=aliases,
        )

    def client_model(self, client_id: str) -> str:
        return self.aliases.get(client_id, self.id)


@dataclass(frozen=True)
class Turn:
    prompt: str
    marker: str
    expected_events: tuple[str, ...]
    expected_any_events: tuple[tuple[str, ...], ...] = ()

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> Turn:
        events = raw.get("expected_events", [])
        if not isinstance(events, list) or not all(
            isinstance(item, str) for item in events
        ):
            raise ContractError("turn.expected_events must be a string array")
        any_events = raw.get("expected_any_events", [])
        if not isinstance(any_events, list) or not all(
            isinstance(group, list)
            and group
            and all(isinstance(item, str) for item in group)
            for group in any_events
        ):
            raise ContractError(
                "turn.expected_any_events must be an array of string arrays"
            )
        marker = raw.get("marker", "")
        if not isinstance(marker, str):
            raise ContractError("turn.marker must be a string")
        if not marker and not events and not any_events:
            raise ContractError("turn needs a marker or expected events")
        return cls(
            _required(raw, "prompt"),
            marker,
            tuple(events),
            tuple(tuple(group) for group in any_events),
        )


WIRE_EXPECTATIONS = {"multi_request", "web_search_requested"}
HISTORY_SOURCE_KEYS = {"route", "model", "seed_prompt", "thinking", "mode"}
HISTORY_MODES = {"replay", "previous_response_id"}


@dataclass(frozen=True)
class HistorySource:
    """Phase one of a two-phase HTTP scenario: obtain a real response from a
    (possibly different) route/model and feed it back as conversation history.
    This reproduces what a client does when the user switches routing groups
    or models mid-session."""

    seed_prompt: str
    route: str | None = None
    model: str | None = None
    thinking: bool = False
    mode: str = "replay"

    @classmethod
    def parse(cls, raw: Any, protocol: str | None) -> HistorySource:
        if not isinstance(raw, dict) or not set(raw) <= HISTORY_SOURCE_KEYS:
            raise ContractError(
                f"scenario.history_source keys must be in {sorted(HISTORY_SOURCE_KEYS)}"
            )
        mode = str(raw.get("mode", "replay"))
        if mode not in HISTORY_MODES:
            raise ContractError(
                f"history_source.mode must be in {sorted(HISTORY_MODES)}"
            )
        if mode == "previous_response_id" and protocol != "responses":
            raise ContractError(
                "previous_response_id mode requires the responses protocol"
            )
        if protocol not in {"messages", "responses"}:
            raise ContractError("history_source supports messages and responses only")
        return cls(
            seed_prompt=_required(raw, "seed_prompt"),
            route=raw.get("route"),
            model=raw.get("model"),
            thinking=bool(raw.get("thinking", False)),
            mode=mode,
        )


@dataclass(frozen=True)
class Scenario:
    id: str
    name: str
    tier: str
    kind: str
    protocol: str | None
    required_capabilities: frozenset[str]
    timeout_seconds: int
    requires_local_tools: bool
    turns: tuple[Turn, ...]
    http_endpoint: str | None = None
    http_payload: dict[str, Any] | None = None
    stream: bool = False
    expect_wire: tuple[str, ...] = ()
    concurrency: int = 1
    max_slowdown: float | None = None
    history_source: HistorySource | None = None

    @classmethod
    def parse(cls, raw: dict[str, Any]) -> Scenario:
        tier = _required(raw, "tier")
        if tier not in TIERS:
            raise ContractError(f"scenario.tier invalid: {tier}")
        kind = _required(raw, "kind")
        if kind not in {"client", "http"}:
            raise ContractError(f"scenario.kind invalid: {kind}")
        turns_raw = raw.get("turns")
        if not isinstance(turns_raw, list) or not turns_raw:
            raise ContractError("scenario.turns must be a non-empty array")
        endpoint = raw.get("http_endpoint")
        if kind == "http" and (
            not isinstance(endpoint, str) or not endpoint.startswith("/")
        ):
            raise ContractError("http scenario requires an absolute http_endpoint path")
        http_payload = raw.get("http_payload")
        if http_payload is not None and (
            kind != "http" or not isinstance(http_payload, dict)
        ):
            raise ContractError(
                "scenario.http_payload must be an object on an HTTP scenario"
            )
        if http_payload is not None:
            _validate_http_payload_credentials(http_payload)
        stream = bool(raw.get("stream", False))
        if stream and kind != "http":
            raise ContractError("scenario.stream applies only to HTTP scenarios")
        expect_wire = raw.get("expect_wire", [])
        if not isinstance(expect_wire, list) or not set(expect_wire) <= (
            WIRE_EXPECTATIONS
        ):
            raise ContractError(
                f"scenario.expect_wire entries must be in {sorted(WIRE_EXPECTATIONS)}"
            )
        if expect_wire and kind != "client":
            raise ContractError("scenario.expect_wire applies only to client scenarios")
        concurrency = int(raw.get("concurrency", 1))
        if concurrency < 1:
            raise ContractError("scenario.concurrency must be >= 1")
        if concurrency > 1:
            if len(turns_raw) != 1:
                raise ContractError("concurrent scenarios must have exactly one turn")
            if "{{nonce}}" not in str(turns_raw[0].get("prompt", "")):
                raise ContractError(
                    "concurrent scenario prompt must embed {{nonce}} so "
                    "cross-request leakage is detectable"
                )
        max_slowdown = raw.get("max_slowdown")
        if max_slowdown is not None:
            max_slowdown = float(max_slowdown)
            if max_slowdown <= 1 or concurrency == 1:
                raise ContractError(
                    "scenario.max_slowdown must be > 1 on a concurrent scenario"
                )
        history_source = None
        if raw.get("history_source") is not None:
            if kind != "http" or concurrency != 1:
                raise ContractError(
                    "scenario.history_source requires a single-user HTTP scenario"
                )
            history_source = HistorySource.parse(
                raw["history_source"], raw.get("protocol")
            )
        return cls(
            id=_required(raw, "id"),
            name=_required(raw, "name"),
            tier=tier,
            kind=kind,
            protocol=raw.get("protocol"),
            required_capabilities=frozenset(
                _strings(
                    raw.get("required_capabilities"), "scenario.required_capabilities"
                )
            ),
            timeout_seconds=int(raw.get("timeout_seconds", 180)),
            requires_local_tools=bool(raw.get("requires_local_tools", False)),
            turns=tuple(Turn.parse(item) for item in turns_raw),
            http_endpoint=endpoint,
            http_payload=http_payload,
            stream=stream,
            expect_wire=tuple(expect_wire),
            concurrency=concurrency,
            max_slowdown=max_slowdown,
            history_source=history_source,
        )


@dataclass(frozen=True)
class MatrixCell:
    client: Client
    route: Route
    model: Model
    scenario: Scenario

    @property
    def id(self) -> str:
        return f"{self.client.id}/{self.route.id}/{self.model.id}/{self.scenario.id}"


@dataclass
class TurnResult:
    index: int
    status: str
    duration_ms: int
    returncode: int | None
    marker: str
    missing_events: list[str]
    output_tail: str


@dataclass
class CellResult:
    cell_id: str
    status: str
    client_version: str | None
    started_at: str
    duration_ms: int
    route_id: str
    model_id: str
    scenario_id: str
    turns: list[TurnResult]
    evidence: dict[str, Any] = field(default_factory=dict)
    detail: str = ""


def unique_ids(items: list[Any], source: Path) -> None:
    ids = [item.id for item in items]
    duplicates = sorted({item for item in ids if ids.count(item) > 1})
    if duplicates:
        raise ContractError(f"duplicate ids in {source}: {', '.join(duplicates)}")
