from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path
from typing import Any

from .model import ContractError

CURSOR_CLIENTS = ["raw-http", "claude-code", "codex-cli", "grok-build"]
CURSOR_PROTOCOLS = ["responses", "messages", "chat"]
CURSOR_CAPABILITIES = [
    "text",
    "stream",
    "tool.shell",
    "tool.custom",
    "tool.web",
    "session.resume",
    "responses",
    "messages",
    "chat",
    "compact",
    "images",
]


def fetch_model_ids(base_url: str, token: str, timeout: int = 30) -> set[str]:
    request = urllib.request.Request(
        base_url.rstrip("/") + "/v1/models",
        headers={"authorization": f"Bearer {token}"},
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        body = json.loads(response.read())
    data = body.get("data", []) if isinstance(body, dict) else []
    return {
        item["id"]
        for item in data
        if isinstance(item, dict) and isinstance(item.get("id"), str)
    }


def build_live_inventory(
    channels: list[dict[str, Any]],
    public_models: set[str],
    base_url: str,
    token_env: str,
    group: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    routes: list[dict[str, Any]] = []
    model_routes: dict[str, list[str]] = {}
    for channel in channels:
        if int(channel.get("status", 0)) != 1 or int(channel.get("type", 0)) != 62:
            continue
        channel_id = int(channel.get("id", 0))
        if channel_id <= 0:
            continue
        route_id = f"cursor-channel-{channel_id}"
        model_ids = [
            item.strip()
            for item in str(channel.get("models", "")).split(",")
            if item.strip() and item.strip() in public_models
        ]
        if not model_ids:
            continue
        configured_test_model = str(channel.get("test_model") or "").strip()
        if configured_test_model and configured_test_model not in model_ids:
            raise ContractError(
                f"channel {channel_id} test_model {configured_test_model!r} "
                "is not in its public model inventory"
            )
        test_model = configured_test_model or model_ids[0]
        routes.append(
            {
                "id": route_id,
                "name": f"Cursor Native channel {channel_id}",
                "auth_mode": "gateway_token",
                "base_url": base_url.rstrip("/"),
                "token_env": token_env,
                "group": group,
                "channel_id": channel_id,
                "pin_channel": True,
                "test_model": test_model,
                "evidence_provider": "beefapi_token_log",
                "release_evidence_required": True,
                "clients": CURSOR_CLIENTS,
                "protocols": CURSOR_PROTOCOLS,
                "capabilities": CURSOR_CAPABILITIES,
            }
        )
        for model_id in model_ids:
            model_routes.setdefault(model_id, []).append(route_id)
    if not routes:
        raise ContractError("production snapshot produced no active Cursor routes")
    models = [
        {
            "id": model_id,
            "name": model_id,
            "routes": sorted(route_ids),
            "clients": CURSOR_CLIENTS,
            "capabilities": CURSOR_CAPABILITIES,
            "aliases": {},
        }
        for model_id, route_ids in sorted(model_routes.items())
    ]
    return {"routes": routes}, {"models": models}


def sync_live_inventory(
    channels_json: str,
    base_url: str,
    token_env: str,
    group: str,
    output_dir: Path,
) -> tuple[Path, Path]:
    token = os.environ.get(token_env, "")
    if not token:
        raise ContractError(f"missing {token_env}")
    try:
        channels = json.loads(channels_json)
    except json.JSONDecodeError as exc:
        raise ContractError(f"invalid channel snapshot: {exc}") from exc
    if not isinstance(channels, list) or not all(
        isinstance(item, dict) for item in channels
    ):
        raise ContractError("channel snapshot must be a JSON object array")
    public_models = fetch_model_ids(base_url, token)
    routes, models = build_live_inventory(
        channels, public_models, base_url, token_env, group
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    routes_path = output_dir / "routes.live.json"
    models_path = output_dir / "models.live.json"
    routes_path.write_text(json.dumps(routes, ensure_ascii=False, indent=2) + "\n")
    models_path.write_text(json.dumps(models, ensure_ascii=False, indent=2) + "\n")
    return routes_path, models_path
