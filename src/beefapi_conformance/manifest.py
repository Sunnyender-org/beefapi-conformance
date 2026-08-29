from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, TypeVar

from .cursor_agent_v1 import validate_completion_references
from .model import Client, ContractError, Model, Route, Scenario, unique_ids

T = TypeVar("T")


@dataclass(frozen=True)
class Inventory:
    clients: list[Client]
    routes: list[Route]
    models: list[Model]
    scenarios: list[Scenario]


def _load(
    path: Path, collection: str, parser: Callable[[dict[str, Any]], T]
) -> list[T]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ContractError(f"cannot read {path}: {exc}") from exc
    values = raw.get(collection) if isinstance(raw, dict) else None
    if not isinstance(values, list):
        raise ContractError(f"{path} must contain array {collection!r}")
    parsed = [parser(item) for item in values if isinstance(item, dict)]
    if len(parsed) != len(values):
        raise ContractError(f"{path} contains a non-object {collection} entry")
    unique_ids(parsed, path)
    return parsed


def load_inventory(root: Path, routes_path: Path, models_path: Path) -> Inventory:
    scenarios: list[Scenario] = []
    scenarios_dir = root / "scenarios"
    for path in sorted(scenarios_dir.glob("*.json")):
        scenarios.extend(_load(path, "scenarios", Scenario.parse))
    unique_ids(scenarios, scenarios_dir)
    validate_completion_references({item.id for item in scenarios})
    inventory = Inventory(
        clients=_load(root / "manifests/clients.json", "clients", Client.parse),
        routes=_load(routes_path, "routes", Route.parse),
        models=_load(models_path, "models", Model.parse),
        scenarios=scenarios,
    )
    validate_references(inventory)
    return inventory


def validate_references(inventory: Inventory) -> None:
    client_ids = {item.id for item in inventory.clients}
    route_ids = {item.id for item in inventory.routes}
    for route in inventory.routes:
        unknown = route.clients - client_ids
        if unknown:
            raise ContractError(
                f"route {route.id} references unknown clients: {sorted(unknown)}"
            )
    for model in inventory.models:
        unknown_routes = model.routes - route_ids
        unknown_clients = model.clients - client_ids
        if unknown_routes or unknown_clients:
            raise ContractError(
                f"model {model.id} references unknown routes={sorted(unknown_routes)} clients={sorted(unknown_clients)}"
            )
