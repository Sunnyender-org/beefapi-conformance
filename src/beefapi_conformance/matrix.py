from __future__ import annotations

from .manifest import Inventory
from .model import TIERS, MatrixCell


def compile_matrix(
    inventory: Inventory,
    tier: str,
    clients: set[str] | None = None,
    routes: set[str] | None = None,
    models: set[str] | None = None,
    scenarios: set[str] | None = None,
) -> list[MatrixCell]:
    if tier not in TIERS:
        raise ValueError(f"unknown tier: {tier}")
    cells: list[MatrixCell] = []
    for client in inventory.clients:
        if clients and client.id not in clients:
            continue
        for route in inventory.routes:
            if routes and route.id not in routes:
                continue
            if client.id not in route.clients:
                continue
            for model in inventory.models:
                if models and model.id not in models:
                    continue
                if route.id not in model.routes or client.id not in model.clients:
                    continue
                capabilities = (
                    client.capabilities & route.capabilities & model.capabilities
                )
                for scenario in inventory.scenarios:
                    if scenarios and scenario.id not in scenarios:
                        continue
                    if TIERS[scenario.tier] > TIERS[tier]:
                        continue
                    if scenario.kind == "http" and client.adapter != "raw-http":
                        continue
                    if scenario.kind == "client" and client.adapter == "raw-http":
                        continue
                    if scenario.protocol and scenario.protocol not in route.protocols:
                        continue
                    if not scenario.required_capabilities.issubset(capabilities):
                        continue
                    cells.append(MatrixCell(client, route, model, scenario))
    return sorted(cells, key=lambda item: item.id)
