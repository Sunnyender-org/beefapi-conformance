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
    coverage: str = "full",
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
    cells = sorted(cells, key=lambda item: item.id)
    if coverage == "full":
        return cells
    if coverage == "representative":
        return representative_matrix(cells)
    raise ValueError(f"unknown coverage: {coverage}")


def representative_matrix(cells: list[MatrixCell]) -> list[MatrixCell]:
    """Deterministic pairwise-like coverage without the full Cartesian cost."""
    if not cells:
        return []
    routes = sorted(
        {cell.route.id: cell.route for cell in cells}.values(), key=lambda item: item.id
    )
    models = sorted(
        {cell.model.id: cell.model for cell in cells}.values(), key=lambda item: item.id
    )
    native_clients = sorted(
        {
            cell.client.id: cell.client
            for cell in cells
            if cell.client.adapter != "raw-http"
        }.values(),
        key=lambda item: item.id,
    )
    route_index = {route.id: index for index, route in enumerate(routes)}
    model_index = {model.id: index for index, model in enumerate(models)}
    client_ids = [client.id for client in native_clients]
    deep_scenarios = [
        "tool-loop",
        "session-resume",
        "web-search",
        "long-stream",
        "concurrent-users",
    ]
    selected: dict[str, MatrixCell] = {}
    for cell in cells:
        scenario_id = cell.scenario.id
        if cell.client.adapter == "raw-http":
            if (
                scenario_id == "responses-stream"
                or cell.model.id == cell.route.test_model
            ):
                selected[cell.id] = cell
            continue
        if not client_ids:
            continue
        if scenario_id == "text-turn":
            assigned_client = client_ids[model_index[cell.model.id] % len(client_ids)]
            first_route = min(cell.model.routes)
            if cell.model.id == cell.route.test_model or (
                cell.route.id == first_route and cell.client.id == assigned_client
            ):
                selected[cell.id] = cell
            continue
        if scenario_id in deep_scenarios and cell.model.id == cell.route.test_model:
            scenario_index = deep_scenarios.index(scenario_id)
            assigned_client = client_ids[
                (route_index[cell.route.id] + scenario_index) % len(client_ids)
            ]
            if cell.client.id == assigned_client:
                selected[cell.id] = cell
    return sorted(selected.values(), key=lambda item: item.id)
