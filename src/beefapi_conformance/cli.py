from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from pathlib import Path

from .clients import resolve_binary
from .harbor import harbor_binary, validate_harbor_tasks
from .inventory import sync_live_inventory
from .manifest import load_inventory
from .matrix import compile_matrix
from .model import ContractError
from .report import build_report, write_report
from .runner import (
    finalize_batch_server_evidence,
    prepare_batch_server_evidence,
    run_cell,
)

ROOT = Path(__file__).resolve().parents[2]


def _inventory(args: argparse.Namespace):
    return load_inventory(ROOT, Path(args.routes), Path(args.models))


def _matrix(args: argparse.Namespace):
    inventory = _inventory(args)
    requested = {
        "client": (set(args.client or []), {item.id for item in inventory.clients}),
        "route": (set(args.route or []), {item.id for item in inventory.routes}),
        "model": (set(args.model or []), {item.id for item in inventory.models}),
        "scenario": (
            set(args.scenario or []),
            {item.id for item in inventory.scenarios},
        ),
    }
    for label, (selected, available) in requested.items():
        unknown = selected - available
        if unknown:
            raise ContractError(f"unknown {label} filter: {', '.join(sorted(unknown))}")
    return compile_matrix(
        inventory,
        args.tier,
        set(args.client or []) or None,
        set(args.route or []) or None,
        set(args.model or []) or None,
        set(args.scenario or []) or None,
        args.coverage,
    )


def command_validate(args: argparse.Namespace) -> int:
    inventory = _inventory(args)
    errors = validate_harbor_tasks(ROOT)
    release_cells = compile_matrix(inventory, "release")
    covered_clients = {cell.client.id for cell in release_cells}
    missing_clients = sorted({item.id for item in inventory.clients} - covered_clients)
    if missing_clients:
        errors.append(f"clients without release cells: {', '.join(missing_clients)}")
    payload = {
        "ok": not errors,
        "counts": {
            "clients": len(inventory.clients),
            "routes": len(inventory.routes),
            "models": len(inventory.models),
            "scenarios": len(inventory.scenarios),
        },
        "errors": errors,
    }
    print(json.dumps(payload, indent=2))
    return 0 if payload["ok"] else 1


def command_doctor(args: argparse.Namespace) -> int:
    inventory = _inventory(args)
    payload = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "clients": [
            {
                "id": item.id,
                "available": (binary := resolve_binary(item)) is not None,
                "binary": binary,
            }
            for item in inventory.clients
        ],
        "harbor": harbor_binary(),
        "route_secrets": {
            route.id: bool(os.environ.get(route.token_env or ""))
            if route.token_env
            else "managed_session"
            for route in inventory.routes
        },
    }
    print(json.dumps(payload, indent=2))
    return 0


def command_plan(args: argparse.Namespace) -> int:
    payload = [
        {
            "id": cell.id,
            "client": cell.client.id,
            "route": cell.route.id,
            "model": cell.model.id,
            "scenario": cell.scenario.id,
            "tier": cell.scenario.tier,
        }
        for cell in _matrix(args)
    ]
    if args.json:
        print(json.dumps({"count": len(payload), "cells": payload}, indent=2))
    else:
        print(f"cells={len(payload)}")
        for cell in payload:
            print(cell["id"])
    return 0


def command_run(args: argparse.Namespace) -> int:
    results = []
    cells = _matrix(args)
    if not cells:
        raise ContractError("filters produced zero compatible matrix cells")
    if len(cells) > args.max_cells:
        raise ContractError(
            f"matrix has {len(cells)} cells, exceeding --max-cells={args.max_cells}"
        )
    require_server_evidence = args.require_server_evidence or args.tier in {
        "nightly",
        "release",
    }
    batch_evidence = (
        prepare_batch_server_evidence(cells) if require_server_evidence else {}
    )
    for cell in cells:
        print(f"RUN {cell.id}", file=sys.stderr)
        result = run_cell(
            cell,
            allow_local_tools=args.allow_local_tools,
            require_server_evidence=require_server_evidence,
            defer_server_evidence=bool(batch_evidence),
        )
        results.append(result)
        print(
            f"{result.status.upper()} {cell.id} {result.duration_ms}ms", file=sys.stderr
        )
        if args.fail_fast and result.status == "fail":
            break
    if batch_evidence:
        finalize_batch_server_evidence(cells[: len(results)], results, batch_evidence)
    report = build_report(results)
    write_report(report, Path(args.output))
    print(json.dumps(report["summary"], indent=2))
    return 0 if report["classification"] == "passed" else 1


def command_sync_inventory(args: argparse.Namespace) -> int:
    channels_json = args.channels_json
    if args.channels_json_env:
        channels_json = os.environ.get(args.channels_json_env, "")
    routes_path, models_path = sync_live_inventory(
        channels_json=channels_json,
        base_url=args.base_url,
        token_env=args.token_env,
        group=args.group,
        output_dir=Path(args.output),
    )
    inventory = load_inventory(ROOT, routes_path, models_path)
    print(
        json.dumps(
            {
                "routes": len(inventory.routes),
                "models": len(inventory.models),
                "routes_path": str(routes_path),
                "models_path": str(models_path),
            },
            indent=2,
        )
    )
    return 0


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(prog="beefapi-conformance")
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--routes", default=str(ROOT / "manifests/routes.example.json"))
    common.add_argument("--models", default=str(ROOT / "manifests/models.example.json"))
    sub = result.add_subparsers(dest="command", required=True)
    validate = sub.add_parser("validate", parents=[common])
    validate.set_defaults(func=command_validate)
    doctor = sub.add_parser("doctor", parents=[common])
    doctor.set_defaults(func=command_doctor)
    sync = sub.add_parser("sync-inventory")
    sync.add_argument("--base-url", default="https://beefapi.com")
    sync.add_argument("--token-env", default="BEEFAPI_CONFORMANCE_TOKEN")
    sync.add_argument("--group", default="cursor-acceptance")
    sync.add_argument("--channels-json", default="")
    sync.add_argument("--channels-json-env")
    sync.add_argument("--output", default=str(ROOT / ".tmp/live-inventory"))
    sync.set_defaults(func=command_sync_inventory)
    for name, func in (("plan", command_plan), ("run", command_run)):
        command = sub.add_parser(name, parents=[common])
        command.add_argument(
            "--tier", choices=("pr", "merge", "nightly", "release"), default="pr"
        )
        command.add_argument("--client", action="append")
        command.add_argument("--route", action="append")
        command.add_argument("--model", action="append")
        command.add_argument("--scenario", action="append")
        command.add_argument(
            "--coverage", choices=("full", "representative"), default="full"
        )
        if name == "plan":
            command.add_argument("--json", action="store_true")
        else:
            command.add_argument("--output", default=str(ROOT / "reports/latest"))
            command.add_argument("--allow-local-tools", action="store_true")
            command.add_argument("--require-server-evidence", action="store_true")
            command.add_argument("--max-cells", type=int, default=100)
            command.add_argument("--fail-fast", action="store_true")
        command.set_defaults(func=func)
    return result


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        return int(args.func(args))
    except ContractError as exc:
        print(f"contract error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
