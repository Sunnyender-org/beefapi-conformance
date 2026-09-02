from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from pathlib import Path

from .clients import resolve_binary
from .inventory import sync_live_inventory
from .manifest import load_inventory
from .matrix import compile_matrix
from .model import ContractError
from .report import build_report, write_report
from .runner import run_cell

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
    errors: list[str] = []
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
    routes = {route.id: route for route in _inventory(args).routes}
    capture_dir = Path(args.capture_wire) if args.capture_wire else None
    for cell in cells:
        print(f"RUN {cell.id}", file=sys.stderr)
        result = run_cell(
            cell,
            allow_local_tools=args.allow_local_tools,
            require_server_evidence=require_server_evidence,
            routes=routes,
            capture_dir=capture_dir,
        )
        results.append(result)
        print(
            f"{result.status.upper()} {cell.id} {result.duration_ms}ms", file=sys.stderr
        )
        if args.fail_fast and result.status == "fail":
            break
    report = build_report(results)
    write_report(report, Path(args.output))
    print(json.dumps(report["summary"], indent=2))
    return 0 if report["classification"] == "passed" else 1


def command_promote_capture(args: argparse.Namespace) -> int:
    """Turn the last completion request of a wire capture into a replayable
    HTTP scenario: model and final user text become template placeholders,
    everything else (system, tools, cache_control, history) is kept verbatim."""
    exchanges = [
        json.loads(line)
        for line in Path(args.capture).read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    completions = [
        item
        for item in exchanges
        if isinstance(item.get("request_body"), dict)
        and item["path"].split("?", 1)[0].endswith(("/messages", "/responses"))
    ]
    if not completions:
        raise ContractError("capture has no completion request with a body")
    exchange = completions[args.index]
    body = exchange["request_body"]
    protocol = (
        "messages"
        if exchange["path"].split("?", 1)[0].endswith("/messages")
        else "responses"
    )
    body["model"] = "{{model}}"
    body.pop("stream", None)
    turns = body.get("messages") if protocol == "messages" else body.get("input")
    if isinstance(turns, list) and turns:
        last = turns[-1]
        content = last.get("content") if isinstance(last, dict) else None
        plain_text = isinstance(content, str) or (
            isinstance(content, list)
            and all(
                isinstance(b, dict) and b.get("type") in {"text", "input_text"}
                for b in content
            )
        )
        # A trailing tool_result/function_call_output must stay paired with
        # its call; only a plain-text user turn can become the prompt slot.
        if isinstance(last, dict) and last.get("role") == "user" and plain_text:
            last["content"] = "{{prompt}}"
        else:
            turns.append({"role": "user", "content": "{{prompt}}"})
    scenario = {
        "id": args.id,
        "name": f"Captured {protocol} request shape replayed ({Path(args.capture).stem})",
        "tier": args.tier,
        "kind": "http",
        "protocol": protocol,
        "http_endpoint": "/v1/" + protocol,
        "stream": True,
        "required_capabilities": [protocol, "stream"],
        "timeout_seconds": 180,
        "requires_local_tools": False,
        "http_payload": body,
        "turns": [
            {
                "prompt": f"Reply exactly {args.marker}.",
                "marker": args.marker,
                "expected_events": [],
            }
        ],
    }
    print(json.dumps({"scenarios": [scenario]}, ensure_ascii=False, indent=2))
    return 0


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
    promote = sub.add_parser("promote-capture")
    promote.add_argument("capture", help="JSONL written by run --capture-wire")
    promote.add_argument("--id", required=True)
    promote.add_argument("--marker", default="BEEFAPI_CAPTURED_SHAPE_OK")
    promote.add_argument("--tier", choices=("pr", "merge", "nightly"), default="pr")
    promote.add_argument(
        "--index", type=int, default=-1, help="which completion request (default last)"
    )
    promote.set_defaults(func=command_promote_capture)
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
            command.add_argument(
                "--capture-wire",
                metavar="DIR",
                help="write full redacted request/response bodies of native "
                "client cells as JSONL fixtures into DIR",
            )
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
