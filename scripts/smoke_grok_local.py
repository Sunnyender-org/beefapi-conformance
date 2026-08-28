#!/usr/bin/env python3
"""Drive the installed Grok CLI through a local fake Responses stream."""

from __future__ import annotations

import http.server
import json
import os
import threading
from pathlib import Path

from beefapi_conformance.manifest import load_inventory
from beefapi_conformance.matrix import compile_matrix
from beefapi_conformance.model import MatrixCell, Route
from beefapi_conformance.runner import run_cell

MARKER = "BEEFAPI_CONFORMANCE_TEXT_OK"


class ResponsesHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        request = json.loads(self.rfile.read(length))
        usage = {
            "input_tokens": 1,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens": 1,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": 2,
        }
        response = {
            "id": "resp_local_grok",
            "object": "response",
            "created_at": 1787940000,
            "status": "completed",
            "model": request.get("model"),
            "output": [
                {
                    "id": "msg_local_grok",
                    "type": "message",
                    "status": "completed",
                    "role": "assistant",
                    "content": [
                        {"type": "output_text", "text": MARKER, "annotations": []}
                    ],
                }
            ],
            "usage": usage,
        }
        events = [
            {
                "type": "response.created",
                "response": {**response, "status": "in_progress", "output": []},
            },
            {
                "type": "response.output_item.added",
                "output_index": 0,
                "item": {
                    "id": "msg_local_grok",
                    "type": "message",
                    "status": "in_progress",
                    "role": "assistant",
                    "content": [],
                },
            },
            {
                "type": "response.content_part.added",
                "item_id": "msg_local_grok",
                "output_index": 0,
                "content_index": 0,
                "part": {"type": "output_text", "text": "", "annotations": []},
            },
            {
                "type": "response.output_text.delta",
                "item_id": "msg_local_grok",
                "output_index": 0,
                "content_index": 0,
                "delta": MARKER,
                "logprobs": [],
            },
            {
                "type": "response.output_text.done",
                "item_id": "msg_local_grok",
                "output_index": 0,
                "content_index": 0,
                "text": MARKER,
                "logprobs": [],
            },
            {
                "type": "response.content_part.done",
                "item_id": "msg_local_grok",
                "output_index": 0,
                "content_index": 0,
                "part": {
                    "type": "output_text",
                    "text": MARKER,
                    "annotations": [],
                },
            },
            {
                "type": "response.output_item.done",
                "output_index": 0,
                "item": response["output"][0],
            },
            {"type": "response.completed", "response": response},
        ]
        for sequence_number, event in enumerate(events):
            event["sequence_number"] = sequence_number
        body = "".join(
            f"data: {json.dumps(event, separators=(',', ':'))}\n\n" for event in events
        ).encode()
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_args: object) -> None:
        return


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    inventory = load_inventory(
        root,
        root / "manifests/routes.example.json",
        root / "manifests/models.example.json",
    )
    original = next(
        cell
        for cell in compile_matrix(inventory, "pr", clients={"grok-build"})
        if cell.scenario.id == "text-turn"
    )
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), ResponsesHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        route = Route(
            original.route.id,
            original.route.name,
            "gateway_token",
            f"http://127.0.0.1:{server.server_port}",
            None,
            "GROK_LOCAL_TEST_TOKEN",
            original.route.clients,
            original.route.protocols,
            original.route.capabilities,
            None,
            False,
        )
        os.environ["GROK_LOCAL_TEST_TOKEN"] = "local-only-token"
        result = run_cell(
            MatrixCell(original.client, route, original.model, original.scenario)
        )
        print(
            json.dumps(
                {
                    "status": result.status,
                    "client_version": result.client_version,
                    "duration_ms": result.duration_ms,
                    "turns": [
                        {
                            "status": turn.status,
                            "returncode": turn.returncode,
                            "missing_events": turn.missing_events,
                        }
                        for turn in result.turns
                    ],
                },
                indent=2,
            )
        )
        return 0 if result.status == "pass" else 1
    finally:
        os.environ.pop("GROK_LOCAL_TEST_TOKEN", None)
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
