#!/usr/bin/env python3
"""Probe a real Claude Code WebSearch wrapper against a deterministic local API.

No upstream/model call is made. This proves client request shape and tool-result
round-trip, NOT real search, production readiness, or interactive TUI rendering.
"""

from __future__ import annotations

import argparse
import base64
import http.server
import json
import os
import subprocess
import tempfile
import threading
from pathlib import Path
from typing import ClassVar

QUERY = "beefapi deterministic search fixture"
MARKER = "CLAUDE_SEARCH_CHILD_FIXTURE_OK"


def stream(message: dict) -> bytes:
    events = [
        {
            "type": "message_start",
            "message": {**message, "content": [], "stop_reason": None},
        }
    ]
    for index, block in enumerate(message["content"]):
        start = dict(block)
        delta = None
        if block["type"] in ("tool_use", "server_tool_use"):
            start["input"] = {}
            delta = {
                "type": "input_json_delta",
                "partial_json": json.dumps(block["input"]),
            }
        elif block["type"] == "text":
            start["text"] = ""
            delta = {"type": "text_delta", "text": block["text"]}
        events.append(
            {"type": "content_block_start", "index": index, "content_block": start}
        )
        if delta:
            events.append(
                {"type": "content_block_delta", "index": index, "delta": delta}
            )
        events.append({"type": "content_block_stop", "index": index})
    events += [
        {
            "type": "message_delta",
            "delta": {"stop_reason": message["stop_reason"], "stop_sequence": None},
            "usage": {"output_tokens": 1},
        },
        {"type": "message_stop"},
    ]
    return "".join(
        f"event: {event['type']}\ndata: {json.dumps(event)}\n\n" for event in events
    ).encode()


class SearchFixture(http.server.BaseHTTPRequestHandler):
    records: ClassVar[list[dict]] = []
    child_mode: ClassVar[str] = "success"

    def log_message(self, *_args):
        pass

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers.get("content-length", 0))))
        if self.path.split("?")[0].endswith("/count_tokens"):
            return self.reply({"input_tokens": 1})
        tools = body.get("tools", [])
        child = any(t.get("type") == "web_search_20250305" for t in tools)
        messages = body.get("messages", [])
        results = [
            b
            for m in messages
            if isinstance(m.get("content"), list)
            for b in m["content"]
            if b.get("type") == "tool_result"
        ]
        record = {
            "kind": "child" if child else "main",
            "model": body.get("model"),
            "tool_names": [t.get("name") for t in tools],
            "tool_result_ids": [r.get("tool_use_id") for r in results],
            "result_is_error": any(r.get("is_error") for r in results),
        }
        if child:
            # Only this synthetic fixture's request is retained, never headers.
            record["request"] = {
                k: body[k]
                for k in (
                    "model",
                    "system",
                    "tools",
                    "tool_choice",
                    "thinking",
                    "messages",
                )
                if k in body
            }
            if self.child_mode == "http-error":
                self.records.append(record)
                return self.reply(
                    {
                        "type": "error",
                        "error": {
                            "type": "invalid_request_error",
                            "message": "fixture-search-error",
                        },
                    },
                    status=400,
                )
            content = [
                {
                    "type": "server_tool_use",
                    "id": "srvtoolu_fixture",
                    "name": "web_search",
                    "input": {"query": QUERY},
                },
                {
                    "type": "web_search_tool_result",
                    "tool_use_id": "srvtoolu_fixture",
                    "content": [
                        {
                            "type": "web_search_result",
                            "url": "https://example.com/",
                            "title": "Deterministic fixture",
                            "encrypted_content": "fixture-only",
                            "page_age": None,
                        }
                    ],
                },
                {
                    "type": "text",
                    "text": "Deterministic fixture result https://example.com/",
                },
            ]
            if self.child_mode == "empty":
                content[1]["content"] = []
                content[2]["text"] = "No search results were found."
            stop = "end_turn"
        elif results:
            record["result_contains_fixture"] = "example.com" in json.dumps(results)
            content = [{"type": "text", "text": MARKER}]
            stop = "end_turn"
        else:
            content = [
                {
                    "type": "tool_use",
                    "id": "toolu_fixture",
                    "name": "WebSearch",
                    "input": {"query": QUERY},
                }
            ]
            stop = "tool_use"
        self.records.append(record)
        if len(self.records) > 8:
            return self.send_error(429, "Fixture request limit")
        message = {
            "id": f"msg_fixture_{len(self.records)}",
            "type": "message",
            "role": "assistant",
            "model": body.get("model"),
            "content": content,
            "stop_reason": stop,
            "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 1},
        }
        self.reply(message, body.get("stream", False))

    def reply(self, message, streaming=False, status=200):
        data = stream(message) if streaming else json.dumps(message).encode()
        self.send_response(status)
        self.send_header(
            "content-type", "text/event-stream" if streaming else "application/json"
        )
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--claude", default="claude")
    parser.add_argument("--ssh-target", help="Optional authorized Windows SSH target")
    parser.add_argument("--identity", help="SSH identity file path (not contents)")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--child-mode", choices=("success", "empty", "http-error"), default="success"
    )
    args = parser.parse_args()
    SearchFixture.records = []
    SearchFixture.child_mode = args.child_mode
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), SearchFixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    cli_args = [
        "--print",
        "--output-format",
        "stream-json",
        "--verbose",
        "--model",
        "claude-opus-5",
        "--permission-mode",
        "bypassPermissions",
        "--strict-mcp-config",
        "--no-chrome",
        "--disable-slash-commands",
        "--setting-sources",
        "project",
        "--max-turns",
        "3",
        "Search the web for the deterministic fixture. Do not read or modify local files.",
    ]
    try:
        if args.ssh_target:
            # Quoted data only; the real credential never enters this harness.
            quote = lambda s: "'" + s.replace("'", "''") + "'"
            ps = (
                """$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false)
$root=Join-Path $env:TEMP ('claude-search-fixture-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $root | Out-Null
New-Item -ItemType Directory -Path (Join-Path $root 'workspace') | Out-Null
$env:CLAUDE_CONFIG_DIR=Join-Path $root 'config'
$env:ANTHROPIC_BASE_URL='http://127.0.0.1:19432'
$env:ANTHROPIC_AUTH_TOKEN='local-fixture-not-a-key'
Remove-Item Env:ANTHROPIC_API_KEY -ErrorAction SilentlyContinue
Remove-Item Env:ANTHROPIC_DEFAULT_HAIKU_MODEL -ErrorAction SilentlyContinue
$env:CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC='1'
Push-Location (Join-Path $root 'workspace')
try {
"""
                + "& "
                + quote(args.claude)
                + " "
                + " ".join(map(quote, cli_args))
                + "\n$code=$LASTEXITCODE\n"
                + """} finally {
Pop-Location
[Environment]::CurrentDirectory=$env:TEMP
Write-Output ('FIXTURE_ROOT='+$root)
}
exit $code
"""
            )
            bootstrap = "[Console]::InputEncoding=[System.Text.UTF8Encoding]::new($false); & ([scriptblock]::Create([Console]::In.ReadToEnd()))"
            cmd = [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "IdentitiesOnly=yes",
                "-o",
                "ConnectTimeout=8",
                "-o",
                "ExitOnForwardFailure=yes",
            ]
            if args.identity:
                cmd += ["-i", args.identity]
            cmd += [
                "-R",
                f"127.0.0.1:19432:127.0.0.1:{server.server_port}",
                args.ssh_target,
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                base64.b64encode(bootstrap.encode("utf-16le")).decode(),
            ]
            result = subprocess.run(
                cmd, input=ps.encode(), capture_output=True, timeout=150, check=False
            )
            roots = [
                line.removeprefix("FIXTURE_ROOT=").strip()
                for line in result.stdout.decode(errors="replace").splitlines()
                if line.startswith("FIXTURE_ROOT=")
            ]
            assert len(roots) == 1, "Missing owned fixture cleanup identity"
            import re

            assert re.fullmatch(
                r"[A-Za-z]:\\[^\r\n']+\\claude-search-fixture-[a-f0-9]{32}", roots[0]
            )
            # A second SSH process releases the first PowerShell process's native
            # working-directory handle before removing only this owned fixture.
            cleanup = (
                "$ErrorActionPreference='Stop'; $p="
                + quote(roots[0])
                + "; cmd.exe /d /c ('rd /s /q \"\\\\?\\'+$p+'\"'); if(Test-Path -LiteralPath $p){throw 'Fixture cleanup failed'}"
            )
            cleanup_cmd = cmd[: cmd.index("-R")] + [
                args.ssh_target,
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                base64.b64encode(cleanup.encode("utf-16le")).decode(),
            ]
            cleaned = subprocess.run(
                cleanup_cmd, capture_output=True, timeout=30, check=False
            )
            assert cleaned.returncode == 0, "Owned Windows fixture cleanup failed"
        else:
            with tempfile.TemporaryDirectory(prefix="claude-search-fixture-") as root:
                env = {
                    k: v
                    for k, v in os.environ.items()
                    if not k.startswith(("ANTHROPIC_", "CLAUDE_", "CLAUDECODE"))
                }
                env.update(
                    CLAUDE_CONFIG_DIR=root + "/config",
                    ANTHROPIC_BASE_URL=f"http://127.0.0.1:{server.server_port}",
                    ANTHROPIC_AUTH_TOKEN="local-fixture-not-a-key",
                    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1",
                )
                result = subprocess.run(
                    [args.claude, *cli_args],
                    cwd=root,
                    env=env,
                    capture_output=True,
                    timeout=150,
                    check=False,
                )
        children = [r for r in SearchFixture.records if r["kind"] == "child"]
        resumes = [
            r
            for r in SearchFixture.records
            if r.get("kind") == "main"
            and "toolu_fixture" in r.get("tool_result_ids", [])
        ]
        valid_result = any(parent_result_matches(args.child_mode, r) for r in resumes)
        evidence = {
            "scope": "deterministic-client-only-not-live-search-or-TUI",
            "client_exit": result.returncode,
            "child_mode": args.child_mode,
            "requests": SearchFixture.records,
            "child_observed": bool(children),
            "main_resume_observed": bool(resumes),
            "parent_result_valid": valid_result,
            "terminal_marker": MARKER in result.stdout.decode(errors="replace"),
        }
        args.output.write_text(
            json.dumps(evidence, ensure_ascii=False, indent=2) + "\n"
        )
        print(json.dumps({k: v for k, v in evidence.items() if k != "requests"}))
        assert result.returncode == 0, (result.stdout + result.stderr).decode(
            errors="replace"
        )[-3000:]
        assert children and resumes and valid_result and evidence["terminal_marker"], (
            "Missing official WebSearch child or main resume"
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)


def parent_result_matches(mode: str, record: dict) -> bool:
    if mode == "http-error":
        return record.get("result_is_error") is True
    if record.get("result_is_error") is not False:
        return False
    return record.get("result_contains_fixture") is (mode == "success")


if __name__ == "__main__":
    main()
