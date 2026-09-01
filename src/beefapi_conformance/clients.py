from __future__ import annotations

import json
import os
import shutil
import uuid
from pathlib import Path

from .model import Client, MatrixCell


def resolve_binary(client: Client) -> str | None:
    for candidate in client.binary_candidates:
        expanded = os.path.expanduser(candidate)
        if (
            os.path.isabs(expanded)
            and os.path.isfile(expanded)
            and os.access(expanded, os.X_OK)
        ):
            return expanded
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


class ClientCommand:
    """Build a real released-client invocation against one route.

    Clients keep their default tool surface: conformance must observe the
    request shape a real user session produces, not a stripped-down variant.
    """

    def __init__(
        self,
        cell: MatrixCell,
        binary: str,
        root: Path,
        token: str | None,
        base_url: str | None,
    ) -> None:
        self.cell = cell
        self.binary = binary
        self.root = root
        self.token = token
        self.base_url = (base_url or "").rstrip("/")
        self.session_id = str(uuid.uuid4())
        self.resume_id: str | None = None

    def environment(self) -> dict[str, str]:
        env = os.environ.copy()
        for key in (
            "OPENAI_API_KEY",
            "OPENAI_BASE_URL",
            "OPENAI_API_BASE",
            "CODEX_API_KEY",
            "ANTHROPIC_API_KEY",
            "ANTHROPIC_AUTH_TOKEN",
            "ANTHROPIC_BASE_URL",
            "XAI_API_KEY",
            "GROK_CODE_XAI_API_KEY",
        ):
            env.pop(key, None)
        adapter = self.cell.client.adapter
        if adapter == "claude-code":
            env.update(
                {
                    "ANTHROPIC_BASE_URL": self.base_url,
                    "ANTHROPIC_AUTH_TOKEN": self.token or "",
                    "ANTHROPIC_MODEL": self.cell.model.client_model(
                        self.cell.client.id
                    ),
                    "CLAUDE_CONFIG_DIR": str(self.root / "client-home"),
                    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
                    "CLAUDE_CODE_DISABLE_TERMINAL_TITLE": "1",
                }
            )
        elif adapter == "codex":
            env["CODEX_HOME"] = str(self.root / "client-home")
            if self.token:
                env["BEEFAPI_CONFORMANCE_TOKEN"] = self.token
        elif adapter == "grok-build":
            isolated_home = self.root / "isolated-home"
            isolated_home.mkdir(parents=True, exist_ok=True)
            env["HOME"] = str(isolated_home)
            env["GROK_HOME"] = str(self.root / "client-home")
            if self.token:
                env["BEEFAPI_CONFORMANCE_TOKEN"] = self.token
        elif adapter == "workbuddy":
            # WorkBuddy managed-session acceptance intentionally uses its own
            # authenticated profile. We isolate workspace/session output but do
            # not copy, export, or rewrite the profile.
            pass
        return env

    def prepare(self) -> None:
        home = self.root / "client-home"
        home.mkdir(parents=True, exist_ok=True)
        adapter = self.cell.client.adapter
        model = self.cell.model.client_model(self.cell.client.id)
        if adapter == "grok-build":
            # session_summary routes Grok's auxiliary traffic (session titles
            # and summaries) to the cell's model; otherwise it calls its
            # built-in default model, which a custom route may not serve.
            # Backend search (which also declares x_search) is only enabled
            # for web scenarios, mirroring how codex is configured.
            lines = [
                "[models]",
                f"default = {json.dumps(model)}",
                f"session_summary = {json.dumps(model)}",
            ]
            web = "tool.web" in self.cell.scenario.required_capabilities
            if web:
                lines.append(f"web_search = {json.dumps(model)}")
            lines += [
                f"[model.{json.dumps(model)}]",
                f"model = {json.dumps(model)}",
                f"base_url = {json.dumps(self.base_url + '/v1')}",
                'name = "BeefAPI conformance"',
                'api_backend = "responses"',
                'env_key = "BEEFAPI_CONFORMANCE_TOKEN"',
            ]
            if web:
                lines.append("supports_backend_search = true")
            config = "\n".join([*lines, ""])
            (home / "config.toml").write_text(config, encoding="utf-8")
        elif adapter == "codex":
            lines = [
                'model_provider = "beefapi_conformance"',
                f"model = {json.dumps(model)}",
                "disable_response_storage = true",
            ]
            if "tool.web" in self.cell.scenario.required_capabilities:
                lines += ["[tools]", "web_search = true"]
            lines += [
                "[model_providers.beefapi_conformance]",
                'name = "BeefAPI conformance"',
                f"base_url = {json.dumps(self.base_url + '/v1')}",
                'wire_api = "responses"',
                'env_key = "BEEFAPI_CONFORMANCE_TOKEN"',
                "requires_openai_auth = false",
                "supports_websockets = false",
                "",
            ]
            (home / "config.toml").write_text("\n".join(lines), encoding="utf-8")

    def command(self, prompt: str, turn_index: int) -> list[str]:
        adapter = self.cell.client.adapter
        model = self.cell.model.client_model(self.cell.client.id)
        workspace = str(self.root / "workspace")
        if adapter == "claude-code":
            args = [
                self.binary,
                "--print",
                "--output-format",
                "stream-json",
                "--verbose",
                "--model",
                model,
                "--permission-mode",
                "bypassPermissions",
            ]
            args += (
                ["--session-id", self.session_id]
                if turn_index == 1
                else ["--resume", self.session_id]
            )
            return [*args, prompt]
        if adapter == "codex":
            # Native web search is enabled through config.toml ([tools]
            # web_search = true); codex 0.146 has no --search exec flag.
            if turn_index == 1:
                return [
                    self.binary,
                    "exec",
                    "--json",
                    "--sandbox",
                    "workspace-write",
                    "--ignore-rules",
                    "--skip-git-repo-check",
                    "-C",
                    workspace,
                    prompt,
                ]
            if not self.resume_id:
                raise RuntimeError("Codex did not return a thread id")
            return [
                self.binary,
                "exec",
                "resume",
                "--json",
                "--skip-git-repo-check",
                "--ignore-rules",
                "-c",
                'sandbox_mode="workspace-write"',
                self.resume_id,
                prompt,
            ]
        if adapter == "grok-build":
            args = [
                self.binary,
                "--single",
                prompt,
                "--output-format",
                "streaming-messages-json",
                "--model",
                model,
                "--permission-mode",
                "bypassPermissions",
                "--cwd",
                workspace,
            ]
            args += (
                ["--resume", self.session_id]
                if turn_index > 1
                else ["--session-id", self.session_id]
            )
            return args
        if adapter == "workbuddy":
            args = [
                self.binary,
                "--print",
                "--output-format",
                "stream-json",
                "--model",
                model,
                "--permission-mode",
                "bypassPermissions",
            ]
            if len(self.cell.scenario.turns) == 1:
                args.append("--no-session-persistence")
            args += (
                ["--resume", self.session_id]
                if turn_index > 1
                else ["--session-id", self.session_id]
            )
            settings = os.environ.get("WORKBUDDY_CONFORMANCE_SETTINGS_JSON")
            if settings:
                args += ["--settings", settings]
            return [*args, prompt]
        if adapter == "mock":
            return [self.binary, prompt]
        raise RuntimeError(f"unsupported client adapter: {adapter}")

    def observe_output(self, output: str) -> None:
        if self.cell.client.adapter != "codex" or self.resume_id:
            return
        for line in output.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("type") == "thread.started" and isinstance(
                event.get("thread_id"), str
            ):
                self.resume_id = event["thread_id"]
                return


def assistant_text(adapter: str, output: str) -> str:
    """Extract assistant/final text without accepting an echoed user prompt."""
    if adapter == "mock":
        return output
    values: list[str] = []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        _assistant_values(event, values)
    return "\n".join(values)


def _assistant_values(value: object, values: list[str], trusted: bool = False) -> None:
    if isinstance(value, str):
        if trusted:
            values.append(value)
        return
    if isinstance(value, list):
        for item in value:
            _assistant_values(item, values, trusted)
        return
    if not isinstance(value, dict):
        return
    role = value.get("role")
    event_type = value.get("type")
    item = value.get("item")
    item_type = item.get("type") if isinstance(item, dict) else None
    is_assistant = (
        trusted
        or role == "assistant"
        or event_type == "assistant"
        or item_type == "agent_message"
    )
    if event_type == "result" and isinstance(value.get("result"), str):
        values.append(value["result"])
    for key, item_value in value.items():
        if key in {"prompt", "input", "user", "request"} and not is_assistant:
            continue
        _assistant_values(item_value, values, is_assistant)
