from __future__ import annotations

import json
import os
import shutil
import sys
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
            env["GROK_HOME"] = str(self.root / "client-home")
            isolated_home = self.root / "isolated-home"
            isolated_home.mkdir(parents=True, exist_ok=True)
            env["HOME"] = str(isolated_home)
            env["GROK_CLAUDE_MCPS_ENABLED"] = "false"
            env["GROK_CLAUDE_SKILLS_ENABLED"] = "false"
            env["GROK_CURSOR_MCPS_ENABLED"] = "false"
            env["GROK_CURSOR_SKILLS_ENABLED"] = "false"
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
        if self.cell.client.adapter == "grok-build":
            model = self.cell.model.client_model(self.cell.client.id)
            disabled_skills = _user_skill_names()
            disabled_plugins = _user_plugin_names()
            config = "\n".join(
                (
                    "[models]",
                    f"default = {json.dumps(model)}",
                    f"[model.{json.dumps(model)}]",
                    f"model = {json.dumps(model)}",
                    f"base_url = {json.dumps(self.base_url + '/v1')}",
                    'name = "BeefAPI conformance"',
                    'api_backend = "responses"',
                    'env_key = "BEEFAPI_CONFORMANCE_TOKEN"',
                    "[compat.cursor]",
                    "skills = false",
                    "rules = false",
                    "agents = false",
                    "mcps = false",
                    "hooks = false",
                    "sessions = false",
                    "[compat.claude]",
                    "skills = false",
                    "rules = false",
                    "agents = false",
                    "mcps = false",
                    "hooks = false",
                    "sessions = false",
                    "[compat.codex]",
                    "sessions = false",
                    "[workflows]",
                    "enabled = false",
                    "[skills]",
                    'ignore = ["~/.agents/skills"]',
                    f"disabled = {json.dumps(disabled_skills)}",
                    "[plugins]",
                    f"disabled = {json.dumps(disabled_plugins)}",
                    "",
                )
            )
            (home / "config.toml").write_text(config, encoding="utf-8")
            return
        if self.cell.client.adapter != "codex":
            return
        config = "\n".join(
            (
                'model_provider = "beefapi_conformance"',
                f"model = {json.dumps(self.cell.model.client_model(self.cell.client.id))}",
                "disable_response_storage = true",
                "[model_providers.beefapi_conformance]",
                'name = "BeefAPI conformance"',
                f"base_url = {json.dumps(self.base_url + '/v1')}",
                'wire_api = "responses"',
                'env_key = "BEEFAPI_CONFORMANCE_TOKEN"',
                "requires_openai_auth = false",
                "supports_websockets = false",
                "",
            )
        )
        (home / "config.toml").write_text(config, encoding="utf-8")

    def command(self, prompt: str, turn_index: int) -> list[str]:
        adapter = self.cell.client.adapter
        model = self.cell.model.client_model(self.cell.client.id)
        workspace = str(self.root / "workspace")
        if adapter == "claude-code":
            permission_mode = (
                "auto"
                if "client.classifier" in self.cell.scenario.required_capabilities
                else "bypassPermissions"
            )
            args = [
                self.binary,
                "--print",
                "--output-format",
                "stream-json",
                "--verbose",
                "--model",
                model,
                "--permission-mode",
                permission_mode,
            ]
            if permission_mode == "auto":
                # Session-only: do not grant tool allow rules or change the
                # user's classifier configuration. Requires Claude >=2.1.193.
                args += [
                    "--tools",
                    "Bash",
                    "--settings",
                    json.dumps({"autoMode": {"classifyAllShell": True}}),
                ]
            args += (
                ["--session-id", self.session_id]
                if turn_index == 1
                else ["--resume", self.session_id]
            )
            return [*args, prompt]
        if adapter == "codex":
            if turn_index == 1:
                return [
                    self.binary,
                    "exec",
                    "--json",
                    "--sandbox",
                    "read-only",
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
                'sandbox_mode="read-only"',
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
                "--tools",
                _grok_tools(self.cell),
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
            argv = [self.binary]
            if self.binary.endswith(".py"):
                argv = [sys.executable, self.binary]
            else:
                for candidate in self.cell.client.binary_candidates:
                    expanded = os.path.expanduser(candidate)
                    if expanded == self.binary or not expanded.endswith(".py"):
                        continue
                    argv.append(expanded)
            argv.append(prompt)
            return argv
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


def _user_skill_names() -> list[str]:
    root = Path.home() / ".agents/skills"
    try:
        return sorted(path.name for path in root.iterdir() if path.is_dir())
    except OSError:
        return []


def _user_plugin_names() -> list[str]:
    path = Path.home() / ".claude/plugins/installed_plugins.json"
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        plugins = raw.get("plugins", {}) if isinstance(raw, dict) else {}
        if not isinstance(plugins, dict):
            return []
        names = set(plugins)
        names.update(name.split("@", 1)[0] for name in plugins)
        return sorted(names)
    except (OSError, json.JSONDecodeError):
        return []


def _grok_tools(cell: MatrixCell) -> str:
    capabilities = cell.scenario.required_capabilities
    if "tool.shell" in capabilities:
        return "read_file,run_terminal_command"
    if "tool.web" in capabilities:
        return "web_search,web_fetch"
    return ""
