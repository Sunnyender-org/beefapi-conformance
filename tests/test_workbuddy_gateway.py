from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from beefapi_conformance.clients import ClientCommand
from beefapi_conformance.model import Client, MatrixCell, Model, Route, Scenario, Turn


class WorkBuddyGatewayTests(unittest.TestCase):
    def cell(
        self,
        *,
        auth_mode: str,
        model_id: str = "claude-opus-5",
        aliases: dict[str, str] | None = None,
        turns: int = 1,
    ) -> MatrixCell:
        client = Client(
            "workbuddy-cli",
            "WorkBuddy",
            "workbuddy",
            ("codebuddy",),
            ("--version",),
            frozenset({"text", "session.resume"}),
            frozenset({"darwin", "linux", "windows"}),
        )
        token_env = (
            "BEEFAPI_CONFORMANCE_TOKEN" if auth_mode == "gateway_token" else None
        )
        base_url = "https://gateway.example" if auth_mode == "gateway_token" else None
        route = Route(
            "route",
            "Route",
            auth_mode,
            base_url,
            None,
            token_env,
            frozenset({"workbuddy-cli"}),
            frozenset({"workbuddy"}),
            frozenset({"text", "session.resume"}),
            None,
        )
        model = Model(
            model_id,
            model_id,
            frozenset({"route"}),
            frozenset({"workbuddy-cli"}),
            frozenset({"text", "session.resume"}),
            aliases or {},
        )
        scenario_turns = tuple(
            Turn(f"prompt-{index}", f"marker-{index}", ())
            for index in range(1, turns + 1)
        )
        scenario = Scenario(
            "scenario",
            "Scenario",
            "pr",
            "client",
            None,
            frozenset({"text"}),
            10,
            False,
            scenario_turns,
        )
        return MatrixCell(client, route, model, scenario)

    def test_gateway_env_and_args_use_explicit_model_without_alias(self) -> None:
        cell = self.cell(auth_mode="gateway_token")
        ambient = {
            "CODEBUDDY_AUTH_TOKEN": "sk-ambient-value",
            "CODEBUDDY_API_KEY": "sk-ambient-api-key",
            "CODEBUDDY_BASE_URL": "https://ambient.example/v2",
            "CODEBUDDY_MODEL": "auto",
            "WORKBUDDY_CONFIG_DIR": "/tmp/ambient-workbuddy",
            "CODEBUDDY_CONFIG_DIR": "/tmp/ambient-codebuddy",
            "ACC_PRODUCT_CONFIG_V3": '{"authentication":{"type":"custom-token"}}',
            "ACC_PRODUCT_CONFIG": '{"endpoint":"https://ambient.example"}',
            "WORKBUDDY_CONFORMANCE_SETTINGS_JSON": '{"env":{"CODEBUDDY_AUTH_TOKEN":"sk-settings"}}',
        }
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.dict(os.environ, ambient),
        ):
            root = Path(tmp)
            command = ClientCommand(
                cell,
                "codebuddy",
                root,
                "sk-ephemeral-value-301",
                "https://gateway.example",
            )
            command.prepare()
            env = command.environment()
            first = command.command("hello", 1)
            home = str(root / "client-home")
            self.assertEqual("sk-ephemeral-value-301", env["CODEBUDDY_AUTH_TOKEN"])
            self.assertEqual("https://gateway.example/v1", env["CODEBUDDY_BASE_URL"])
            self.assertEqual(home, env["CODEBUDDY_CONFIG_DIR"])
            self.assertEqual(home, env["WORKBUDDY_CONFIG_DIR"])
            self.assertNotIn("CODEBUDDY_API_KEY", env)
            self.assertNotIn("CODEBUDDY_MODEL", env)
            self.assertNotIn("ACC_PRODUCT_CONFIG_V3", env)
            self.assertNotIn("ACC_PRODUCT_CONFIG", env)
            self.assertNotIn("sk-ambient-value", env.values())
            self.assertNotIn("sk-ambient-api-key", env.values())
            self.assertIn("--print", first)
            self.assertIn("stream-json", first)
            self.assertEqual("claude-opus-5", first[first.index("--model") + 1])
            self.assertNotIn("auto", first)
            sources_at = first.index("--setting-sources")
            self.assertEqual("none", first[sources_at + 1])
            self.assertNotIn("--settings", first)
            self.assertNotIn("sk-ephemeral-value-301", first)
            self.assertNotIn("sk-ambient-value", first)
            self.assertNotIn("sk-settings", first)

    def test_gateway_rejects_custom_alias_before_call(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            auto_cell = self.cell(
                auth_mode="gateway_token",
                aliases={"workbuddy-cli": "auto"},
            )
            remapped = self.cell(
                auth_mode="gateway_token",
                aliases={"workbuddy-cli": "my-private-model"},
            )
            self_named_custom = self.cell(
                auth_mode="gateway_token", model_id="custom:wb-existing-private-model"
            )
            local_custom = self.cell(
                auth_mode="gateway_token", model_id="custom-local:existing-model"
            )
            for cell in (auto_cell, remapped, self_named_custom, local_custom):
                command = ClientCommand(
                    cell,
                    "codebuddy",
                    root,
                    "sk-ephemeral-value",
                    "https://gateway.example",
                )
                with self.assertRaisesRegex(RuntimeError, "explicit model"):
                    command.command("hello", 1)
                with self.assertRaisesRegex(RuntimeError, "explicit model"):
                    command.environment()

    def test_gateway_prepare_does_not_write_credentials_or_user_profile(self) -> None:
        profile_models = json.dumps(
            {
                "models": [
                    {
                        "id": "auto",
                        "url": "https://profile.example/v1",
                        "apiKey": "sk-profile-key",
                    }
                ]
            }
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "run"
            profile = Path(tmp) / "profile"
            workbuddy_home = profile / ".workbuddy"
            workbuddy_home.mkdir(parents=True)
            models_path = workbuddy_home / "models.json"
            models_path.write_text(profile_models, encoding="utf-8")
            before = models_path.read_text(encoding="utf-8")
            command = ClientCommand(
                self.cell(auth_mode="gateway_token"),
                "codebuddy",
                root,
                "sk-ephemeral-value",
                "https://gateway.example",
            )
            with patch.dict(
                os.environ,
                {"HOME": str(profile), "USERPROFILE": str(profile)},
            ):
                command.prepare()
                env = command.environment()
                argv = command.command("hello", 1)
            self.assertEqual(before, models_path.read_text(encoding="utf-8"))
            self.assertTrue((root / "client-home").is_dir())
            self.assertEqual(str(root / "client-home"), env["CODEBUDDY_CONFIG_DIR"])
            written = [
                path for path in (root / "client-home").rglob("*") if path.is_file()
            ]
            self.assertEqual([], written)
            blob = "\n".join(argv)
            self.assertNotIn("sk-ephemeral-value", blob)
            self.assertNotIn("sk-profile-key", blob)

    def test_gateway_absent_token_errors_before_env_is_returned(self) -> None:
        with (
            tempfile.TemporaryDirectory() as tmp,
            patch.dict(os.environ, {"CODEBUDDY_AUTH_TOKEN": "sk-ambient-value"}),
        ):
            command = ClientCommand(
                self.cell(auth_mode="gateway_token"),
                "codebuddy",
                Path(tmp),
                None,
                "https://gateway.example",
            )
            with self.assertRaisesRegex(RuntimeError, "missing the request token"):
                command.environment()

    def test_managed_session_keeps_profile_auth_and_omits_setting_sources_none(
        self,
    ) -> None:
        cell = self.cell(
            auth_mode="managed_session",
            model_id="workbuddy-test-model",
            aliases={"workbuddy-cli": "auto"},
            turns=2,
        )
        settings = '{"permissionMode":"bypassPermissions"}'
        ambient = {
            "CODEBUDDY_AUTH_TOKEN": "sk-managed-profile",
            "CODEBUDDY_BASE_URL": "https://managed.example",
            "WORKBUDDY_CONFORMANCE_SETTINGS_JSON": settings,
        }
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, ambient):
            command = ClientCommand(cell, "codebuddy", Path(tmp), None, None)
            command.prepare()
            env = command.environment()
            first = command.command("hello", 1)
            second = command.command("again", 2)
            self.assertEqual("sk-managed-profile", env.get("CODEBUDDY_AUTH_TOKEN"))
            self.assertEqual("https://managed.example", env.get("CODEBUDDY_BASE_URL"))
            self.assertNotIn("CODEBUDDY_CONFIG_DIR", env)
            self.assertNotIn("WORKBUDDY_CONFIG_DIR", env)
            self.assertNotIn("--setting-sources", first)
            self.assertNotIn("none", first)
            self.assertEqual("auto", first[first.index("--model") + 1])
            self.assertIn("--print", first)
            self.assertIn("stream-json", first)
            self.assertIn("--session-id", first)
            self.assertIn("--resume", second)
            self.assertEqual(["--settings", settings], first[-3:-1])
            self.assertFalse((Path(tmp) / "client-home" / "config.toml").exists())
