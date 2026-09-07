"""Black-box Codex contracts. Expected facts never appear in follow-up prompts.

The callback owns credentials, route pinning, timeouts and request receipts.
This module never executes a model-supplied command or patch.
"""

from __future__ import annotations

import json
import uuid

from .wire import parse_sse


def response(outcome, stream=True):
    if outcome.status_code is None or not 200 <= outcome.status_code < 300:
        raise ValueError(f"HTTP {outcome.status_code}")
    if stream:
        if outcome.stream_detail:
            raise ValueError(outcome.stream_detail)
        events = [
            json.loads(data)
            for _, data in parse_sse(outcome.output)
            if data != "[DONE]"
        ]
        if any(
            e.get("type") in {"error", "response.failed", "response.incomplete"}
            for e in events
        ):
            raise ValueError("unsuccessful Responses terminal")
        completed = [
            e["response"] for e in events if e.get("type") == "response.completed"
        ]
        if len(completed) != 1:
            raise ValueError("expected exactly one response.completed")
        result = completed[0]
        if result.get("status") != "completed":
            raise ValueError("terminal response is not completed")
        return result
    result = json.loads(outcome.output)
    if result.get("error"):
        raise ValueError("JSON error")
    return result


def output_text(result):
    return "\n".join(
        c.get("text", "")
        for i in result.get("output", [])
        if i.get("type") == "message"
        for c in i.get("content", [])
        if c.get("type") == "output_text"
    )


def exercise(contract, model, send):
    outcomes, problems = [], []

    def call(payload, endpoint="/v1/responses", stream=True):
        payload = dict(payload, model=model)
        if endpoint.endswith("/compact"):
            payload.pop("stream", None)
        else:
            payload["stream"] = stream
        outcome = send(payload, endpoint, stream)
        outcomes.append(outcome)
        return response(outcome, stream)

    try:
        if contract == "foreign-compaction":
            outcome = send(
                {
                    "model": model,
                    "stream": True,
                    "input": [
                        {
                            "type": "compaction",
                            "encrypted_content": "foreign.unreadable.fixture",
                        },
                        {"role": "user", "content": "Continue."},
                    ],
                },
                "/v1/responses",
                True,
            )
            outcomes.append(outcome)
            errors = []
            if outcome.status_code in {400, 409, 422}:
                try:
                    errors.append(json.loads(outcome.output).get("error", {}))
                except ValueError:
                    pass
            for _, data in parse_sse(outcome.output):
                try:
                    e = json.loads(data)
                    if e.get("type") == "response.failed":
                        errors.append(e.get("response", {}).get("error", {}))
                except ValueError:
                    pass
            if not any(
                e.get("code")
                in {
                    "invalid_compaction",
                    "invalid_request_error",
                    "context_length_exceeded",
                }
                for e in errors
            ):
                raise ValueError(
                    "foreign opaque state was not explicitly rejected with a protocol error"
                )
        elif contract.startswith("compact-"):
            nonce = "REMEMBER_" + uuid.uuid4().hex
            history = [
                {
                    "type": "message",
                    "role": "user",
                    "content": "Remember the secret "
                    + nonce
                    + ". "
                    + ("Background detail. " * 1500),
                },
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "Remembered."}],
                },
            ]
            for cycle in range(2):
                streaming = contract == "compact-stream"
                payload = {
                    "input": history
                    + ([{"type": "compaction_trigger"}] if streaming else [])
                }
                compact = call(
                    payload,
                    "/v1/responses" if streaming else "/v1/responses/compact",
                    streaming,
                )
                items = compact.get("output", [])
                states = [i for i in items if i.get("type") == "compaction"]
                if len(states) != 1 or not states[0].get("encrypted_content"):
                    raise ValueError(
                        "expected exactly one reusable opaque compaction item"
                    )
                if len(json.dumps(items)) >= len(json.dumps(history)):
                    raise ValueError("compaction did not reduce the serialized context")
                continued = call(
                    {
                        "input": items
                        + [
                            {
                                "role": "user",
                                "content": "What secret did I ask you to remember? Reply with it only.",
                            }
                        ]
                    }
                )
                if nonce not in output_text(continued):
                    raise ValueError("compaction continuation lost the secret")
                # Keep enough material to make the second reduction meaningful.
                history = (
                    items
                    + continued.get("output", [])
                    + [
                        {
                            "role": "user",
                            "content": "Continue to remember the same secret. "
                            + ("New background. " * 1500),
                        }
                    ]
                )
        else:
            custom = contract != "namespace"
            name = (
                "apply_patch"
                if contract == "apply_patch"
                else ("write_raw" if custom else "lookup")
            )
            expected = "PATCH_" + uuid.uuid4().hex
            target = (
                "*** Begin Patch\n*** Add File: fixture.txt\n+"
                + expected
                + "\n*** End Patch"
                if contract == "apply_patch"
                else expected
            )
            tool = (
                {
                    "type": "custom",
                    "name": name,
                    "description": "Return the exact requested text.",
                    "format": {"type": "text"},
                }
                if custom
                else {
                    "type": "function",
                    "name": name,
                    "description": "Look up a record.",
                    "parameters": {
                        "type": "object",
                        "properties": {"id": {"type": "string"}},
                        "required": ["id"],
                    },
                }
            )
            tools = (
                [tool]
                if custom
                else [{"type": "namespace", "name": "functions", "tools": [tool]}]
            )
            prompt = (
                "Call "
                + name
                + " exactly once with "
                + ("this exact input:\n" + target if custom else 'id="fixture"')
                + ". Do not answer in prose."
            )
            result = call(
                {
                    "tools": tools,
                    "tool_choice": {"type": "custom", "name": name}
                    if custom
                    else {"type": "function", "name": name, "namespace": "functions"},
                    "input": [{"role": "user", "content": prompt}],
                }
            )
            calls = [
                i
                for i in result.get("output", [])
                if i.get("type") in {"function_call", "custom_tool_call"}
            ]
            if len(calls) != 1:
                raise ValueError("expected one tool call")
            item = calls[0]
            if (
                item.get("type") != ("custom_tool_call" if custom else "function_call")
                or item.get("name") != name
            ):
                raise ValueError("tool kind/name did not round-trip")
            if not custom and item.get("namespace") != "functions":
                raise ValueError("tool namespace lost")
            if custom and item.get("input", "").strip() != target:
                raise ValueError("custom tool input changed")
            if not custom and json.loads(item.get("arguments", "{}")) != {
                "id": "fixture"
            }:
                raise ValueError("function arguments changed")
            if not item.get("call_id"):
                raise ValueError("missing call_id")
            receipt = "RESULT_" + uuid.uuid4().hex
            follow = call(
                {
                    "tools": tools,
                    "tool_choice": "none",
                    "input": [{"role": "user", "content": prompt}]
                    + result["output"]
                    + [
                        {
                            "type": "custom_tool_call_output"
                            if custom
                            else "function_call_output",
                            "call_id": item["call_id"],
                            "output": receipt,
                        },
                        {"role": "user", "content": "Reply with the tool result only."},
                    ],
                }
            )
            if receipt not in output_text(follow):
                raise ValueError("tool result continuation lost the result")
    except (ValueError, KeyError, TypeError) as exc:
        problems.append(str(exc))
    return outcomes, problems
