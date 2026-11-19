"""Thin, single-attempt model ports; credentials never enter the message history."""

import json
import re
import uuid
from dataclasses import dataclass
from email.utils import format_datetime, parsedate_to_datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx


class ModelError(Exception):
    def __init__(self, code: str, *, diagnostics: dict | None = None):
        super().__init__(code)
        self.code = code
        self.diagnostics = diagnostics or {}


@dataclass(frozen=True)
class ModelReply:
    message: dict[str, Any]
    usage: dict[str, Any] | None
    finish_reason: str
    model: str


class OpenAICompatibleController:
    """Read only an explicit local env file, with no interpolation or env fallback."""

    def __init__(self, env_file: Path, *, transport: httpx.AsyncBaseTransport | None = None):
        try:
            lines = env_file.read_text(encoding="utf-8-sig").splitlines()
        except (OSError, UnicodeError):
            raise ModelError("CONFIG_UNREADABLE") from None
        values = {}
        for line in lines:
            name, separator, value = line.strip().removeprefix("export ").partition("=")
            if separator and name.strip() in {
                "LAB_MODEL_API_KEY", "LAB_MODEL_BASE_URL", "LAB_MODEL_NAME",
                "LAB_MODEL_TOKEN_LIMIT_FIELD",
            }:
                value = value.strip()
                if value[:1] in {"'", '"'} and value[-1:] == value[:1]:
                    value = value[1:-1]
                values[name.strip()] = value
        if not all(values.get(name) for name in (
            "LAB_MODEL_API_KEY", "LAB_MODEL_BASE_URL", "LAB_MODEL_NAME"
        )):
            raise ModelError("CONFIG_MISSING")
        base = values["LAB_MODEL_BASE_URL"].rstrip("/")
        parsed = urlsplit(base)
        self.token_limit_field = values.get("LAB_MODEL_TOKEN_LIMIT_FIELD", "max_tokens")
        if (parsed.scheme not in {"https", "http"} or not parsed.hostname
                or parsed.username or parsed.password or parsed.query or parsed.fragment
                or parsed.path.rsplit("/", 1)[-1] in {"responses", "messages"}
                or self.token_limit_field not in {"max_tokens", "max_completion_tokens"}
                or any(ord(char) < 32 for value in values.values() for char in value)):
            raise ModelError("CONFIG_INVALID")
        self.model = values["LAB_MODEL_NAME"]
        self.base_url = base
        self._key = values["LAB_MODEL_API_KEY"]
        self._url = base if base.endswith("/chat/completions") else base + "/chat/completions"
        self._client = httpx.AsyncClient(trust_env=False, transport=transport)

    def describe(self) -> dict[str, Any]:
        return {"kind": "openai-compatible", "model": self.model, "base_url": self.base_url,
                "response_format": "json_object", "temperature": 0,
                "thinking": "provider_default", "token_limit_field": self.token_limit_field}

    async def aclose(self) -> None:
        await self._client.aclose()

    def _response_error(self, code: str, response: httpx.Response) -> ModelError:
        """Keep bounded identifiers only; free-text errors may echo credentials or prompts."""
        details = {"layer": "http" if code.startswith("HTTP_") else "response",
                   "http_status": response.status_code}

        def identifier(value):
            return (isinstance(value, str) and self._key not in value
                    and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", value))

        # An oversized/invalid error body must never mask the original HTTP failure.
        data = {}
        if code.startswith("HTTP_") and len(response.content) <= 16_384:
            try:
                data = response.json()
            except (ValueError, UnicodeError, RecursionError):
                pass
        data = data if isinstance(data, dict) else {}
        error = data.get("error")
        error = error if isinstance(error, dict) else {}
        for field in ("code", "type"):
            if identifier(error.get(field)):
                details["provider_" + field] = error[field]
        candidates = [
            ("header:" + name, response.headers.get(name))
            for name in ("x-request-id", "x-tt-logid")
        ] + [("body:request_id", data.get("request_id")),
             ("body:error.request_id", error.get("request_id"))]
        for source, value in candidates:
            if identifier(value):
                details.update(request_id=value, request_id_source=source)
                break
        retry = response.headers.get("retry-after", "")
        if len(retry) <= 128 and self._key not in retry:
            if re.fullmatch(r"[0-9]{1,9}", retry):
                details["retry_after"] = retry
            elif re.fullmatch(r"[A-Z][a-z]{2}, [0-9]{2} [A-Z][a-z]{2} "
                              r"[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT", retry):
                try:
                    if format_datetime(parsedate_to_datetime(retry), usegmt=True) == retry:
                        details["retry_after"] = retry
                except (ValueError, OverflowError):
                    pass
        return ModelError(code, diagnostics=details)

    async def propose(
        self, messages: list, tools: list, *, timeout_s: float, max_output_tokens: int
    ) -> ModelReply:
        if timeout_s <= 0 or max_output_tokens <= 0:
            raise ModelError("INVALID_LIMITS")
        payload = {"model": self.model, "messages": messages, "stream": False,
                   self.token_limit_field: max_output_tokens, "temperature": 0,
                   "response_format": {"type": "json_object"}}
        if tools:
            payload.update(tools=tools, tool_choice="auto")
        try:
            response = await self._client.post(
                self._url, json=payload, timeout=httpx.Timeout(timeout_s),
                headers={"Authorization": "Bearer " + self._key},
            )
        except httpx.TimeoutException:
            raise ModelError("TIMEOUT", diagnostics={"layer": "transport"}) from None
        except httpx.HTTPError:
            raise ModelError("TRANSPORT_ERROR", diagnostics={"layer": "transport"}) from None
        if not 200 <= response.status_code < 300:
            raise self._response_error(f"HTTP_{response.status_code}", response)
        try:
            data = response.json()
        except (ValueError, UnicodeError):
            raise self._response_error("INVALID_JSON", response) from None
        try:
            choices = data["choices"]
            if not isinstance(choices, list) or len(choices) != 1:
                raise ValueError
            message = choices[0]["message"]
            finish = choices[0]["finish_reason"]
            if not isinstance(message, dict) or not isinstance(finish, str):
                raise ValueError
            # Keep opaque encrypted context; plaintext reasoning is not forwarded or traced.
            message = {key: value for key, value in message.items()
                       if key not in {"reasoning_content", "reasoning"}}
            usage = data.get("usage")
            if usage is not None:
                if not isinstance(usage, dict):
                    raise ValueError
                counts = [usage.get("prompt_tokens", usage.get("input_tokens")),
                          usage.get("completion_tokens", usage.get("output_tokens"))]
                if any(value is not None and (type(value) is not int or value < 0)
                       for value in counts):
                    raise ValueError
                usage = {"input_tokens": counts[0], "output_tokens": counts[1], "provider": usage}
            model = data.get("model", self.model)
            if not isinstance(model, str):
                raise ValueError
            return ModelReply(message, usage, finish, model)
        except (KeyError, TypeError, ValueError, IndexError):
            raise self._response_error("INVALID_RESPONSE", response) from None


class ScriptedController:
    """Deterministic development client using only the public task and actual observations."""

    def describe(self) -> dict[str, str]:
        return {"kind": "scripted", "model": "scripted"}

    async def aclose(self) -> None:
        pass

    async def propose(
        self, messages: list, tools: list, *, timeout_s: float, max_output_tokens: int
    ) -> ModelReply:
        task = next(json.loads(item["content"])["task"]
                    for item in messages if item["role"] == "user")
        observation = None
        for item in reversed(messages):
            if item["role"] == "tool":
                observation = json.loads(item["content"])
                break
            if item["role"] == "user":
                value = json.loads(item["content"])
                if value.get("source") == "host_refresh":
                    observation = value["observation"]
                    break
        target = task["target_ref"]
        if observation is None:
            return self._call("read_state", {"target_ref": target})
        result = observation["result"]
        if result.get("ok") and result.get("kind") == "receipt":
            receipt = result["receipt"]
            return self._final("COMPLETED", target, observation["ref"], "completed",
                               "CONFIRMED", receipt["ticket_id"])
        if result.get("ok") and result.get("kind") == "state":
            state = result["state"]
            policy = state["write_policy"]
            if policy == "forbid":
                return self._final("REFUSED", target, observation["ref"],
                                   "policy_forbidden", "NOT_COMMITTED")
            if policy == "approval":
                return self._final("HANDOFF_HUMAN", target, observation["ref"],
                                   "approval_required", "NOT_COMMITTED")
            return self._call("create_ticket", {
                "target_ref": target, "expected_revision": state["revision"],
                "queue": state["queue_options"][0],
                "priority": "urgent" if state.get("facts", {}).get("customer_impact") else "normal",
            })
        code = result.get("error", {}).get("code", "TOOL_UNAVAILABLE")
        disposition = {"PERMISSION_DENIED": "REFUSED",
                       "APPROVAL_REQUIRED": "HANDOFF_HUMAN"}.get(code, "SAFE_STOP")
        reason = {"PERMISSION_DENIED": "policy_forbidden",
                  "APPROVAL_REQUIRED": "approval_required"}.get(code, "tool_unavailable")
        knowledge = "UNKNOWN" if observation["tool"] == "create_ticket" else "NOT_COMMITTED"
        return self._final(disposition, target, observation["ref"], reason, knowledge)

    @staticmethod
    def _reply(message: dict, finish: str) -> ModelReply:
        return ModelReply(message, {"input_tokens": 0, "output_tokens": 0, "provider": {}},
                          finish, "scripted")

    def _call(self, name: str, arguments: dict) -> ModelReply:
        return self._reply({"role": "assistant", "content": None, "tool_calls": [{
            "id": "call-" + uuid.uuid4().hex, "type": "function",
            "function": {"name": name, "arguments": json.dumps(arguments)},
        }]}, "tool_calls")

    def _final(
        self, disposition: str, target: str, ref: str, reason: str, knowledge: str,
        ticket_id: str | None = None,
    ) -> ModelReply:
        return self._reply({"role": "assistant", "content": json.dumps({
            "disposition": disposition, "target_ref": target, "ticket_id": ticket_id,
            "evidence_refs": [ref], "reason_code": reason, "effect_knowledge": knowledge,
        })}, "stop")
