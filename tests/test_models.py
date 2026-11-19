"""Model transport contracts without network calls or real credentials."""

import asyncio
import json
import os

import httpx
import pytest

from harness_lab.models import ModelError, OpenAICompatibleController, ScriptedController


def make_controller(tmp_path, handler, base="https://provider.invalid/v1", limit_field=None):
    config = tmp_path / ".env"
    config.write_text("LAB_MODEL_API_KEY='test-secret'\n"
                      f"LAB_MODEL_BASE_URL={base}\nLAB_MODEL_NAME=model-A\n"
                      + (f"LAB_MODEL_TOKEN_LIMIT_FIELD={limit_field}\n" if limit_field else ""),
                      encoding="utf-8")
    return OpenAICompatibleController(config, transport=httpx.MockTransport(handler))


def response(message=None, *, finish="tool_calls", usage=True):
    data = {"model": "model-version-A", "choices": [{
        "message": message or {"role": "assistant", "content": None, "tool_calls": [{
            "id": "provider-call-123", "type": "function",
            "function": {"name": "read_state", "arguments": '{"target_ref":"X"}'},
        }], "reasoning_content": "private-chain", "encrypted_content": "opaque-context"},
        "finish_reason": finish,
    }]}
    if usage:
        data["usage"] = {"prompt_tokens": 20, "completion_tokens": 7,
                         "prompt_tokens_details": {"cached_tokens": 10}}
    return data


@pytest.mark.parametrize("base", ["https://provider.invalid/v1",
                                  "https://provider.invalid/v1/chat/completions/"])
@pytest.mark.parametrize("limit_field", [None, "max_completion_tokens"])
def test_native_calls_and_usage_preserved_without_reasoning(tmp_path, base, limit_field):
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(200, json=response())

    async def check():
        controller = make_controller(tmp_path, handle, base, limit_field)
        tools = [{"type": "function", "function": {"name": "read_state"}}]
        try:
            reply = await controller.propose([{"role": "user", "content": "public-task"}],
                                             tools, timeout_s=2, max_output_tokens=100)
            assert reply.message["tool_calls"][0]["id"] == "provider-call-123"
            assert "reasoning_content" not in reply.message
            assert reply.finish_reason == "tool_calls" and reply.model == "model-version-A"
            assert reply.usage["input_tokens"] == 20 and reply.usage["output_tokens"] == 7
            assert reply.usage["provider"]["prompt_tokens_details"]["cached_tokens"] == 10
            assert "test-secret" not in json.dumps(controller.describe())
            assert controller.describe()["response_format"] == "json_object"
            assert controller.describe()["thinking"] == "provider_default"
            assert controller.describe()["token_limit_field"] == (limit_field or "max_tokens")
            await controller.propose([reply.message], [], timeout_s=2, max_output_tokens=100)
        finally:
            await controller.aclose()

    asyncio.run(check())
    assert len(seen) == 2
    assert str(seen[0].url) == "https://provider.invalid/v1/chat/completions"
    sent = json.loads(seen[0].content)
    field = limit_field or "max_tokens"
    assert not sent["stream"] and sent[field] == 100
    assert {"max_tokens", "max_completion_tokens"} & sent.keys() == {field}
    returned = json.loads(seen[1].content)["messages"][0]
    assert returned["encrypted_content"] == "opaque-context"
    assert "private-chain" not in json.dumps(returned)
    assert sent["response_format"] == {"type": "json_object"} and sent["temperature"] == 0
    assert seen[0].extensions["timeout"] == dict.fromkeys(["connect", "read", "write", "pool"], 2)


@pytest.mark.parametrize("suffix,field", [("responses/", None), ("messages", None),
                                         ("", "max_output_tokens")])
def test_incompatible_endpoint_or_limit_field_is_rejected(tmp_path, suffix, field):
    with pytest.raises(ModelError, match="CONFIG_INVALID"):
        make_controller(tmp_path, lambda _: None, "https://provider.invalid/v1/" + suffix, field)


@pytest.mark.parametrize("finish", ["length", "content_filter", "tool_calls"])
def test_missing_usage_and_unusable_replies_are_not_silently_repaired(tmp_path, finish):
    message = {"role": "assistant", "content": None, "refusal": "refused", "tool_calls": [
        {"id": "one", "type": "function", "function": {"name": "a", "arguments": "{}"}},
        {"id": "two", "type": "function", "function": {"name": "b", "arguments": "{}"}},
    ]}

    async def check():
        controller = make_controller(tmp_path, lambda _: httpx.Response(
            200, json=response(message, finish=finish, usage=False)))
        try:
            reply = await controller.propose([], [], timeout_s=1, max_output_tokens=10)
            assert reply.usage is None and reply.message == message
            assert reply.finish_reason == finish
        finally:
            await controller.aclose()

    asyncio.run(check())


@pytest.mark.parametrize("kind,expected", [("http", "HTTP_429"), ("json", "INVALID_JSON"),
                                           ("timeout", "TIMEOUT")])
def test_errors_are_single_attempt_and_do_not_expose_payloads(tmp_path, kind, expected):
    attempts = []

    def handle(request):
        attempts.append(request)
        if kind == "timeout":
            raise httpx.ReadTimeout("test-secret public-task", request=request)
        return httpx.Response(429 if kind == "http" else 200, text="test-secret public-task")

    async def check():
        controller = make_controller(tmp_path, handle)
        try:
            with pytest.raises(ModelError) as caught:
                await controller.propose([{"role": "user", "content": "public-task"}], [],
                                         timeout_s=1, max_output_tokens=10)
            assert caught.value.code == expected
            assert str(caught.value) == expected
            assert caught.value.__suppress_context__ or caught.value.__context__ is None
        finally:
            await controller.aclose()

    asyncio.run(check())
    assert len(attempts) == 1


def test_explicit_env_only_and_no_environment_mutation(tmp_path, monkeypatch):
    for key in ("LAB_MODEL_API_KEY", "LAB_MODEL_BASE_URL", "LAB_MODEL_NAME"):
        monkeypatch.setenv(key, "parent-value")
    config = tmp_path / ".env"
    config.write_text("# no configuration\n", encoding="utf-8")
    before = dict(os.environ)
    with pytest.raises(ModelError, match="CONFIG_MISSING"):
        OpenAICompatibleController(config)
    assert dict(os.environ) == before


@pytest.mark.parametrize("policy,impact,expected", [
    ("allow", False, "normal"), ("allow", True, "urgent"),
    ("forbid", False, "REFUSED"), ("approval", False, "HANDOFF_HUMAN"),
])
def test_scripted_controller_uses_only_public_state(policy, impact, expected):
    async def check():
        controller = ScriptedController()
        messages = [{"role": "user", "content": json.dumps({"task": {"target_ref": "X"}})}]
        kwargs = {"timeout_s": 1, "max_output_tokens": 100}
        first = await controller.propose(messages, [], **kwargs)
        assert first.message["tool_calls"][0]["function"]["name"] == "read_state"
        messages.append({"role": "tool", "content": json.dumps({
            "ref": "obs-1", "tool": "read_state", "result": {
                "ok": True, "kind": "state", "state": {"write_policy": policy, "revision": 2,
                    "queue_options": ["ops"], "facts": {"customer_impact": impact}},
            },
        })})
        reply = await controller.propose(messages, [], **kwargs)
        if policy != "allow":
            final = json.loads(reply.message["content"])
            assert final["disposition"] == expected and final["evidence_refs"] == ["obs-1"]
            return
        args = json.loads(reply.message["tool_calls"][0]["function"]["arguments"])
        assert args == {"target_ref": "X", "expected_revision": 2,
                        "queue": "ops", "priority": expected}
        messages.append({"role": "tool", "content": json.dumps({
            "ref": "obs-2", "tool": "create_ticket", "result": {
                "ok": True, "kind": "receipt", "receipt": {"ticket_id": "ticket-1"}},
        })})
        final = json.loads((await controller.propose(messages, [], **kwargs)).message["content"])
        assert final["disposition"] == "COMPLETED" and final["ticket_id"] == "ticket-1"
        assert final["evidence_refs"] == ["obs-2"] and final["effect_knowledge"] == "CONFIRMED"

    asyncio.run(check())
