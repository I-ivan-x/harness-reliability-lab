"""Safe provider diagnostics, using fake HTTP responses and a real MCP run."""

import asyncio
import json
import sqlite3

import httpx
import pytest
from tests.test_runtime import execute, prepare

from harness_lab.contracts import Budget
from harness_lab.models import ModelError, OpenAICompatibleController
from harness_lab.runtime import run
from harness_lab.trace import replay

API_KEY = "sk-test-diagnostic-secret"
PRIVATE_BODY = "private-user-task-and-provider-message"


def controller_for(tmp_path, handler):
    config = tmp_path / "model.env"
    config.write_text(
        f"LAB_MODEL_API_KEY={API_KEY}\n"
        "LAB_MODEL_BASE_URL=https://provider.invalid/v1\n"
        "LAB_MODEL_NAME=diagnostic-test\n",
        encoding="utf-8",
    )
    return OpenAICompatibleController(config, transport=httpx.MockTransport(handler))


def failed_request(tmp_path, response_or_error):
    """Exercise the public adapter without a retry or external network request."""
    seen = []

    def handle(request):
        seen.append(request)
        if isinstance(response_or_error, Exception):
            raise response_or_error
        return response_or_error

    async def check():
        controller = controller_for(tmp_path, handle)
        try:
            with pytest.raises(ModelError) as caught:
                await controller.propose(
                    [{"role": "user", "content": PRIVATE_BODY}], [],
                    timeout_s=1, max_output_tokens=20,
                )
            return caught.value
        finally:
            await controller.aclose()

    error = asyncio.run(check())
    assert len(seen) == 1
    assert str(error) == error.code
    exposed = json.dumps(error.diagnostics)
    assert API_KEY not in exposed and PRIVATE_BODY not in exposed
    assert "provider.invalid" not in exposed
    return error


def test_http_error_keeps_only_safe_metadata(tmp_path):
    error = failed_request(tmp_path, httpx.Response(403, json={
        "error": {
            "code": "AccessDenied.ResourceUnavailable",
            "type": "PermissionDenied",
            "message": f"{PRIVATE_BODY} {API_KEY}",
            "debug": {"authorization": API_KEY},
        },
        "request_id": "body-request-ignored",
        "usage": {"prompt_tokens": 123},
    }, headers={
        "x-request-id": "provider-request-7",
        "x-tt-logid": "secondary-request-8",
        "authorization": "Bearer " + API_KEY,
        "set-cookie": PRIVATE_BODY,
    }))
    assert error.code == "HTTP_403"
    assert error.diagnostics == {
        "layer": "http", "http_status": 403,
        "provider_code": "AccessDenied.ResourceUnavailable",
        "provider_type": "PermissionDenied",
        "request_id": "provider-request-7", "request_id_source": "header:x-request-id",
    }


@pytest.mark.parametrize(("headers", "body", "request_id", "source"), [
    ({"x-tt-logid": "ark-log-1"}, {"request_id": "root-2"},
     "ark-log-1", "header:x-tt-logid"),
    ({}, {"request_id": "root-2", "error": {"request_id": "nested-3"}},
     "root-2", "body:request_id"),
    ({}, {"error": {"request_id": "nested-3"}},
     "nested-3", "body:error.request_id"),
    ({"X-Request-Id": "case-insensitive-4"}, {},
     "case-insensitive-4", "header:x-request-id"),
])
def test_request_id_source_is_explicit(tmp_path, headers, body, request_id, source):
    error = failed_request(tmp_path, httpx.Response(403, json=body, headers=headers))
    assert error.diagnostics["request_id"] == request_id
    assert error.diagnostics["request_id_source"] == source


def test_unsafe_preferred_request_id_falls_back_to_safe_source(tmp_path):
    error = failed_request(tmp_path, httpx.Response(403, json={"request_id": "body-safe"},
        headers={"x-request-id": API_KEY, "x-tt-logid": "ark-safe"}))
    assert error.diagnostics["request_id"] == "ark-safe"
    assert error.diagnostics["request_id_source"] == "header:x-tt-logid"


@pytest.mark.parametrize("body", [None, [], "error", {"error": "unstructured"}, {
    "code": "DoNotInferRootCode", "type": "DoNotInferRootType", "message": PRIVATE_BODY,
}])
def test_missing_or_unstructured_metadata_stays_unknown(tmp_path, body):
    error = failed_request(tmp_path, httpx.Response(403, json=body))
    assert error.code == "HTTP_403"
    assert error.diagnostics == {"layer": "http", "http_status": 403}


def test_non_json_http_error_still_has_header_request_id(tmp_path):
    error = failed_request(tmp_path, httpx.Response(502, text=PRIVATE_BODY,
        headers={"x-request-id": "gateway-12"}))
    assert error.code == "HTTP_502"
    assert error.diagnostics == {
        "layer": "http", "http_status": 502,
        "request_id": "gateway-12", "request_id_source": "header:x-request-id",
    }


def test_oversized_error_body_is_ignored_without_losing_header_identity(tmp_path):
    error = failed_request(tmp_path, httpx.Response(403, json={
        "error": {"code": "MustNotParseOversizedBody"}, "request_id": "body-id",
        "padding": "x" * (16 * 1024),
    }, headers={"x-tt-logid": "large-body-log-1"}))
    assert error.code == "HTTP_403"
    assert error.diagnostics == {
        "layer": "http", "http_status": 403,
        "request_id": "large-body-log-1", "request_id_source": "header:x-tt-logid",
    }


def test_deeply_nested_error_json_cannot_hide_http_status(tmp_path):
    body = "[" * 1200 + "0" + "]" * 1200
    error = failed_request(tmp_path, httpx.Response(403, text=body))
    assert error.code == "HTTP_403"
    assert error.diagnostics == {"layer": "http", "http_status": 403}


def test_client_chosen_request_id_is_not_claimed_as_provider_identity(tmp_path):
    error = failed_request(tmp_path, httpx.Response(403, headers={
        "x-client-request-id": "caller-chosen-not-provider-generated",
    }))
    assert error.diagnostics == {"layer": "http", "http_status": 403}


@pytest.mark.parametrize("bad_value", [
    "", "error with spaces", "bad\nline", "非ASCII", "a" * 129,
    API_KEY, "prefix-" + API_KEY + "-suffix", 123, ["error"], {"code": "error"},
])
def test_unsafe_provider_identifiers_are_discarded(tmp_path, bad_value):
    error = failed_request(tmp_path, httpx.Response(403, json={
        "error": {"code": bad_value, "type": bad_value, "message": PRIVATE_BODY},
        "request_id": bad_value,
    }))
    assert error.diagnostics == {"layer": "http", "http_status": 403}


@pytest.mark.parametrize("value", ["7", "0", "Wed, 21 Oct 2015 07:28:00 GMT"])
def test_retry_after_is_a_hint_without_changing_single_attempt(tmp_path, value):
    error = failed_request(tmp_path, httpx.Response(429, json={
        "error": {"code": "RateLimitExceeded"},
    }, headers={"Retry-After": value}))
    assert error.code == "HTTP_429"
    assert error.diagnostics["retry_after"] == value
    assert error.diagnostics["provider_code"] == "RateLimitExceeded"


@pytest.mark.parametrize("value", [
    "-1", "1.5", "tomorrow", "a" * 129, API_KEY,
    "Wed, 99 Oct 2015 07:28:00 GMT", "9999999999999999999999999999999999x",
])
def test_invalid_retry_after_is_discarded(tmp_path, value):
    error = failed_request(tmp_path, httpx.Response(429, headers={"Retry-After": value}))
    assert error.diagnostics == {"layer": "http", "http_status": 429}


@pytest.mark.parametrize(("reply", "expected"), [
    (httpx.Response(200, text=PRIVATE_BODY), "INVALID_JSON"),
    (httpx.Response(200, json={"choices": [], "error": {"code": "NotHttpError"}}),
     "INVALID_RESPONSE"),
])
def test_received_but_invalid_response_is_distinguished_from_transport(tmp_path, reply, expected):
    reply.headers["x-request-id"] = "received-response-11"
    error = failed_request(tmp_path, reply)
    assert error.code == expected
    assert error.diagnostics == {
        "layer": "response", "http_status": 200,
        "request_id": "received-response-11", "request_id_source": "header:x-request-id",
    }


@pytest.mark.parametrize(("exception", "expected"), [
    (httpx.ReadTimeout(f"{API_KEY} {PRIVATE_BODY}"), "TIMEOUT"),
    (httpx.ConnectError(f"{API_KEY} {PRIVATE_BODY}"), "TRANSPORT_ERROR"),
])
def test_transport_failure_has_no_invented_http_response(tmp_path, exception, expected):
    error = failed_request(tmp_path, exception)
    assert error.code == expected
    assert error.diagnostics == {"layer": "transport"}


def test_403_is_persisted_with_unknown_usage_and_no_behavior_change(tmp_path):
    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(403, json={
            "error": {"code": "AccessDenied.ResourceUnavailable",
                      "type": "PermissionDenied", "message": f"{PRIVATE_BODY} {API_KEY}"},
        }, headers={"x-tt-logid": "real-mcp-fixture-log-1"})

    prepared = prepare(tmp_path, controller=controller_for(tmp_path, handle))
    record = execute(prepared)
    assert len(requests) == 1
    assert record["output"]["disposition"] == "SYSTEM_FAILURE"
    assert record["output"]["reason_code"] == "HTTP_403"
    assert record["output"]["effect_knowledge"] == "NOT_COMMITTED"
    assert record["costs"]["model_calls"] == 1
    assert record["costs"]["tool_attempts"] == 0
    assert record["costs"]["input_tokens"] is None
    assert record["costs"]["output_tokens"] is None
    directory = prepared[1].artifact_dir
    raw_trace = (directory / "trace.jsonl").read_text(encoding="utf-8")
    events = [json.loads(line) for line in raw_trace.splitlines()]
    failed = [event["data"] for event in events if event["event"] == "model_failed"]
    assert failed == [{"usage": None, "error": {
        "code": "HTTP_403", "layer": "http", "http_status": 403,
        "provider_code": "AccessDenied.ResourceUnavailable",
        "provider_type": "PermissionDenied", "request_id": "real-mcp-fixture-log-1",
        "request_id_source": "header:x-tt-logid",
    }}]
    assert any(event["event"] == "wire_send" and
               event["data"].get("method") == "initialize" for event in events)
    assert not any(event["event"] == "tool_attempt" for event in events)
    with sqlite3.connect(directory / "environment.sqlite") as database:
        assert database.execute("SELECT count(*) FROM tickets").fetchone()[0] == 0
    # Metadata belongs to the trace diagnostic, never to future model messages or disposition.
    model_request = next(event["data"] for event in events if event["event"] == "model_request")
    assert "real-mcp-fixture-log-1" not in json.dumps(model_request)
    assert "real-mcp-fixture-log-1" not in json.dumps(record["output"])
    for path in (directory / "manifest.json", directory / "trace.jsonl"):
        text = path.read_text(encoding="utf-8")
        assert API_KEY not in text and PRIVATE_BODY not in text


@pytest.mark.parametrize(("mode", "code", "layer", "disposition", "reason"), [
    ("deadline", "HOST_TIMEOUT", "host_deadline", "SYSTEM_FAILURE", "invalid_response"),
    ("cancel", "CANCELLED", "host_cancel", "SAFE_STOP", "cancelled"),
])
def test_host_interruption_is_distinct_from_provider_timeout(
    tmp_path, mode, code, layer, disposition, reason,
):
    requests = []

    async def check():
        started = asyncio.Event()

        async def handle(request):
            requests.append(request)
            started.set()
            await asyncio.Event().wait()

        prepared = prepare(
            tmp_path, controller=controller_for(tmp_path, handle),
            budget=Budget(model_timeout_s=0.01 if mode == "deadline" else 30),
        )
        task, config, ports = prepared
        running = asyncio.create_task(run(task, config, ports))
        if mode == "cancel":
            await asyncio.wait_for(started.wait(), timeout=5)
            running.cancel()
        record = await asyncio.wait_for(running, timeout=10)
        assert record["measurement_valid"] and record["terminated_quiescent"]
        assert replay(config.artifact_dir) == record
        events = [json.loads(line) for line in
                  (config.artifact_dir / "trace.jsonl").read_text(encoding="utf-8").splitlines()]
        assert [event["data"] for event in events if event["event"] == "model_failed"] == [{
            "usage": None, "error": {"code": code, "layer": layer},
        }]
        assert record["output"]["disposition"] == disposition
        assert record["output"]["reason_code"] == reason
        assert record["costs"]["model_calls"] == 1
        assert record["costs"]["tool_attempts"] == 0
        assert record["costs"]["input_tokens"] is None
        assert record["costs"]["output_tokens"] is None

    asyncio.run(check())
    assert len(requests) == 1
