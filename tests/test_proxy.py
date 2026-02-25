import json
import pytest
import pytest_asyncio
import respx
from httpx import Response, AsyncClient, TimeoutException
from fastapi.testclient import TestClient
from unittest.mock import patch, AsyncMock

from config import TARGET_SERVICE_HEADER, TARGET_MODEL_HEADER, APIKEY_PLACEHOLDER


class TestProxyBasicForwarding:
    @pytest.mark.asyncio
    async def test_proxy_service_not_found(self, client: TestClient):
        headers = {TARGET_SERVICE_HEADER: "nonexistent"}
        response = client.post("/proxy/chat/completions", headers=headers, json={})
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_proxy_model_not_found(self, client: TestClient, sample_service: dict):
        headers = {
            TARGET_SERVICE_HEADER: "test-service",
            TARGET_MODEL_HEADER: "nonexistent-model"
        }
        response = client.post("/proxy/chat/completions", headers=headers, json={})
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_proxy_no_keys_configured(self, client: TestClient, manager):
        await manager.add_service("empty-service", "https://empty.com/api", "empty-model")
        await manager.add_model("empty-service", "empty-model")
        
        headers = {TARGET_SERVICE_HEADER: "empty-service"}
        response = client.post("/proxy/chat/completions", headers=headers, json={})
        assert response.status_code == 503

    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_forwards_request(self, client: TestClient, sample_service: dict, mock_target_response: dict):
        respx.post("https://api.test.com/v1/chat/completions").mock(
            return_value=Response(200, json=mock_target_response)
        )
        
        headers = {
            TARGET_SERVICE_HEADER: "test-service",
            TARGET_MODEL_HEADER: "default-model",
            "Content-Type": "application/json"
        }
        body = {"model": "gpt-4", "messages": [{"role": "user", "content": "Hi"}]}
        
        response = client.post("/proxy/chat/completions", headers=headers, json=body)
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == "test-response-id"

    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_replaces_apikey_placeholder_body(self, client: TestClient, sample_service: dict, mock_target_response: dict):
        call = respx.post("https://api.test.com/v1/test").mock(
            return_value=Response(200, json=mock_target_response)
        )
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        body = {"api_key": APIKEY_PLACEHOLDER, "query": "test"}
        
        response = client.post("/proxy/test", headers=headers, json=body)
        assert response.status_code == 200
        
        request_body = call.calls.last.request.content.decode()
        assert "key-aaa111" in request_body or "key-bbb222" in request_body or "key-ccc333" in request_body
        assert APIKEY_PLACEHOLDER not in request_body

    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_replaces_apikey_placeholder_header(self, client: TestClient, sample_service: dict, mock_target_response: dict):
        call = respx.post("https://api.test.com/v1/test").mock(
            return_value=Response(200, json=mock_target_response)
        )
        
        headers = {
            TARGET_SERVICE_HEADER: "test-service",
            "Authorization": f"Bearer {APIKEY_PLACEHOLDER}"
        }
        
        response = client.post("/proxy/test", headers=headers, json={})
        assert response.status_code == 200
        
        request_headers = call.calls.last.request.headers
        auth = request_headers.get("authorization", "") or request_headers.get("Authorization", "")
        assert APIKEY_PLACEHOLDER not in auth
        assert "key-" in auth

    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_preserves_query_params(self, client: TestClient, sample_service: dict, mock_target_response: dict):
        call = respx.get("https://api.test.com/v1/models?page=1&limit=10").mock(
            return_value=Response(200, json={"models": []})
        )
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        
        response = client.get("/proxy/models?page=1&limit=10", headers=headers)
        assert response.status_code == 200


class TestProxyModelResolution:
    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_explicit_model(self, client: TestClient, sample_service: dict, mock_target_response: dict):
        respx.post("https://api.test.com/v1/test").mock(
            return_value=Response(200, json=mock_target_response)
        )
        
        headers = {
            TARGET_SERVICE_HEADER: "test-service",
            TARGET_MODEL_HEADER: "other-model"
        }
        
        response = client.post("/proxy/test", headers=headers, json={})
        assert response.status_code == 503

    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_default_model(self, client: TestClient, sample_service: dict, mock_target_response: dict):
        respx.post("https://api.test.com/v1/test").mock(
            return_value=Response(200, json=mock_target_response)
        )
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        
        response = client.post("/proxy/test", headers=headers, json={})
        assert response.status_code == 200


class TestProxyRetry:
    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_429_triggers_cooldown(self, client: TestClient, sample_service: dict):
        call_count = [0]
        
        def side_effect(request):
            call_count[0] += 1
            if call_count[0] < 3:
                return Response(429, json={"error": "rate limited"})
            return Response(200, json={"success": True})
        
        respx.post("https://api.test.com/v1/test").mock(side_effect=side_effect)
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        
        response = client.post("/proxy/test", headers=headers, json={})
        assert response.status_code == 200
        assert call_count[0] >= 2

    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_max_retries_exhausted(self, client: TestClient, sample_service: dict):
        respx.post("https://api.test.com/v1/test").mock(
            return_value=Response(429, json={"error": "rate limited"})
        )
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        
        response = client.post("/proxy/test", headers=headers, json={})
        assert response.status_code == 503

    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_success_records_usage(self, client: TestClient, sample_service: dict, manager):
        respx.post("https://api.test.com/v1/test").mock(
            return_value=Response(200, json={"success": True, "usage": {"total_tokens": 50}})
        )
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        
        keys_before = await manager.get_keys("test-service", "default-model")
        usage_before = sum(k.usage_today for k in keys_before)
        
        response = client.post("/proxy/test", headers=headers, json={})
        assert response.status_code == 200
        
        keys_after = await manager.get_keys("test-service", "default-model")
        usage_after = sum(k.usage_today for k in keys_after)
        assert usage_after > usage_before


class TestProxyStreaming:
    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_detects_streaming_request(self, client: TestClient, sample_service: dict):
        async def stream_content():
            yield b'data: {"choices": []}\n\n'
            yield b'data: [DONE]\n\n'
        
        route = respx.post("https://api.test.com/v1/chat/completions")
        route.mock(return_value=Response(200, content="".encode()))
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        body = {"stream": True, "messages": []}
        
        response = client.post("/proxy/chat/completions", headers=headers, json=body)
        assert response.status_code == 200


class TestProxyHTTPMethods:
    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_get_request(self, client: TestClient, sample_service: dict):
        respx.get("https://api.test.com/v1/models").mock(
            return_value=Response(200, json={"models": []})
        )
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        response = client.get("/proxy/models", headers=headers)
        assert response.status_code == 200

    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_post_request(self, client: TestClient, sample_service: dict):
        respx.post("https://api.test.com/v1/completions").mock(
            return_value=Response(200, json={"choices": []})
        )
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        response = client.post("/proxy/completions", headers=headers, json={"prompt": "test"})
        assert response.status_code == 200

    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_delete_request(self, client: TestClient, sample_service: dict):
        respx.delete("https://api.test.com/v1/files/file123").mock(
            return_value=Response(200, json={"deleted": True})
        )
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        response = client.delete("/proxy/files/file123", headers=headers)
        assert response.status_code == 200


class TestProxyErrorHandling:
    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_500_error_passthrough(self, client: TestClient, sample_service: dict):
        respx.post("https://api.test.com/v1/test").mock(
            return_value=Response(500, json={"error": "internal error"})
        )
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        response = client.post("/proxy/test", headers=headers, json={})
        assert response.status_code == 500

    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_400_error_passthrough(self, client: TestClient, sample_service: dict):
        respx.post("https://api.test.com/v1/test").mock(
            return_value=Response(400, json={"error": "bad request"})
        )
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        response = client.post("/proxy/test", headers=headers, json={})
        assert response.status_code == 400

    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_503_triggers_retry(self, client: TestClient, sample_service: dict):
        call_count = [0]
        
        def side_effect(request):
            call_count[0] += 1
            if call_count[0] < 2:
                return Response(503, json={"error": "unavailable"})
            return Response(200, json={"success": True})
        
        respx.post("https://api.test.com/v1/test").mock(side_effect=side_effect)
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        response = client.post("/proxy/test", headers=headers, json={})
        assert response.status_code == 200
        assert call_count[0] >= 2


class TestProxyTimeout:
    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_timeout_triggers_cooldown(self, client: TestClient, sample_service: dict, manager):
        import httpx
        
        def timeout_side_effect(request):
            raise httpx.TimeoutException("Request timed out")
        
        route = respx.post("https://api.test.com/v1/test")
        route.mock(side_effect=timeout_side_effect)
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        
        response = client.post("/proxy/test", headers=headers, json={}, timeout=30)
        assert response.status_code == 503


class TestProxyBodyFormats:
    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_empty_body(self, client: TestClient, sample_service: dict):
        respx.post("https://api.test.com/v1/test").mock(
            return_value=Response(200, json={"success": True})
        )
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        response = client.post("/proxy/test", headers=headers, content="")
        assert response.status_code == 200

    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_form_data(self, client: TestClient, sample_service: dict):
        respx.post("https://api.test.com/v1/test").mock(
            return_value=Response(200, json={"success": True})
        )
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        response = client.post("/proxy/test", headers=headers, data={"key": "value"})
        assert response.status_code == 200

    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_text_body(self, client: TestClient, sample_service: dict):
        respx.post("https://api.test.com/v1/test").mock(
            return_value=Response(200, content=b"plain text response")
        )
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        response = client.post("/proxy/test", headers=headers, content="plain text")
        assert response.status_code == 200


class TestProxyHeadersPassthrough:
    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_custom_headers_passed(self, client: TestClient, sample_service: dict):
        call = respx.post("https://api.test.com/v1/test").mock(
            return_value=Response(200, json={"success": True})
        )
        
        headers = {
            TARGET_SERVICE_HEADER: "test-service",
            "X-Custom-Header": "custom-value",
            "Content-Type": "application/json"
        }
        response = client.post("/proxy/test", headers=headers, json={})
        assert response.status_code == 200
        
        request_headers = call.calls.last.request.headers
        assert request_headers.get("x-custom-header") == "custom-value"


class TestProxyAllHTTPMethods:
    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_put_request(self, client: TestClient, sample_service: dict):
        respx.put("https://api.test.com/v1/files/file123").mock(
            return_value=Response(200, json={"updated": True})
        )
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        response = client.put("/proxy/files/file123", headers=headers, json={"name": "new"})
        assert response.status_code == 200

    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_patch_request(self, client: TestClient, sample_service: dict):
        respx.patch("https://api.test.com/v1/files/file123").mock(
            return_value=Response(200, json={"patched": True})
        )
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        response = client.patch("/proxy/files/file123", headers=headers, json={"name": "new"})
        assert response.status_code == 200

    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_head_request(self, client: TestClient, sample_service: dict):
        respx.head("https://api.test.com/v1/models").mock(
            return_value=Response(200)
        )
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        response = client.head("/proxy/models", headers=headers)
        assert response.status_code == 200

    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_options_request(self, client: TestClient, sample_service: dict):
        respx.options("https://api.test.com/v1/models").mock(
            return_value=Response(200)
        )
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        response = client.options("/proxy/models", headers=headers)
        assert response.status_code == 200


class TestProxyResponseWithoutUsage:
    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_response_no_usage_field(self, client: TestClient, sample_service: dict, manager):
        respx.post("https://api.test.com/v1/test").mock(
            return_value=Response(200, json={"result": "success"})
        )
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        
        keys_before = await manager.get_keys("test-service", "default-model")
        usage_before = sum(k.usage_today for k in keys_before)
        
        response = client.post("/proxy/test", headers=headers, json={})
        assert response.status_code == 200
        
        keys_after = await manager.get_keys("test-service", "default-model")
        usage_after = sum(k.usage_today for k in keys_after)
        assert usage_after > usage_before


class TestProxyManagerNotInitialized:
    @pytest.mark.asyncio
    async def test_proxy_manager_not_initialized(self, manager):
        from fastapi.testclient import TestClient
        from server import app
        from routes import proxy
        
        with TestClient(app, raise_server_exceptions=False) as test_client:
            proxy.manager = None
            headers = {TARGET_SERVICE_HEADER: "test-service"}
            response = test_client.post("/proxy/test", headers=headers, json={})
            assert response.status_code == 500
            assert "Manager not initialized" in response.text


class TestProxyModelNotFoundError:
    @pytest.mark.asyncio
    async def test_proxy_model_not_found_after_service_check(self, client: TestClient, manager):
        await manager.add_service("model-test-svc", "https://api.test.com/v1")
        
        headers = {
            TARGET_SERVICE_HEADER: "model-test-svc",
            TARGET_MODEL_HEADER: "nonexistent-model"
        }
        response = client.post("/proxy/test", headers=headers, json={})
        assert response.status_code == 404


class TestProxyGenericException:
    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_generic_exception_in_request(self, client: TestClient, sample_service: dict):
        def raise_exception(request):
            raise RuntimeError("Unexpected error")
        
        respx.post("https://api.test.com/v1/test").mock(side_effect=raise_exception)
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        response = client.post("/proxy/test", headers=headers, json={})
        assert response.status_code == 500


class TestProxyStreamingRateLimited:
    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_streaming_rate_limited(self, client: TestClient, sample_service: dict, manager):
        route = respx.post("https://api.test.com/v1/chat/completions")
        route.mock(return_value=Response(429, json={"error": "rate limited"}))
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        body = {"stream": True, "messages": [{"role": "user", "content": "Hi"}]}
        
        response = client.post("/proxy/chat/completions", headers=headers, json=body)
        assert response.status_code == 200


class TestProxyStreamingTimeout:
    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_streaming_timeout(self, client: TestClient, sample_service: dict):
        import httpx
        
        def timeout_stream(request):
            raise httpx.TimeoutException("Stream timed out")
        
        route = respx.post("https://api.test.com/v1/chat/completions")
        route.mock(side_effect=timeout_stream)
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        body = {"stream": True, "messages": [{"role": "user", "content": "Hi"}]}
        
        response = client.post("/proxy/chat/completions", headers=headers, json=body)
        assert response.status_code == 200


class TestProxyStreamingGenericError:
    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_streaming_generic_error(self, client: TestClient, sample_service: dict):
        def error_stream(request):
            raise RuntimeError("Streaming failed")
        
        route = respx.post("https://api.test.com/v1/chat/completions")
        route.mock(side_effect=error_stream)
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        body = {"stream": True, "messages": [{"role": "user", "content": "Hi"}]}
        
        response = client.post("/proxy/chat/completions", headers=headers, json=body)
        assert response.status_code == 200


class TestProxyStreamingSuccess:
    @respx.mock
    @pytest.mark.asyncio
    async def test_proxy_streaming_success_with_tokens(self, client: TestClient, sample_service: dict):
        route = respx.post("https://api.test.com/v1/chat/completions")
        route.mock(return_value=Response(200, content=b'data: {"choices": []}\n\ndata: [DONE]\n\n'))
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        body = {"stream": True, "messages": [{"role": "user", "content": "Hi"}]}
        
        response = client.post("/proxy/chat/completions", headers=headers, json=body)
        assert response.status_code == 200


class TestHandleStreamingRequest:
    @pytest.mark.asyncio
    @respx.mock
    async def test_handle_streaming_rate_limited(self, manager):
        import httpx
        from routes.proxy import handle_streaming_request, init_manager
        
        init_manager(manager)
        await manager.add_service("stream-svc", "https://api.stream.com/v1", "stream-model")
        await manager.add_model("stream-svc", "stream-model")
        await manager.add_key("stream-svc", "stream-model", "stream-key")
        
        respx.post("https://api.stream.com/v1/chat/completions").mock(
            return_value=Response(429, json={"error": "rate limited"})
        )
        
        client = httpx.AsyncClient()
        try:
            response = await handle_streaming_request(
                client, "POST", "https://api.stream.com/v1/chat/completions", 
                {}, "{}", "stream-key", "stream-svc", "stream-model"
            )
            chunks = []
            async for chunk in response.body_iterator:
                chunks.append(chunk)
            assert len(chunks) == 1
            assert "rate_limited" in chunks[0]
        finally:
            await client.aclose()
    
    @pytest.mark.asyncio
    @respx.mock
    async def test_handle_streaming_timeout(self, manager):
        import httpx
        from routes.proxy import handle_streaming_request, init_manager
        
        init_manager(manager)
        await manager.add_service("stream-svc2", "https://api.stream2.com/v1", "stream-model")
        await manager.add_model("stream-svc2", "stream-model")
        await manager.add_key("stream-svc2", "stream-model", "stream-key2")
        
        def timeout_side_effect(request):
            raise TimeoutException("Timeout")
        
        respx.post("https://api.stream2.com/v1/chat/completions").mock(
            side_effect=timeout_side_effect
        )
        
        client = httpx.AsyncClient()
        try:
            response = await handle_streaming_request(
                client, "POST", "https://api.stream2.com/v1/chat/completions", 
                {}, "{}", "stream-key2", "stream-svc2", "stream-model"
            )
            chunks = []
            async for chunk in response.body_iterator:
                chunks.append(chunk)
            assert len(chunks) == 1
            assert "timeout" in chunks[0]
        finally:
            await client.aclose()
    
    @pytest.mark.asyncio
    @respx.mock
    async def test_handle_streaming_success(self, manager):
        import httpx
        from routes.proxy import handle_streaming_request, init_manager
        
        init_manager(manager)
        await manager.add_service("stream-svc3", "https://api.stream3.com/v1", "stream-model")
        await manager.add_model("stream-svc3", "stream-model")
        await manager.add_key("stream-svc3", "stream-model", "stream-key3")
        
        respx.post("https://api.stream3.com/v1/chat/completions").mock(
            return_value=Response(200, content=b'data: {"choices": [], "usage": {"total_tokens": 50}}\n\ndata: [DONE]\n\n')
        )
        
        client = httpx.AsyncClient()
        try:
            response = await handle_streaming_request(
                client, "POST", "https://api.stream3.com/v1/chat/completions", 
                {}, "{}", "stream-key3", "stream-svc3", "stream-model"
            )
            chunks = []
            async for chunk in response.body_iterator:
                chunks.append(chunk)
            assert len(chunks) >= 1
        finally:
            await client.aclose()
    
    @pytest.mark.asyncio
    @respx.mock
    async def test_handle_streaming_generic_error(self, manager):
        import httpx
        from routes.proxy import handle_streaming_request, init_manager
        
        init_manager(manager)
        await manager.add_service("stream-svc4", "https://api.stream4.com/v1", "stream-model")
        await manager.add_model("stream-svc4", "stream-model")
        await manager.add_key("stream-svc4", "stream-model", "stream-key4")
        
        def error_side_effect(request):
            raise RuntimeError("Connection failed")
        
        respx.post("https://api.stream4.com/v1/chat/completions").mock(
            side_effect=error_side_effect
        )
        
        client = httpx.AsyncClient()
        try:
            response = await handle_streaming_request(
                client, "POST", "https://api.stream4.com/v1/chat/completions", 
                {}, "{}", "stream-key4", "stream-svc4", "stream-model"
            )
            chunks = []
            async for chunk in response.body_iterator:
                chunks.append(chunk)
            assert len(chunks) == 1
            assert "Connection failed" in chunks[0]
        finally:
            await client.aclose()
    
    @pytest.mark.asyncio
    @respx.mock
    async def test_handle_streaming_malformed_json(self, manager):
        import httpx
        from routes.proxy import handle_streaming_request, init_manager
        
        init_manager(manager)
        await manager.add_service("stream-svc5", "https://api.stream5.com/v1", "stream-model")
        await manager.add_model("stream-svc5", "stream-model")
        await manager.add_key("stream-svc5", "stream-model", "stream-key5")
        
        respx.post("https://api.stream5.com/v1/chat/completions").mock(
            return_value=Response(200, content=b'data: {invalid json}\n\ndata: [DONE]\n\n')
        )
        
        client = httpx.AsyncClient()
        try:
            response = await handle_streaming_request(
                client, "POST", "https://api.stream5.com/v1/chat/completions", 
                {}, "{}", "stream-key5", "stream-svc5", "stream-model"
            )
            chunks = []
            async for chunk in response.body_iterator:
                chunks.append(chunk)
            assert len(chunks) >= 1
        finally:
            await client.aclose()
