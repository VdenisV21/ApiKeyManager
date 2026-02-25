import json
import os
import time
from datetime import datetime, timezone

import pytest
import pytest_asyncio
import respx
from httpx import Response
from fastapi.testclient import TestClient

from core.manager import ApiKeyManager
from core.models import KeyLimits
from config import TARGET_SERVICE_HEADER, TARGET_MODEL_HEADER


class TestFullWorkflows:
    @respx.mock
    @pytest.mark.asyncio
    async def test_full_workflow(self, client: TestClient, admin_headers: dict, manager):
        create_svc = client.post(
            "/admin/services",
            json={"name": "workflow-service", "base_url": "https://workflow.com/api"},
            headers=admin_headers
        )
        assert create_svc.status_code == 200

        create_model = client.post(
            "/admin/services/workflow-service/models",
            json={"name": "workflow-model", "limits": {"rpm": 10, "rpd": 100}},
            headers=admin_headers
        )
        assert create_model.status_code == 200

        for i in range(3):
            add_key = client.post(
                "/admin/services/workflow-service/models/workflow-model/keys",
                json={"api_key": f"wf-key-{i}"},
                headers=admin_headers
            )
            assert add_key.status_code == 200

        respx.post("https://workflow.com/api/test").mock(
            return_value=Response(200, json={"result": "success", "usage": {"total_tokens": 50}})
        )

        proxy_response = client.post(
            "/proxy/test",
            headers={TARGET_SERVICE_HEADER: "workflow-service"},
            json={"prompt": "test"}
        )
        assert proxy_response.status_code == 200

        keys = await manager.get_keys("workflow-service", "workflow-model")
        assert any(k.usage_today > 0 for k in keys)
        assert any(k.tokens_today > 0 for k in keys)

    @respx.mock
    @pytest.mark.asyncio
    async def test_multi_key_rotation(self, client: TestClient, admin_headers: dict, manager):
        await manager.add_service("rotation-svc", "https://rotation.com/api", "rot-model")
        await manager.add_model("rotation-svc", "rot-model", KeyLimits())
        
        keys_added = []
        for i in range(5):
            key = f"rot-key-{i:03d}"
            await manager.add_key("rotation-svc", "rot-model", key)
            keys_added.append(key)

        respx.post("https://rotation.com/api/test").mock(
            return_value=Response(200, json={"ok": True})
        )

        keys_used = []
        for _ in range(10):
            response = client.post(
                "/proxy/test",
                headers={TARGET_SERVICE_HEADER: "rotation-svc"},
                json={}
            )
            assert response.status_code == 200
            
            key_info = await manager.get_keys("rotation-svc", "rot-model")
            for k in key_info:
                if k.usage_today > 0 and k.key_preview not in keys_used:
                    full_key = [key for key in keys_added if key.startswith(k.key_preview[:8])][0]
                    keys_used.append(full_key)
                    break

        assert len(keys_used) >= 3

    @pytest.mark.asyncio
    async def test_rate_limit_exhaustion_and_recovery(self, client: TestClient, admin_headers: dict, manager):
        await manager.add_service("limit-svc", "https://limit.com/api", "limit-model")
        await manager.add_model("limit-svc", "limit-model", KeyLimits(rpd=2))
        await manager.add_key("limit-svc", "limit-model", "limit-key-1")

        key, _ = await manager.get_key("limit-svc", "limit-model")
        await manager.record_usage("limit-svc", "limit-model", key, tokens=10)
        
        key, _ = await manager.get_key("limit-svc", "limit-model")
        await manager.record_usage("limit-svc", "limit-model", key, tokens=10)

        with pytest.raises(Exception):
            await manager.get_key("limit-svc", "limit-model")

        await manager.add_key("limit-svc", "limit-model", "limit-key-2")
        key, _ = await manager.get_key("limit-svc", "limit-model")
        assert key == "limit-key-2"

    @respx.mock
    @pytest.mark.asyncio
    async def test_analytics_accumulation(self, client: TestClient, admin_headers: dict, manager):
        await manager.add_service("analytics-svc", "https://analytics.com/api", "a-model")
        await manager.add_model("analytics-svc", "a-model", KeyLimits())
        await manager.add_key("analytics-svc", "a-model", "a-key-1")

        respx.post("https://analytics.com/api/test").mock(
            return_value=Response(200, json={"usage": {"total_tokens": 100}})
        )

        for _ in range(5):
            client.post(
                "/proxy/test",
                headers={TARGET_SERVICE_HEADER: "analytics-svc"},
                json={}
            )

        analytics = await manager.get_analytics(days=1)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        assert today in analytics
        assert "analytics-svc:a-model" in analytics[today]
        entry = analytics[today]["analytics-svc:a-model"]
        assert entry.requests == 5
        assert entry.tokens == 500

    @respx.mock
    @pytest.mark.asyncio
    async def test_failover_scenario(self, client: TestClient, admin_headers: dict, manager):
        await manager.add_service("failover-svc", "https://failover.com/api", "f-model")
        await manager.add_model("failover-svc", "f-model", KeyLimits())
        await manager.add_key("failover-svc", "f-model", "fail-key-1")
        await manager.add_key("failover-svc", "f-model", "fail-key-2")

        call_count = {"count": 0}
        
        def side_effect(request):
            call_count["count"] += 1
            if call_count["count"] == 1:
                return Response(429, json={"error": "rate limited"})
            return Response(200, json={"success": True})

        respx.post("https://failover.com/api/test").mock(side_effect=side_effect)

        response = client.post(
            "/proxy/test",
            headers={TARGET_SERVICE_HEADER: "failover-svc"},
            json={}
        )
        assert response.status_code == 200
        assert call_count["count"] >= 2


class TestPersistence:
    @pytest.mark.asyncio
    async def test_persistence_across_restarts(self, temp_data_file: str):
        mgr1 = ApiKeyManager(data_file=temp_data_file)
        await mgr1.add_service("persist-svc", "https://persist.com/api")
        await mgr1.add_model("persist-svc", "persist-model")
        await mgr1.add_key("persist-svc", "persist-model", "persist-key-123")

        del mgr1

        mgr2 = ApiKeyManager(data_file=temp_data_file)
        services = await mgr2.get_services()
        assert len(services) == 1
        assert services[0].name == "persist-svc"
        
        keys = await mgr2.get_keys("persist-svc", "persist-model")
        assert len(keys) == 1

    @pytest.mark.asyncio
    async def test_usage_persists(self, temp_data_file: str):
        mgr1 = ApiKeyManager(data_file=temp_data_file)
        await mgr1.add_service("usage-svc", "https://usage.com/api")
        await mgr1.add_model("usage-svc", "usage-model")
        await mgr1.add_key("usage-svc", "usage-model", "usage-key")
        
        key, _ = await mgr1.get_key("usage-svc", "usage-model")
        await mgr1.record_usage("usage-svc", "usage-model", key, tokens=100)

        del mgr1

        mgr2 = ApiKeyManager(data_file=temp_data_file)
        keys = await mgr2.get_keys("usage-svc", "usage-model")
        assert keys[0].usage_today == 0
        assert keys[0].tokens_today == 0

    @pytest.mark.asyncio
    async def test_concurrent_managers_same_file(self, temp_data_file: str):
        import asyncio

        results = {"success": 0, "errors": []}

        async def create_service(manager_instance, svc_name):
            try:
                await asyncio.sleep(0.01)
                await manager_instance.add_service(svc_name, f"https://{svc_name}.com/api")
                results["success"] += 1
            except Exception as e:
                results["errors"].append(str(e))

        mgr = ApiKeyManager(data_file=temp_data_file)
        
        tasks = []
        for i in range(3):
            task = create_service(mgr, f"svc-{i}")
            tasks.append(task)
        
        await asyncio.gather(*tasks, return_exceptions=True)

    @pytest.mark.asyncio
    async def test_graceful_degradation(self, corrupted_data_file: str):
        mgr = ApiKeyManager(data_file=corrupted_data_file)
        assert mgr.data is not None
        assert mgr.data.services == {}


class TestEdgeCases:
    @pytest.mark.asyncio
    async def test_service_with_no_models(self, manager: ApiKeyManager):
        await manager.add_service("no-models", "https://none.com/api")
        
        with pytest.raises(Exception):
            await manager.get_key("no-models")

    @pytest.mark.asyncio
    async def test_model_with_no_keys(self, manager: ApiKeyManager):
        await manager.add_service("no-keys", "https://none.com/api")
        await manager.add_model("no-keys", "empty-model")
        
        with pytest.raises(Exception):
            await manager.get_key("no-keys", "empty-model")

    @pytest.mark.asyncio
    async def test_remove_default_model_updates(self, manager: ApiKeyManager):
        await manager.add_service("default-svc", "https://default.com/api", "model-a")
        await manager.add_model("default-svc", "model-a")
        await manager.add_model("default-svc", "model-b")
        
        svc = await manager.get_service("default-svc")
        assert svc.default_model == "model-a"
        
        await manager.remove_model("default-svc", "model-a")
        
        svc = await manager.get_service("default-svc")
        assert svc.default_model == "model-b"

    @pytest.mark.asyncio
    async def test_special_characters_in_keys(self, manager: ApiKeyManager):
        await manager.add_service("special-svc", "https://special.com/api")
        await manager.add_model("special-svc", "special-model")
        
        special_key = "sk-proj-abc123DEF456-xyz789"
        await manager.add_key("special-svc", "special-model", special_key)
        
        key, _ = await manager.get_key("special-svc", "special-model")
        assert key == special_key

    @pytest.mark.asyncio
    async def test_unicode_in_service_names(self, manager: ApiKeyManager):
        await manager.add_service("test-服务", "https://unicode.com/api")
        services = await manager.get_services()
        assert any(s.name == "test-服务" for s in services)

    @respx.mock
    @pytest.mark.asyncio
    async def test_empty_response_body(self, client: TestClient, sample_service: dict):
        respx.post("https://api.test.com/v1/test").mock(
            return_value=Response(204)
        )
        
        headers = {TARGET_SERVICE_HEADER: "test-service"}
        response = client.post("/proxy/test", headers=headers, json={})
        assert response.status_code == 204

    @pytest.mark.asyncio
    async def test_multiple_models_per_service(self, manager: ApiKeyManager):
        await manager.add_service("multi-model", "https://multi.com/api", "model-1")
        
        for i in range(5):
            await manager.add_model("multi-model", f"model-{i}")
            await manager.add_key("multi-model", f"model-{i}", f"key-{i}")
        
        models = await manager.get_models("multi-model")
        assert len(models) == 5
        
        for i in range(5):
            key, model = await manager.get_key("multi-model", f"model-{i}")
            assert model == f"model-{i}"
            assert key == f"key-{i}"


class TestCleanup:
    @pytest.mark.asyncio
    async def test_timestamp_cleanup(self, manager: ApiKeyManager):
        await manager.add_service("cleanup-svc", "https://cleanup.com/api")
        await manager.add_model("cleanup-svc", "cleanup-model", KeyLimits(rpm=10))
        await manager.add_key("cleanup-svc", "cleanup-model", "cleanup-key")
        
        for _ in range(5):
            key, _ = await manager.get_key("cleanup-svc", "cleanup-model")
            await manager.record_usage("cleanup-svc", "cleanup-model", key, tokens=10)
        
        assert len(manager._key_timestamps.get("cleanup-key", [])) == 5
        
        manager._key_timestamps["cleanup-key"] = [0.0, 0.0, 0.0, 0.0, 0.0]
        
        manager._cleanup_timestamps()
        
        assert len(manager._key_timestamps.get("cleanup-key", [])) == 0

    @pytest.mark.asyncio
    async def test_cooldown_cleanup(self, manager: ApiKeyManager):
        await manager.add_service("cooldown-svc", "https://cooldown.com/api")
        await manager.add_model("cooldown-svc", "cooldown-model")
        await manager.add_key("cooldown-svc", "cooldown-model", "cooldown-key")
        
        await manager.mark_key_cooldown("cooldown-svc", "cooldown-model", "cooldown-key", seconds=1)
        assert "cooldown-key" in manager._key_cooldowns
        
        time.sleep(1.1)
        manager._cleanup_timestamps()
        
        assert "cooldown-key" not in manager._key_cooldowns
