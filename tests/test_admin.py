import pytest
import pytest_asyncio
from fastapi.testclient import TestClient

from core.models import KeyLimits


class TestAdminAuth:
    @pytest.mark.asyncio
    async def test_admin_valid_token(self, client: TestClient, admin_headers: dict):
        response = client.get("/admin/services", headers=admin_headers)
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_admin_invalid_token(self, client: TestClient):
        headers = {"X-Admin-Token": "wrong-token"}
        response = client.get("/admin/services", headers=headers)
        assert response.status_code == 401

    @pytest.mark.asyncio
    async def test_admin_missing_token(self, client: TestClient):
        response = client.get("/admin/services")
        assert response.status_code == 401


class TestServiceEndpoints:
    @pytest.mark.asyncio
    async def test_list_services_empty(self, client: TestClient, admin_headers: dict):
        response = client.get("/admin/services", headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        assert "services" in data
        assert data["services"] == []

    @pytest.mark.asyncio
    async def test_list_services_with_data(self, client: TestClient, admin_headers: dict, sample_service: dict):
        response = client.get("/admin/services", headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        assert len(data["services"]) == 1
        assert data["services"][0]["name"] == "test-service"

    @pytest.mark.asyncio
    async def test_get_service(self, client: TestClient, admin_headers: dict, sample_service: dict):
        response = client.get("/admin/services/test-service", headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "test-service"
        assert data["base_url"] == "https://api.test.com/v1"
        assert "default-model" in data["models"]

    @pytest.mark.asyncio
    async def test_get_service_not_found(self, client: TestClient, admin_headers: dict):
        response = client.get("/admin/services/nonexistent", headers=admin_headers)
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_create_service(self, client: TestClient, admin_headers: dict):
        payload = {"name": "new-service", "base_url": "https://new.com/api"}
        response = client.post("/admin/services", json=payload, headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "created"
        assert data["service"] == "new-service"

    @pytest.mark.asyncio
    async def test_create_service_with_default_model(self, client: TestClient, admin_headers: dict):
        payload = {
            "name": "service-with-default",
            "base_url": "https://test.com/api",
            "default_model": "gpt-4"
        }
        response = client.post("/admin/services", json=payload, headers=admin_headers)
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_create_duplicate_service(self, client: TestClient, admin_headers: dict, sample_service: dict):
        payload = {"name": "test-service", "base_url": "https://other.com/api"}
        response = client.post("/admin/services", json=payload, headers=admin_headers)
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_delete_service(self, client: TestClient, admin_headers: dict, sample_service: dict):
        response = client.delete("/admin/services/test-service", headers=admin_headers)
        assert response.status_code == 200
        assert response.json()["status"] == "deleted"

    @pytest.mark.asyncio
    async def test_delete_service_not_found(self, client: TestClient, admin_headers: dict):
        response = client.delete("/admin/services/nonexistent", headers=admin_headers)
        assert response.status_code == 404


class TestModelEndpoints:
    @pytest.mark.asyncio
    async def test_list_models(self, client: TestClient, admin_headers: dict, sample_service: dict):
        response = client.get("/admin/services/test-service/models", headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "test-service"
        assert len(data["models"]) == 2

    @pytest.mark.asyncio
    async def test_list_models_service_not_found(self, client: TestClient, admin_headers: dict):
        response = client.get("/admin/services/nonexistent/models", headers=admin_headers)
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_get_model(self, client: TestClient, admin_headers: dict, sample_service: dict):
        response = client.get(
            "/admin/services/test-service/models/default-model",
            headers=admin_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "default-model"
        assert data["limits"]["rpm"] == 10
        assert data["key_count"] == 3

    @pytest.mark.asyncio
    async def test_get_model_not_found(self, client: TestClient, admin_headers: dict, sample_service: dict):
        response = client.get(
            "/admin/services/test-service/models/nonexistent",
            headers=admin_headers
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_create_model(self, client: TestClient, admin_headers: dict, sample_service: dict):
        payload = {"name": "new-model", "limits": {"rpm": 50, "rpd": 500}}
        response = client.post(
            "/admin/services/test-service/models",
            json=payload,
            headers=admin_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "created"
        assert data["model"] == "new-model"

    @pytest.mark.asyncio
    async def test_create_model_no_limits(self, client: TestClient, admin_headers: dict, sample_service: dict):
        payload = {"name": "no-limits-model"}
        response = client.post(
            "/admin/services/test-service/models",
            json=payload,
            headers=admin_headers
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_create_duplicate_model(self, client: TestClient, admin_headers: dict, sample_service: dict):
        payload = {"name": "default-model"}
        response = client.post(
            "/admin/services/test-service/models",
            json=payload,
            headers=admin_headers
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_delete_model(self, client: TestClient, admin_headers: dict, sample_service: dict):
        response = client.delete(
            "/admin/services/test-service/models/other-model",
            headers=admin_headers
        )
        assert response.status_code == 200
        assert response.json()["status"] == "deleted"

    @pytest.mark.asyncio
    async def test_delete_model_not_found(self, client: TestClient, admin_headers: dict, sample_service: dict):
        response = client.delete(
            "/admin/services/test-service/models/nonexistent",
            headers=admin_headers
        )
        assert response.status_code == 404


class TestKeyEndpoints:
    @pytest.mark.asyncio
    async def test_list_keys(self, client: TestClient, admin_headers: dict, sample_service: dict):
        response = client.get(
            "/admin/services/test-service/models/default-model/keys",
            headers=admin_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["service"] == "test-service"
        assert data["model"] == "default-model"
        assert len(data["keys"]) == 3

    @pytest.mark.asyncio
    async def test_list_keys_model_not_found(self, client: TestClient, admin_headers: dict, sample_service: dict):
        response = client.get(
            "/admin/services/test-service/models/nonexistent/keys",
            headers=admin_headers
        )
        assert response.status_code == 404

    @pytest.mark.asyncio
    async def test_add_key(self, client: TestClient, admin_headers: dict, sample_service: dict):
        payload = {"api_key": "sk-new-test-key-123"}
        response = client.post(
            "/admin/services/test-service/models/default-model/keys",
            json=payload,
            headers=admin_headers
        )
        assert response.status_code == 200
        assert response.json()["status"] == "created"

    @pytest.mark.asyncio
    async def test_add_key_duplicate(self, client: TestClient, admin_headers: dict, sample_service: dict):
        payload = {"api_key": "key-aaa111"}
        response = client.post(
            "/admin/services/test-service/models/default-model/keys",
            json=payload,
            headers=admin_headers
        )
        assert response.status_code == 400

    @pytest.mark.asyncio
    async def test_remove_key_exact(self, client: TestClient, admin_headers: dict, sample_service: dict):
        response = client.delete(
            "/admin/services/test-service/models/default-model/keys/key-aaa111",
            headers=admin_headers
        )
        assert response.status_code == 200
        assert response.json()["status"] == "deleted"

    @pytest.mark.asyncio
    async def test_remove_key_not_found(self, client: TestClient, admin_headers: dict, sample_service: dict):
        response = client.delete(
            "/admin/services/test-service/models/default-model/keys/nonexistent-key",
            headers=admin_headers
        )
        assert response.status_code == 404


class TestLimitsEndpoints:
    @pytest.mark.asyncio
    async def test_update_limits_partial(self, client: TestClient, admin_headers: dict, sample_service: dict):
        payload = {"rpm": 999}
        response = client.patch(
            "/admin/services/test-service/models/default-model/limits",
            json=payload,
            headers=admin_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["limits"]["rpm"] == 999

    @pytest.mark.asyncio
    async def test_update_limits_all(self, client: TestClient, admin_headers: dict, sample_service: dict):
        payload = {"rpm": 100, "rpd": 1000, "tpm": 10000, "tpd": 100000}
        response = client.patch(
            "/admin/services/test-service/models/default-model/limits",
            json=payload,
            headers=admin_headers
        )
        assert response.status_code == 200
        data = response.json()
        assert data["limits"]["rpm"] == 100
        assert data["limits"]["rpd"] == 1000
        assert data["limits"]["tpm"] == 10000
        assert data["limits"]["tpd"] == 100000

    @pytest.mark.asyncio
    async def test_update_limits_model_not_found(self, client: TestClient, admin_headers: dict, sample_service: dict):
        payload = {"rpm": 100}
        response = client.patch(
            "/admin/services/test-service/models/nonexistent/limits",
            json=payload,
            headers=admin_headers
        )
        assert response.status_code == 404


class TestAnalyticsEndpoint:
    @pytest.mark.asyncio
    async def test_get_analytics(self, client: TestClient, admin_headers: dict):
        response = client.get("/admin/analytics?days=7", headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        assert "days" in data
        assert data["days"] == 7
        assert "analytics" in data

    @pytest.mark.asyncio
    async def test_get_analytics_with_data(
        self, 
        client: TestClient, 
        admin_headers: dict, 
        sample_service: dict,
        manager
    ):
        key, model = await manager.get_key("test-service", "default-model")
        await manager.record_usage("test-service", model, key, tokens=100)
        
        response = client.get("/admin/analytics?days=1", headers=admin_headers)
        assert response.status_code == 200


class TestStatusEndpoint:
    @pytest.mark.asyncio
    async def test_get_status_empty(self, client: TestClient, admin_headers: dict):
        response = client.get("/admin/status", headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["services_count"] == 0
        assert data["total_keys"] == 0
        assert data["available_keys"] == 0

    @pytest.mark.asyncio
    async def test_get_status_with_data(self, client: TestClient, admin_headers: dict, sample_service: dict):
        response = client.get("/admin/status", headers=admin_headers)
        assert response.status_code == 200
        data = response.json()
        assert data["services_count"] == 1
        assert data["total_keys"] == 3
        assert data["available_keys"] == 3


class TestAnalyticsDaysValidation:
    @pytest.mark.asyncio
    async def test_analytics_days_too_high(self, client: TestClient, admin_headers: dict):
        response = client.get("/admin/analytics?days=100", headers=admin_headers)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_analytics_days_too_low(self, client: TestClient, admin_headers: dict):
        response = client.get("/admin/analytics?days=0", headers=admin_headers)
        assert response.status_code == 422


class TestServiceErrors:
    @pytest.mark.asyncio
    async def test_add_service_missing_fields(self, client: TestClient, admin_headers: dict):
        response = client.post("/admin/services", json={}, headers=admin_headers)
        assert response.status_code == 422

    @pytest.mark.asyncio
    async def test_add_key_missing_api_key(self, client: TestClient, admin_headers: dict, sample_service: dict):
        response = client.post(
            "/admin/services/test-service/models/default-model/keys",
            json={},
            headers=admin_headers
        )
        assert response.status_code == 422


class TestHealthEndpoint:
    @pytest.mark.asyncio
    async def test_health_endpoint(self, client: TestClient):
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json()["status"] == "healthy"


class TestRootEndpoint:
    @pytest.mark.asyncio
    async def test_root_endpoint(self, client: TestClient):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "API Key Manager"
        assert "version" in data
        assert "endpoints" in data


class TestAdminManagerNotInitialized:
    @pytest.mark.asyncio
    async def test_admin_manager_not_initialized(self, manager):
        from fastapi.testclient import TestClient
        from server import app
        from routes import admin
        
        with TestClient(app, raise_server_exceptions=False) as test_client:
            admin.manager = None
            response = test_client.get("/admin/services", headers={"X-Admin-Token": "test"})
            assert response.status_code == 500
            assert "Manager not initialized" in response.text


class TestAdminGenericExceptions:
    @pytest.mark.asyncio
    async def test_list_services_generic_error(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.get_services = AsyncMock(side_effect=RuntimeError("Unexpected error"))
        admin.manager = mock_manager
        
        try:
            response = client.get("/admin/services", headers=admin_headers)
            assert response.status_code == 500
        finally:
            admin.manager = original_manager
    
    @pytest.mark.asyncio
    async def test_get_service_generic_error(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.get_service = AsyncMock(side_effect=RuntimeError("Unexpected error"))
        admin.manager = mock_manager
        
        try:
            response = client.get("/admin/services/test", headers=admin_headers)
            assert response.status_code == 500
        finally:
            admin.manager = original_manager
    
    @pytest.mark.asyncio
    async def test_add_service_generic_error(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.add_service = AsyncMock(side_effect=RuntimeError("Unexpected error"))
        admin.manager = mock_manager
        
        try:
            response = client.post("/admin/services", json={"name": "test", "base_url": "https://test.com"}, headers=admin_headers)
            assert response.status_code == 500
        finally:
            admin.manager = original_manager
    
    @pytest.mark.asyncio
    async def test_remove_service_generic_error(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.remove_service = AsyncMock(side_effect=RuntimeError("Unexpected error"))
        admin.manager = mock_manager
        
        try:
            response = client.delete("/admin/services/test", headers=admin_headers)
            assert response.status_code == 500
        finally:
            admin.manager = original_manager
    
    @pytest.mark.asyncio
    async def test_list_models_generic_error(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.get_models = AsyncMock(side_effect=RuntimeError("Unexpected error"))
        admin.manager = mock_manager
        
        try:
            response = client.get("/admin/services/test/models", headers=admin_headers)
            assert response.status_code == 500
        finally:
            admin.manager = original_manager
    
    @pytest.mark.asyncio
    async def test_get_model_generic_error(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.get_model_info = AsyncMock(side_effect=RuntimeError("Unexpected error"))
        admin.manager = mock_manager
        
        try:
            response = client.get("/admin/services/test/models/model", headers=admin_headers)
            assert response.status_code == 500
        finally:
            admin.manager = original_manager
    
    @pytest.mark.asyncio
    async def test_add_model_generic_error(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.add_model = AsyncMock(side_effect=RuntimeError("Unexpected error"))
        admin.manager = mock_manager
        
        try:
            response = client.post("/admin/services/test/models", json={"name": "model"}, headers=admin_headers)
            assert response.status_code == 500
        finally:
            admin.manager = original_manager
    
    @pytest.mark.asyncio
    async def test_remove_model_generic_error(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.remove_model = AsyncMock(side_effect=RuntimeError("Unexpected error"))
        admin.manager = mock_manager
        
        try:
            response = client.delete("/admin/services/test/models/model", headers=admin_headers)
            assert response.status_code == 500
        finally:
            admin.manager = original_manager
    
    @pytest.mark.asyncio
    async def test_update_limits_generic_error(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.update_limits = AsyncMock(side_effect=RuntimeError("Unexpected error"))
        admin.manager = mock_manager
        
        try:
            response = client.patch("/admin/services/test/models/model/limits", json={"rpm": 100}, headers=admin_headers)
            assert response.status_code == 500
        finally:
            admin.manager = original_manager
    
    @pytest.mark.asyncio
    async def test_list_keys_generic_error(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.get_keys = AsyncMock(side_effect=RuntimeError("Unexpected error"))
        admin.manager = mock_manager
        
        try:
            response = client.get("/admin/services/test/models/model/keys", headers=admin_headers)
            assert response.status_code == 500
        finally:
            admin.manager = original_manager
    
    @pytest.mark.asyncio
    async def test_add_key_generic_error(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.add_key = AsyncMock(side_effect=RuntimeError("Unexpected error"))
        admin.manager = mock_manager
        
        try:
            response = client.post("/admin/services/test/models/model/keys", json={"api_key": "test"}, headers=admin_headers)
            assert response.status_code == 500
        finally:
            admin.manager = original_manager
    
    @pytest.mark.asyncio
    async def test_remove_key_generic_error(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.remove_key = AsyncMock(side_effect=RuntimeError("Unexpected error"))
        admin.manager = mock_manager
        
        try:
            response = client.delete("/admin/services/test/models/model/keys/key", headers=admin_headers)
            assert response.status_code == 500
        finally:
            admin.manager = original_manager
    
    @pytest.mark.asyncio
    async def test_get_analytics_generic_error(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.get_analytics = AsyncMock(side_effect=RuntimeError("Unexpected error"))
        admin.manager = mock_manager
        
        try:
            response = client.get("/admin/analytics", headers=admin_headers)
            assert response.status_code == 500
        finally:
            admin.manager = original_manager
    
    @pytest.mark.asyncio
    async def test_get_status_generic_error(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.get_services = AsyncMock(side_effect=RuntimeError("Unexpected error"))
        admin.manager = mock_manager
        
        try:
            response = client.get("/admin/status", headers=admin_headers)
            assert response.status_code == 500
        finally:
            admin.manager = original_manager


class TestGetModelServiceNotFoundError:
    @pytest.mark.asyncio
    async def test_get_model_service_not_found(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        from core.exceptions import ServiceNotFoundError
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.get_model_info = AsyncMock(side_effect=ServiceNotFoundError("Service not found"))
        admin.manager = mock_manager
        
        try:
            response = client.get("/admin/services/test/models/model", headers=admin_headers)
            assert response.status_code == 404
        finally:
            admin.manager = original_manager


class TestAddModelServiceNotFoundError:
    @pytest.mark.asyncio
    async def test_add_model_service_not_found(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        from core.exceptions import ServiceNotFoundError
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.add_model = AsyncMock(side_effect=ServiceNotFoundError("Service not found"))
        admin.manager = mock_manager
        
        try:
            response = client.post("/admin/services/test/models", json={"name": "model"}, headers=admin_headers)
            assert response.status_code == 404
        finally:
            admin.manager = original_manager


class TestRemoveModelServiceNotFoundError:
    @pytest.mark.asyncio
    async def test_remove_model_service_not_found(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        from core.exceptions import ServiceNotFoundError
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.remove_model = AsyncMock(side_effect=ServiceNotFoundError("Service not found"))
        admin.manager = mock_manager
        
        try:
            response = client.delete("/admin/services/test/models/model", headers=admin_headers)
            assert response.status_code == 404
        finally:
            admin.manager = original_manager


class TestUpdateLimitsServiceNotFoundError:
    @pytest.mark.asyncio
    async def test_update_limits_service_not_found(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        from core.exceptions import ServiceNotFoundError
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.update_limits = AsyncMock(side_effect=ServiceNotFoundError("Service not found"))
        admin.manager = mock_manager
        
        try:
            response = client.patch("/admin/services/test/models/model/limits", json={"rpm": 100}, headers=admin_headers)
            assert response.status_code == 404
        finally:
            admin.manager = original_manager


class TestListKeysServiceNotFoundError:
    @pytest.mark.asyncio
    async def test_list_keys_service_not_found(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        from core.exceptions import ServiceNotFoundError
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.get_keys = AsyncMock(side_effect=ServiceNotFoundError("Service not found"))
        admin.manager = mock_manager
        
        try:
            response = client.get("/admin/services/test/models/model/keys", headers=admin_headers)
            assert response.status_code == 404
        finally:
            admin.manager = original_manager


class TestAddKeyServiceNotFoundError:
    @pytest.mark.asyncio
    async def test_add_key_service_not_found(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        from core.exceptions import ServiceNotFoundError
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.add_key = AsyncMock(side_effect=ServiceNotFoundError("Service not found"))
        admin.manager = mock_manager
        
        try:
            response = client.post("/admin/services/test/models/model/keys", json={"api_key": "test"}, headers=admin_headers)
            assert response.status_code == 404
        finally:
            admin.manager = original_manager


class TestAddKeyModelNotFoundError:
    @pytest.mark.asyncio
    async def test_add_key_model_not_found(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        from core.exceptions import ModelNotFoundError
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.add_key = AsyncMock(side_effect=ModelNotFoundError("Model not found"))
        admin.manager = mock_manager
        
        try:
            response = client.post("/admin/services/test/models/model/keys", json={"api_key": "test"}, headers=admin_headers)
            assert response.status_code == 404
        finally:
            admin.manager = original_manager


class TestRemoveKeyServiceNotFoundError:
    @pytest.mark.asyncio
    async def test_remove_key_service_not_found(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        from core.exceptions import ServiceNotFoundError
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.remove_key = AsyncMock(side_effect=ServiceNotFoundError("Service not found"))
        admin.manager = mock_manager
        
        try:
            response = client.delete("/admin/services/test/models/model/keys/key", headers=admin_headers)
            assert response.status_code == 404
        finally:
            admin.manager = original_manager


class TestRemoveKeyModelNotFoundError:
    @pytest.mark.asyncio
    async def test_remove_key_model_not_found(self, client: TestClient, admin_headers: dict):
        from routes import admin
        from unittest.mock import AsyncMock, MagicMock
        from core.exceptions import ModelNotFoundError
        
        original_manager = admin.manager
        mock_manager = MagicMock()
        mock_manager.verify_admin_token = MagicMock(return_value=True)
        mock_manager.remove_key = AsyncMock(side_effect=ModelNotFoundError("Model not found"))
        admin.manager = mock_manager
        
        try:
            response = client.delete("/admin/services/test/models/model/keys/key", headers=admin_headers)
            assert response.status_code == 404
        finally:
            admin.manager = original_manager
