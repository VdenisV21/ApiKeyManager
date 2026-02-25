import os
import json
import time
import pytest
import pytest_asyncio
from datetime import datetime, timezone

from core.manager import ApiKeyManager
from core.models import KeyLimits
from core.exceptions import (
    ApiKeyManagerError,
    NoAvailableKeyError,
    ServiceNotFoundError,
    ModelNotFoundError,
    KeyNotFoundError,
    AuthenticationError,
)


class TestPersistence:
    @pytest.mark.asyncio
    async def test_init_creates_new_file(self, temp_data_file: str):
        assert not os.path.exists(temp_data_file) or os.path.getsize(temp_data_file) == 2
        mgr = ApiKeyManager(data_file=temp_data_file)
        assert os.path.exists(temp_data_file)
        with open(temp_data_file, 'r') as f:
            data = json.load(f)
        assert "admin_token" in data
        assert "services" in data
        assert "analytics" in data

    @pytest.mark.asyncio
    async def test_init_loads_existing_file(self, pre_existing_data_file: str):
        mgr = ApiKeyManager(data_file=pre_existing_data_file)
        assert mgr.data.admin_token == "pre-existing-token"
        assert "preloaded-service" in mgr.data.services
        services = await mgr.get_services()
        assert len(services) == 1
        assert services[0].name == "preloaded-service"

    @pytest.mark.asyncio
    async def test_save_persists_changes(self, manager: ApiKeyManager):
        await manager.add_service("new-service", "https://new.com/api")
        
        with open(manager.data_file, 'r') as f:
            data = json.load(f)
        
        assert "new-service" in data["services"]
        assert data["services"]["new-service"]["base_url"] == "https://new.com/api"

    @pytest.mark.asyncio
    async def test_corrupted_file_handling(self, corrupted_data_file: str):
        mgr = ApiKeyManager(data_file=corrupted_data_file)
        assert mgr.data is not None
        assert mgr.data.admin_token == "change-me"
        assert mgr.data.services == {}


class TestServiceCRUD:
    @pytest.mark.asyncio
    async def test_add_service(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api")
        services = await manager.get_services()
        assert len(services) == 1
        assert services[0].name == "test-svc"
        assert services[0].base_url == "https://test.com/api"

    @pytest.mark.asyncio
    async def test_add_service_with_default_model(self, manager: ApiKeyManager):
        await manager.add_service("svc-with-default", "https://test.com/api", "gpt-4")
        svc = await manager.get_service("svc-with-default")
        assert svc.default_model == "gpt-4"

    @pytest.mark.asyncio
    async def test_add_duplicate_service_error(self, manager: ApiKeyManager):
        await manager.add_service("duplicate", "https://test.com/api")
        with pytest.raises(ApiKeyManagerError, match="already exists"):
            await manager.add_service("duplicate", "https://other.com/api")

    @pytest.mark.asyncio
    async def test_remove_service(self, manager: ApiKeyManager):
        await manager.add_service("to-remove", "https://test.com/api")
        await manager.remove_service("to-remove")
        services = await manager.get_services()
        assert not any(s.name == "to-remove" for s in services)

    @pytest.mark.asyncio
    async def test_remove_nonexistent_service_error(self, manager: ApiKeyManager):
        with pytest.raises(ServiceNotFoundError):
            await manager.remove_service("nonexistent")

    @pytest.mark.asyncio
    async def test_get_service(self, manager: ApiKeyManager):
        await manager.add_service("get-test", "https://test.com/api", "model-1")
        svc = await manager.get_service("get-test")
        assert svc.name == "get-test"
        assert svc.base_url == "https://test.com/api"
        assert svc.default_model == "model-1"


class TestModelCRUD:
    @pytest.mark.asyncio
    async def test_add_model(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api")
        await manager.add_model("test-svc", "new-model", KeyLimits(rpm=100, rpd=1000))
        models = await manager.get_models("test-svc")
        assert len(models) == 1
        assert models[0].name == "new-model"
        assert models[0].limits.rpm == 100
        assert models[0].limits.rpd == 1000

    @pytest.mark.asyncio
    async def test_add_model_no_limits(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api")
        await manager.add_model("test-svc", "no-limits-model")
        info = await manager.get_model_info("test-svc", "no-limits-model")
        assert info.limits.rpm is None
        assert info.limits.rpd is None

    @pytest.mark.asyncio
    async def test_add_duplicate_model_error(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api")
        await manager.add_model("test-svc", "dup-model")
        with pytest.raises(ApiKeyManagerError, match="already exists"):
            await manager.add_model("test-svc", "dup-model")

    @pytest.mark.asyncio
    async def test_remove_model(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api")
        await manager.add_model("test-svc", "to-remove")
        await manager.remove_model("test-svc", "to-remove")
        models = await manager.get_models("test-svc")
        assert not any(m.name == "to-remove" for m in models)

    @pytest.mark.asyncio
    async def test_remove_model_updates_default(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api", "model-a")
        await manager.add_model("test-svc", "model-a")
        await manager.add_model("test-svc", "model-b")
        await manager.remove_model("test-svc", "model-a")
        svc = await manager.get_service("test-svc")
        assert svc.default_model == "model-b"

    @pytest.mark.asyncio
    async def test_get_models(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api")
        await manager.add_model("test-svc", "model-1")
        await manager.add_model("test-svc", "model-2")
        models = await manager.get_models("test-svc")
        names = [m.name for m in models]
        assert "model-1" in names
        assert "model-2" in names


class TestKeyCRUD:
    @pytest.mark.asyncio
    async def test_add_key(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api")
        await manager.add_model("test-svc", "test-model")
        await manager.add_key("test-svc", "test-model", "sk-test-key-123")
        keys = await manager.get_keys("test-svc", "test-model")
        assert len(keys) == 1
        assert "..." in keys[0].key_preview
        assert keys[0].key_preview.endswith("-123")

    @pytest.mark.asyncio
    async def test_add_duplicate_key_error(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api")
        await manager.add_model("test-svc", "test-model")
        await manager.add_key("test-svc", "test-model", "sk-duplicate")
        with pytest.raises(ApiKeyManagerError, match="already exists"):
            await manager.add_key("test-svc", "test-model", "sk-duplicate")

    @pytest.mark.asyncio
    async def test_remove_key_exact(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api")
        await manager.add_model("test-svc", "test-model")
        await manager.add_key("test-svc", "test-model", "sk-exact-key")
        await manager.remove_key("test-svc", "test-model", "sk-exact-key")
        keys = await manager.get_keys("test-svc", "test-model")
        assert len(keys) == 0

    @pytest.mark.asyncio
    async def test_remove_key_prefix(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api")
        await manager.add_model("test-svc", "test-model")
        await manager.add_key("test-svc", "test-model", "prefix-key-1")
        await manager.add_key("test-svc", "test-model", "prefix-key-2")
        await manager.add_key("test-svc", "test-model", "other-key")
        await manager.remove_key("test-svc", "test-model", "prefix-")
        keys = await manager.get_keys("test-svc", "test-model")
        assert len(keys) == 1
        assert "other-k" in keys[0].key_preview

    @pytest.mark.asyncio
    async def test_remove_nonexistent_key_error(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api")
        await manager.add_model("test-svc", "test-model")
        with pytest.raises(KeyNotFoundError):
            await manager.remove_key("test-svc", "test-model", "nonexistent")


class TestKeyRotation:
    @pytest.mark.asyncio
    async def test_get_key_returns_available(self, sample_service: dict, manager: ApiKeyManager):
        key, model = await manager.get_key("test-service", "default-model")
        assert key.startswith("key-")
        assert model == "default-model"

    @pytest.mark.asyncio
    async def test_rotation_lru_order(self, sample_service: dict, manager: ApiKeyManager):
        keys_used = []
        for _ in range(6):
            key, _ = await manager.get_key("test-service", "default-model")
            keys_used.append(key)
            await manager.record_usage("test-service", "default-model", key, tokens=10)
        
        assert keys_used[0] == keys_used[3]
        assert keys_used[1] == keys_used[4]
        assert keys_used[2] == keys_used[5]
        assert keys_used[0:3] != keys_used[1:4]

    @pytest.mark.asyncio
    async def test_get_key_exhausted_error(self, sample_service: dict, manager: ApiKeyManager):
        for key in sample_service["keys"]:
            for _ in range(50):
                await manager.record_usage("test-service", "default-model", key, tokens=1)
        
        manager.data.services["test-service"].models["default-model"].limits.rpd = 1
        
        with pytest.raises(NoAvailableKeyError):
            await manager.get_key("test-service", "default-model")

    @pytest.mark.asyncio
    async def test_get_key_resolves_default_model(self, sample_service: dict, manager: ApiKeyManager):
        key, model = await manager.get_key("test-service")
        assert model == "default-model"

    @pytest.mark.asyncio
    async def test_get_key_resolves_first_model(self, manager: ApiKeyManager):
        await manager.add_service("no-default", "https://test.com/api")
        await manager.add_model("no-default", "first-model")
        await manager.add_key("no-default", "first-model", "key-1")
        
        key, model = await manager.get_key("no-default")
        assert model == "first-model"


class TestRateLimits:
    @pytest.mark.asyncio
    async def test_rpd_limit(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api")
        await manager.add_model("test-svc", "test-model", KeyLimits(rpd=3))
        await manager.add_key("test-svc", "test-model", "rpd-key")
        
        for _ in range(3):
            key, _ = await manager.get_key("test-svc", "test-model")
            await manager.record_usage("test-svc", "test-model", key)
        
        with pytest.raises(NoAvailableKeyError):
            await manager.get_key("test-svc", "test-model")

    @pytest.mark.asyncio
    async def test_rpm_limit(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api")
        await manager.add_model("test-svc", "test-model", KeyLimits(rpm=2))
        await manager.add_key("test-svc", "test-model", "rpm-key")
        
        for _ in range(2):
            key, _ = await manager.get_key("test-svc", "test-model")
            await manager.record_usage("test-svc", "test-model", key)
        
        with pytest.raises(NoAvailableKeyError):
            await manager.get_key("test-svc", "test-model")

    @pytest.mark.asyncio
    async def test_tpd_limit(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api")
        await manager.add_model("test-svc", "test-model", KeyLimits(tpd=100))
        await manager.add_key("test-svc", "test-model", "tpd-key")
        
        key, _ = await manager.get_key("test-svc", "test-model")
        await manager.record_usage("test-svc", "test-model", key, tokens=60)
        
        key, _ = await manager.get_key("test-svc", "test-model")
        await manager.record_usage("test-svc", "test-model", key, tokens=50)
        
        with pytest.raises(NoAvailableKeyError):
            await manager.get_key("test-svc", "test-model")

    @pytest.mark.asyncio
    async def test_tpm_limit(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api")
        await manager.add_model("test-svc", "test-model", KeyLimits(tpm=50))
        await manager.add_key("test-svc", "test-model", "tpm-key")
        
        key, _ = await manager.get_key("test-svc", "test-model")
        await manager.record_usage("test-svc", "test-model", key, tokens=30)
        
        key, _ = await manager.get_key("test-svc", "test-model")
        await manager.record_usage("test-svc", "test-model", key, tokens=30)
        
        with pytest.raises(NoAvailableKeyError):
            await manager.get_key("test-svc", "test-model")

    @pytest.mark.asyncio
    async def test_no_limits(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api")
        await manager.add_model("test-svc", "test-model", KeyLimits())
        await manager.add_key("test-svc", "test-model", "unlimited-key")
        
        for _ in range(100):
            key, _ = await manager.get_key("test-svc", "test-model")
            await manager.record_usage("test-svc", "test-model", key, tokens=1000)
        
        key, _ = await manager.get_key("test-svc", "test-model")
        assert key == "unlimited-key"

    @pytest.mark.asyncio
    async def test_record_usage_updates_counters(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api")
        await manager.add_model("test-svc", "test-model")
        await manager.add_key("test-svc", "test-model", "counter-key")
        
        key, _ = await manager.get_key("test-svc", "test-model")
        await manager.record_usage("test-svc", "test-model", key, tokens=100)
        
        keys = await manager.get_keys("test-svc", "test-model")
        assert keys[0].usage_today == 1
        assert keys[0].tokens_today == 100


class TestCooldown:
    @pytest.mark.asyncio
    async def test_cooldown_blocks_key(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api")
        await manager.add_model("test-svc", "test-model")
        await manager.add_key("test-svc", "test-model", "cooldown-key")
        
        await manager.mark_key_cooldown("test-svc", "test-model", "cooldown-key", seconds=60)
        
        keys = await manager.get_keys("test-svc", "test-model")
        assert keys[0].is_on_cooldown is True
        assert keys[0].is_usable is False

    @pytest.mark.asyncio
    async def test_cooldown_expires(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api")
        await manager.add_model("test-svc", "test-model")
        await manager.add_key("test-svc", "test-model", "expire-key")
        
        await manager.mark_key_cooldown("test-svc", "test-model", "expire-key", seconds=1)
        time.sleep(1.1)
        manager._cleanup_timestamps()
        
        keys = await manager.get_keys("test-svc", "test-model")
        assert keys[0].is_on_cooldown is False
        assert keys[0].is_usable is True

    @pytest.mark.asyncio
    async def test_mark_key_cooldown(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api")
        await manager.add_model("test-svc", "test-model")
        await manager.add_key("test-svc", "test-model", "manual-cooldown")
        
        await manager.mark_key_cooldown("test-svc", "test-model", "manual-cooldown", seconds=30)
        assert "manual-cooldown" in manager._key_cooldowns


class TestAuth:
    def test_verify_valid_token(self, manager: ApiKeyManager):
        token = manager.data.admin_token
        assert manager.verify_admin_token(token) is True

    def test_verify_invalid_token(self, manager: ApiKeyManager):
        with pytest.raises(AuthenticationError):
            manager.verify_admin_token("wrong-token")


class TestAnalytics:
    @pytest.mark.asyncio
    async def test_record_analytics(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api")
        await manager.add_model("test-svc", "test-model")
        await manager.add_key("test-svc", "test-model", "analytics-key")
        
        key, _ = await manager.get_key("test-svc", "test-model")
        await manager.record_usage("test-svc", "test-model", key, tokens=50)
        
        analytics = await manager.get_analytics(days=1)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        assert today in analytics
        assert "test-svc:test-model" in analytics[today]

    @pytest.mark.asyncio
    async def test_get_analytics(self, manager: ApiKeyManager):
        await manager.add_service("test-svc", "https://test.com/api")
        await manager.add_model("test-svc", "test-model")
        await manager.add_key("test-svc", "test-model", "key-1")
        
        key, _ = await manager.get_key("test-svc", "test-model")
        for _ in range(3):
            await manager.record_usage("test-svc", "test-model", key, tokens=100)
        
        analytics = await manager.get_analytics(days=1)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        entry = analytics[today]["test-svc:test-model"]
        assert entry.requests == 3
        assert entry.tokens == 300

    @pytest.mark.asyncio
    async def test_analytics_multiple_days(self, pre_existing_data_file: str):
        mgr = ApiKeyManager(data_file=pre_existing_data_file)
        analytics = await mgr.get_analytics(days=7)
        assert isinstance(analytics, dict)


class TestGetBaseUrl:
    @pytest.mark.asyncio
    async def test_get_base_url(self, manager: ApiKeyManager):
        await manager.add_service("url-svc", "https://api.example.com/v2")
        url = manager.get_base_url("url-svc")
        assert url == "https://api.example.com/v2"

    @pytest.mark.asyncio
    async def test_get_base_url_service_not_found(self, manager: ApiKeyManager):
        with pytest.raises(ServiceNotFoundError):
            manager.get_base_url("nonexistent")


class TestGetLimits:
    @pytest.mark.asyncio
    async def test_get_limits(self, manager: ApiKeyManager):
        await manager.add_service("limits-svc", "https://test.com/api")
        await manager.add_model("limits-svc", "limits-model", KeyLimits(rpm=100, rpd=1000, tpm=5000, tpd=50000))
        limits = manager._get_limits("limits-svc", "limits-model")
        assert limits.rpm == 100
        assert limits.rpd == 1000
        assert limits.tpm == 5000
        assert limits.tpd == 50000


class TestNewFileCreation:
    @pytest.mark.asyncio
    async def test_creates_new_file_when_missing(self, temp_data_file: str):
        if os.path.exists(temp_data_file):
            os.remove(temp_data_file)
        
        mgr = ApiKeyManager(data_file=temp_data_file)
        
        assert os.path.exists(temp_data_file)
        assert mgr.data is not None
        assert mgr.data.admin_token == "change-me"


class TestMarkKeyCooldownErrors:
    @pytest.mark.asyncio
    async def test_mark_cooldown_key_not_found(self, manager: ApiKeyManager):
        await manager.add_service("cd-svc", "https://test.com/api")
        await manager.add_model("cd-svc", "cd-model")
        
        with pytest.raises(KeyNotFoundError):
            await manager.mark_key_cooldown("cd-svc", "cd-model", "nonexistent-key")


class TestGetAllKeyPreviews:
    @pytest.mark.asyncio
    async def test_get_all_key_previews(self, manager: ApiKeyManager):
        await manager.add_service("preview-svc", "https://test.com/api")
        await manager.add_model("preview-svc", "preview-model")
        await manager.add_key("preview-svc", "preview-model", "key-aaa111")
        await manager.add_key("preview-svc", "preview-model", "key-bbb222")
        
        previews = await manager.get_all_key_previews("preview-svc", "preview-model")
        assert len(previews) == 2
        assert "key-aaa111" in previews
        assert "key-bbb222" in previews


class TestRemoveModelWithKeys:
    @pytest.mark.asyncio
    async def test_remove_model_cleans_up_timestamps(self, manager: ApiKeyManager):
        await manager.add_service("rm-svc", "https://test.com/api")
        await manager.add_model("rm-svc", "rm-model")
        await manager.add_key("rm-svc", "rm-model", "rm-key-1")
        
        key, _ = await manager.get_key("rm-svc", "rm-model")
        await manager.record_usage("rm-svc", "rm-model", key, tokens=100)
        
        assert "rm-key-1" in manager._key_timestamps
        assert "rm-key-1" in manager._key_token_timestamps
        
        await manager.remove_model("rm-svc", "rm-model")
        
        assert "rm-key-1" not in manager._key_timestamps
        assert "rm-key-1" not in manager._key_token_timestamps
        assert "rm-key-1" not in manager._key_cooldowns


class TestTokenTimestampsCleanup:
    @pytest.mark.asyncio
    async def test_token_timestamps_cleanup_removes_old(self, manager: ApiKeyManager):
        await manager.add_service("token-svc", "https://test.com/api")
        await manager.add_model("token-svc", "token-model", KeyLimits(tpm=100))
        await manager.add_key("token-svc", "token-model", "token-key")
        
        key, _ = await manager.get_key("token-svc", "token-model")
        await manager.record_usage("token-svc", "token-model", key, tokens=50)
        
        assert "token-key" in manager._key_token_timestamps
        
        manager._key_token_timestamps["token-key"] = [(0.0, 50)]
        manager._cleanup_timestamps()
        
        assert "token-key" not in manager._key_token_timestamps


class TestCooldownCleanupInCleanupTimestamps:
    @pytest.mark.asyncio
    async def test_cooldown_cleanup_in_cleanup(self, manager: ApiKeyManager):
        await manager.add_service("cdclean-svc", "https://test.com/api")
        await manager.add_model("cdclean-svc", "cdclean-model")
        await manager.add_key("cdclean-svc", "cdclean-model", "cdclean-key")
        
        await manager.mark_key_cooldown("cdclean-svc", "cdclean-model", "cdclean-key", seconds=1)
        assert "cdclean-key" in manager._key_cooldowns
        
        time.sleep(1.1)
        manager._cleanup_timestamps()
        
        assert "cdclean-key" not in manager._key_cooldowns


class TestSaveDataError:
    @pytest.mark.asyncio
    async def test_save_data_permission_error(self, manager: ApiKeyManager):
        await manager.add_service("save-svc", "https://test.com/api")
        
        import unittest.mock
        with unittest.mock.patch('builtins.open', side_effect=PermissionError("No write permission")):
            with pytest.raises(PermissionError):
                await manager.add_service("another-svc", "https://test.com/api2")
    
    @pytest.mark.asyncio
    async def test_save_data_json_dump_error_removes_temp_file(self, manager: ApiKeyManager):
        await manager.add_service("save-svc2", "https://test.com/api")
        
        import unittest.mock
        original_dump = json.dump
        
        def failing_dump(*args, **kwargs):
            raise json.JSONDecodeError("test error", "", 0)
        
        with unittest.mock.patch('json.dump', side_effect=failing_dump):
            with pytest.raises(json.JSONDecodeError):
                await manager.add_service("another-svc2", "https://test.com/api2")


class TestRecordUsageKeyNotFound:
    @pytest.mark.asyncio
    async def test_record_usage_key_not_in_model(self, manager: ApiKeyManager):
        await manager.add_service("rec-svc", "https://test.com/api")
        await manager.add_model("rec-svc", "rec-model")
        
        with pytest.raises(KeyNotFoundError):
            await manager.record_usage("rec-svc", "rec-model", "nonexistent-key")


class TestRecordAnalyticsError:
    @pytest.mark.asyncio
    async def test_record_usage_with_error_flag(self, manager: ApiKeyManager):
        await manager.add_service("err-svc", "https://test.com/api")
        await manager.add_model("err-svc", "err-model")
        await manager.add_key("err-svc", "err-model", "err-key")
        
        await manager.record_usage("err-svc", "err-model", "err-key", tokens=100, success=False)
        
        from datetime import datetime, timezone
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        assert today in manager.data.analytics
        assert "err-svc:err-model" in manager.data.analytics[today]
        assert manager.data.analytics[today]["err-svc:err-model"].errors == 1
