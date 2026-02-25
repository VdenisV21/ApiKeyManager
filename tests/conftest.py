import os
import json
import tempfile
import pytest
import pytest_asyncio
from typing import Generator
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock
import respx
from httpx import Response

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.manager import ApiKeyManager
from core.models import DataManager, ServiceConfig, ModelConfig, KeyLimits, KeyUsage
from server import app
from routes.proxy import init_manager as init_proxy_manager
from routes.admin import init_manager as init_admin_manager


@pytest.fixture
def temp_data_file() -> Generator[str, None, None]:
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write('{}')
        temp_path = f.name
    yield temp_path
    if os.path.exists(temp_path):
        os.remove(temp_path)
    tmp_file = temp_path + ".tmp"
    if os.path.exists(tmp_file):
        os.remove(tmp_file)


@pytest.fixture
def manager(temp_data_file: str) -> ApiKeyManager:
    mgr = ApiKeyManager(data_file=temp_data_file)
    return mgr


@pytest_asyncio.fixture
async def client(manager: ApiKeyManager) -> Generator[TestClient, None, None]:
    with TestClient(app, raise_server_exceptions=False) as test_client:
        init_proxy_manager(manager, None)
        init_admin_manager(manager)
        yield test_client


@pytest.fixture
def admin_headers(manager: ApiKeyManager) -> dict:
    return {"X-Admin-Token": manager.data.admin_token}


@pytest_asyncio.fixture
async def sample_service(manager: ApiKeyManager) -> dict:
    await manager.add_service("test-service", "https://api.test.com/v1", "default-model")
    await manager.add_model("test-service", "default-model", KeyLimits(rpm=10, rpd=100, tpm=1000, tpd=10000))
    await manager.add_model("test-service", "other-model", KeyLimits(rpm=5, rpd=50))
    
    keys = ["key-aaa111", "key-bbb222", "key-ccc333"]
    for key in keys:
        await manager.add_key("test-service", "default-model", key)
    
    return {
        "name": "test-service",
        "models": ["default-model", "other-model"],
        "default_model": "default-model",
        "keys": keys
    }


@pytest.fixture
def mock_target_response():
    return {
        "id": "test-response-id",
        "choices": [{"message": {"content": "Hello!"}}],
        "usage": {"total_tokens": 50}
    }


@pytest.fixture
def mock_streaming_chunks():
    return [
        b'data: {"choices": [{"delta": {"content": "Hello"}}]}\n\n',
        b'data: {"choices": [{"delta": {"content": " world"}}]}\n\n',
        b'data: {"usage": {"total_tokens": 10}}\n\n',
        b'data: [DONE]\n\n',
    ]


@pytest_asyncio.fixture
async def mock_httpx_client():
    with respx.mock() as mock:
        yield mock


@pytest_asyncio.fixture
async def populated_manager(manager: ApiKeyManager):
    await manager.add_service("openai", "https://api.openai.com/v1", "gpt-4")
    await manager.add_model("openai", "gpt-4", KeyLimits(rpm=500, rpd=10000, tpm=30000, tpd=500000))
    await manager.add_model("openai", "gpt-3.5-turbo", KeyLimits(rpm=3500, rpd=50000))
    
    await manager.add_key("openai", "gpt-4", "sk-test-key-1")
    await manager.add_key("openai", "gpt-4", "sk-test-key-2")
    await manager.add_key("openai", "gpt-4", "sk-test-key-3")
    await manager.add_key("openai", "gpt-3.5-turbo", "sk-turbo-key-1")
    
    return manager


@pytest.fixture
def pre_existing_data_file() -> Generator[str, None, None]:
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        data = {
            "admin_token": "pre-existing-token",
            "server": {"host": "0.0.0.0", "port": 8000},
            "services": {
                "preloaded-service": {
                    "base_url": "https://preloaded.com/api",
                    "default_model": "preloaded-model",
                    "models": {
                        "preloaded-model": {
                            "limits": {"rpm": 100, "rpd": 1000},
                            "keys": {
                                "pre-key-123": {"usage_today": 5, "tokens_today": 100, "last_used_index": 0}
                            }
                        }
                    }
                }
            },
            "analytics": {}
        }
        json.dump(data, f)
        temp_path = f.name
    yield temp_path
    if os.path.exists(temp_path):
        os.remove(temp_path)


@pytest.fixture
def corrupted_data_file() -> Generator[str, None, None]:
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        f.write("{ invalid json }")
        temp_path = f.name
    yield temp_path
    if os.path.exists(temp_path):
        os.remove(temp_path)
