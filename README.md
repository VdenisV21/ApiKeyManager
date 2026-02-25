# API Key Manager

A high-performance proxy server that manages API keys with rate limiting, key rotation, and analytics. Acts as middleware between your applications and API providers (OpenAI, Anthropic, Gemini, etc.).

## Features

- **Multi-service support** - Manage keys for OpenAI, Anthropic, Gemini, Ollama, and any HTTP API
- **Per-model rate limits** - Configure RPM (requests/min), RPD (requests/day), TPM (tokens/min), TPD (tokens/day)
- **Intelligent key rotation** - LRU-based rotation spreads usage evenly across keys
- **Automatic failover** - Retries with different keys on 429/503 errors
- **Streaming support** - Full SSE (Server-Sent Events) support for LLM streaming responses
- **Analytics** - Track usage, tokens, and errors per service/model
- **Admin API** - Full CRUD for services, models, and keys
- **Persistent storage** - JSON file storage with debounced saves
- **Async-first** - Built with asyncio for high concurrency

## Installation

```bash
# Clone the repository
git clone https://github.com/your-org/ApiKeyManager.git
cd ApiKeyManager

# Install dependencies
pip install -r requirements.txt
```

Requirements: Python 3.10+

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `APIKEYMGR_DATA_FILE` | `data/api_keys.json` | Path to JSON config file |
| `APIKEYMGR_HOST` | `0.0.0.0` | Server host |
| `APIKEYMGR_PORT` | `8000` | Server port |
| `APIKEYMGR_MAX_RETRIES` | `3` | Max retry attempts on failures |
| `APIKEYMGR_REQUEST_TIMEOUT` | `120` | Request timeout in seconds |
| `APIKEYMGR_STREAMING_TIMEOUT` | `600` | Streaming timeout in seconds |

### JSON Configuration File

The `data/api_keys.json` file stores all configuration:

```json
{
  "admin_token": "your-secret-admin-token-change-me",
  "server": {
    "host": "0.0.0.0",
    "port": 8000,
    "max_retries": 3,
    "request_timeout": 120
  },
  "services": {
    "openai": {
      "base_url": "https://api.openai.com/v1",
      "default_model": "gpt-4",
      "models": {
        "gpt-4": {
          "limits": {
            "rpm": 500,
            "rpd": 10000,
            "tpm": 30000,
            "tpd": 500000
          },
          "keys": {
            "sk-your-api-key": {
              "usage_today": 0,
              "tokens_today": 0,
              "last_used_index": 0
            }
          }
        }
      }
    }
  },
  "analytics": {}
}
```

## Running the Server

```bash
# Development mode with auto-reload
python server.py

# Or using uvicorn directly
uvicorn server:app --host 0.0.0.0 --port 8000 --reload

# Production mode
uvicorn server:app --host 0.0.0.0 --port 8000 --workers 4
```

The API will be available at `http://localhost:8000`

- **API Docs**: http://localhost:8000/docs
- **Health Check**: http://localhost:8000/health

## API Endpoints

### Proxy Endpoint

| Method | Endpoint | Description |
|--------|----------|-------------|
| `*` | `/proxy/{path}` | Proxy requests to target service |

**Required Headers:**
- `X-Target-Service`: Service name (e.g., `openai`, `anthropic`)
- `X-Target-Model`: (Optional) Model name (uses default if omitted)

**Request Body:**
Use `<apikey>` as a placeholder for the API key. It will be replaced with a valid key.

### Admin Endpoints

All admin endpoints require the `X-Admin-Token` header.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/admin/services` | List all services |
| `POST` | `/admin/services` | Add a new service |
| `GET` | `/admin/services/{service}` | Get service details |
| `DELETE` | `/admin/services/{service}` | Remove a service |
| `GET` | `/admin/services/{service}/models` | List models for service |
| `POST` | `/admin/services/{service}/models` | Add a model |
| `GET` | `/admin/services/{service}/models/{model}` | Get model details |
| `DELETE` | `/admin/services/{service}/models/{model}` | Remove a model |
| `PATCH` | `/admin/services/{service}/models/{model}/limits` | Update rate limits |
| `GET` | `/admin/services/{service}/models/{model}/keys` | List keys |
| `POST` | `/admin/services/{service}/models/{model}/keys` | Add a key |
| `DELETE` | `/admin/services/{service}/models/{model}/keys/{key}` | Remove a key |
| `GET` | `/admin/analytics` | Get usage analytics |
| `GET` | `/admin/status` | Get server status |

## Python Usage Examples

### Basic Proxy Request

```python
import httpx

API_BASE = "http://localhost:8000"
ADMIN_TOKEN = "your-secret-admin-token-change-me"

# Make a proxy request to OpenAI
response = httpx.post(
    f"{API_BASE}/proxy/chat/completions",
    headers={
        "X-Target-Service": "openai",
        "X-Target-Model": "gpt-4",
        "Content-Type": "application/json",
    },
    json={
        "model": "gpt-4",
        "messages": [{"role": "user", "content": "Hello!"}],
    },
    timeout=120.0,
)

print(response.json())
```

### Streaming Request (SSE)

```python
import httpx
import json

API_BASE = "http://localhost:8000"

def stream_chat():
    with httpx.stream(
        "POST",
        f"{API_BASE}/proxy/chat/completions",
        headers={
            "X-Target-Service": "openai",
            "X-Target-Model": "gpt-4",
            "Content-Type": "application/json",
        },
        json={
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Tell me a story"}],
            "stream": True,
        },
        timeout=600.0,
    ) as response:
        for line in response.iter_lines():
            if line.startswith("data: "):
                data = line[6:]
                if data == "[DONE]":
                    break
                chunk = json.loads(data)
                if chunk.get("choices"):
                    delta = chunk["choices"][0].get("delta", {})
                    if "content" in delta:
                        print(delta["content"], end="", flush=True)

stream_chat()
```

### Using with OpenAI SDK

```python
from openai import OpenAI

# Point the OpenAI SDK to your proxy server
client = OpenAI(
    base_url="http://localhost:8000/proxy",  # Proxy base URL
    api_key="<apikey>",  # Placeholder - will be replaced by proxy
)

# Set default headers for service/model selection
client._client.headers.update({
    "X-Target-Service": "openai",
    "X-Target-Model": "gpt-4",
})

response = client.chat.completions.create(
    model="gpt-4",
    messages=[{"role": "user", "content": "Hello!"}],
)

print(response.choices[0].message.content)
```

### List All Services

```python
import httpx

response = httpx.get(
    f"{API_BASE}/admin/services",
    headers={"X-Admin-Token": ADMIN_TOKEN},
)
print(response.json())
# {"services": [{"name": "openai", "base_url": "...", "models": [...], ...}]}
```

### Add a New Service

```python
response = httpx.post(
    f"{API_BASE}/admin/services",
    headers={"X-Admin-Token": ADMIN_TOKEN},
    json={
        "name": "cohere",
        "base_url": "https://api.cohere.ai/v1",
        "default_model": "command",
    },
)
print(response.json())
# {"status": "created", "service": "cohere"}
```

### Add a Model to a Service

```python
response = httpx.post(
    f"{API_BASE}/admin/services/cohere/models",
    headers={"X-Admin-Token": ADMIN_TOKEN},
    json={
        "name": "command-r",
        "limits": {
            "rpm": 100,
            "rpd": 1000,
            "tpm": 40000,
            "tpd": 500000,
        },
    },
)
print(response.json())
# {"status": "created", "service": "cohere", "model": "command-r"}
```

### Add API Keys

```python
response = httpx.post(
    f"{API_BASE}/admin/services/openai/models/gpt-4/keys",
    headers={"X-Admin-Token": ADMIN_TOKEN},
    json={"api_key": "sk-your-new-api-key-here"},
)
print(response.json())
# {"status": "created", "service": "openai", "model": "gpt-4"}
```

### Update Rate Limits

```python
response = httpx.patch(
    f"{API_BASE}/admin/services/openai/models/gpt-4/limits",
    headers={"X-Admin-Token": ADMIN_TOKEN},
    json={
        "rpm": 1000,
        "rpd": 20000,
    },
)
print(response.json())
# {"status": "updated", "service": "openai", "model": "gpt-4", "limits": {"rpm": 1000, "rpd": 20000}}
```

### List Keys for a Model

```python
response = httpx.get(
    f"{API_BASE}/admin/services/openai/models/gpt-4/keys",
    headers={"X-Admin-Token": ADMIN_TOKEN},
)
print(response.json())
# {"service": "openai", "model": "gpt-4", "keys": [{"key_preview": "sk-xxxxx...1234", "usage_today": 5, ...}]}
```

### Remove a Key

```python
response = httpx.delete(
    f"{API_BASE}/admin/services/openai/models/gpt-4/keys/sk-old-key",
    headers={"X-Admin-Token": ADMIN_TOKEN},
)
print(response.json())
# {"status": "deleted", "service": "openai", "model": "gpt-4"}
```

### Remove a Model

```python
response = httpx.delete(
    f"{API_BASE}/admin/services/openai/models/gpt-3.5-turbo",
    headers={"X-Admin-Token": ADMIN_TOKEN},
)
print(response.json())
# {"status": "deleted", "service": "openai", "model": "gpt-3.5-turbo"}
```

### Remove a Service

```python
response = httpx.delete(
    f"{API_BASE}/admin/services/gemini",
    headers={"X-Admin-Token": ADMIN_TOKEN},
)
print(response.json())
# {"status": "deleted", "service": "gemini"}
```

### View Analytics

```python
response = httpx.get(
    f"{API_BASE}/admin/analytics?days=7",
    headers={"X-Admin-Token": ADMIN_TOKEN},
)
print(response.json())
# {"days": 7, "analytics": {"2024-01-15": {"openai:gpt-4": {"requests": 150, "tokens": 25000, "errors": 2}}}}
```

### Check Server Status

```python
response = httpx.get(
    f"{API_BASE}/admin/status",
    headers={"X-Admin-Token": ADMIN_TOKEN},
)
print(response.json())
# {"services_count": 4, "total_keys": 12, "available_keys": 10}
```

### Complete Setup Example

```python
import httpx

API_BASE = "http://localhost:8000"
ADMIN_TOKEN = "my-secure-admin-token"

def setup_server():
    headers = {"X-Admin-Token": ADMIN_TOKEN}
    
    # Add OpenAI service
    httpx.post(
        f"{API_BASE}/admin/services",
        headers=headers,
        json={
            "name": "openai",
            "base_url": "https://api.openai.com/v1",
            "default_model": "gpt-4",
        },
    )
    
    # Add GPT-4 model with limits
    httpx.post(
        f"{API_BASE}/admin/services/openai/models",
        headers=headers,
        json={
            "name": "gpt-4",
            "limits": {"rpm": 500, "rpd": 10000, "tpm": 30000, "tpd": 500000},
        },
    )
    
    # Add API keys (add multiple for rotation)
    for key in ["sk-key1", "sk-key2", "sk-key3"]:
        httpx.post(
            f"{API_BASE}/admin/services/openai/models/gpt-4/keys",
            headers=headers,
            json={"api_key": key},
        )
    
    print("Setup complete!")

# Now make requests
def make_request():
    response = httpx.post(
        f"{API_BASE}/proxy/chat/completions",
        headers={
            "X-Target-Service": "openai",
            "Content-Type": "application/json",
        },
        json={
            "model": "gpt-4",
            "messages": [{"role": "user", "content": "Hello!"}],
        },
        timeout=120.0,
    )
    return response.json()

if __name__ == "__main__":
    setup_server()
    result = make_request()
    print(result)
```

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_manager.py

# Run with coverage report
pytest --cov --cov-report=term-missing
```

The project has 99% test coverage with 176 tests.

### Project Structure

```
ApiKeyManager/
├── config.py              # Server configuration (env vars)
├── server.py              # FastAPI app entry point
├── requirements.txt       # Python dependencies
├── core/
│   ├── manager.py         # ApiKeyManager (key rotation, limits, analytics)
│   ├── models.py          # Pydantic data models
│   └── exceptions.py      # Custom exceptions
├── routes/
│   ├── proxy.py           # /proxy endpoint (handles forwarding)
│   └── admin.py           # /admin/* endpoints (CRUD operations)
├── tests/
│   ├── conftest.py        # Test fixtures
│   ├── test_manager.py    # Manager unit tests
│   ├── test_admin.py      # Admin API tests
│   ├── test_proxy.py      # Proxy tests
│   └── test_integration.py # End-to-end tests
└── data/
    └── api_keys.json      # Persistent storage
```

## Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌─────────────────┐
│  Your App   │────▶│  API Key Manager │────▶│  API Provider   │
│             │     │     (Proxy)      │     │  (OpenAI, etc)  │
└─────────────┘     └──────────────────┘     └─────────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │ api_keys.js │
                    │  (Storage)  │
                    └─────────────┘
```

**Request Flow:**
1. Your app sends request to proxy with `X-Target-Service` header
2. Proxy selects the least-recently-used available key
3. Key replaces `<apikey>` placeholder in request body/headers
4. Request forwarded to target API provider
5. Response returned to your app
6. Usage recorded (requests, tokens) for analytics and rate limiting

**Key Selection Algorithm:**
- Keys with active cooldowns are skipped
- Keys exceeding RPM/RPD/TPM/TPD limits are skipped
- The key with the lowest `last_used_index` is selected (LRU)
- On 429/503 errors, key is put on 60s cooldown, next key tried

## License

MIT
