import json
import logging
from typing import Optional
from fastapi import APIRouter, Request, Response, HTTPException, Header
from fastapi.responses import StreamingResponse
import httpx

from config import (
    TARGET_SERVICE_HEADER,
    TARGET_MODEL_HEADER,
    APIKEY_PLACEHOLDER,
    MAX_RETRIES,
    REQUEST_TIMEOUT,
    STREAMING_TIMEOUT,
)
from core.exceptions import ServiceNotFoundError, ModelNotFoundError, NoAvailableKeyError

logger = logging.getLogger(__name__)
router = APIRouter(tags=["proxy"])

manager = None
http_client: Optional[httpx.AsyncClient] = None


def init_manager(mgr, client: Optional[httpx.AsyncClient] = None):
    global manager, http_client
    manager = mgr
    http_client = client


@router.api_route("/proxy/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"])
async def proxy_request(
    path: str,
    request: Request,
    x_target_service: str = Header(..., alias=TARGET_SERVICE_HEADER),
    x_target_model: Optional[str] = Header(None, alias=TARGET_MODEL_HEADER),
):
    if manager is None:
        raise HTTPException(status_code=500, detail="Manager not initialized")
    
    try:
        base_url = manager.get_base_url(x_target_service)
    except ServiceNotFoundError:
        raise HTTPException(status_code=404, detail=f"Service '{x_target_service}' not found")
    
    body = await request.body()
    body_str = body.decode('utf-8') if body else ""
    
    headers = dict(request.headers)
    headers.pop("host", None)
    headers.pop("content-length", None)
    headers.pop(TARGET_SERVICE_HEADER.lower().replace("-", "_"), None)
    headers.pop(TARGET_MODEL_HEADER.lower().replace("-", "_"), None)
    
    target_url = f"{base_url.rstrip('/')}/{path}"
    
    query_params = str(request.query_params)
    if query_params:
        target_url += f"?{query_params}"
    
    client = http_client or httpx.AsyncClient(timeout=REQUEST_TIMEOUT)
    should_close_client = http_client is None
    
    last_error = None
    key_used = None
    resolved_model = x_target_model
    retries = 0
    
    try:
        for attempt in range(MAX_RETRIES):
            try:
                api_key, resolved_model = await manager.get_key(x_target_service, x_target_model)
                key_used = api_key
                retries = attempt
                
                modified_body = body_str.replace(APIKEY_PLACEHOLDER, api_key)
                
                if "authorization" in headers:
                    headers["authorization"] = headers["authorization"].replace(APIKEY_PLACEHOLDER, api_key)
                
                is_streaming = False
                try:
                    body_json = json.loads(modified_body)
                    is_streaming = body_json.get("stream", False)
                except (json.JSONDecodeError, TypeError):
                    pass
                
                request_headers = {k: v for k, v in headers.items() if v}
                
                if is_streaming:
                    return await handle_streaming_request(
                        client, request.method, target_url, request_headers, 
                        modified_body, api_key, x_target_service, resolved_model, should_close_client
                    )
                else:
                    response = await client.request(
                        method=request.method,
                        url=target_url,
                        headers=request_headers,
                        content=modified_body if modified_body else None,
                    )
                    
                    if response.status_code in (429, 503):
                        await manager.mark_key_cooldown(x_target_service, resolved_model, api_key, seconds=60)
                        last_error = f"Rate limited (status {response.status_code})"
                        logger.warning(f"Key rate limited, trying next: {last_error}")
                        continue
                    
                    tokens_used = 0
                    try:
                        resp_json = response.json()
                        if "usage" in resp_json:
                            tokens_used = resp_json["usage"].get("total_tokens", 0)
                    except (json.JSONDecodeError, TypeError, AttributeError):
                        pass
                    
                    await manager.record_usage(x_target_service, resolved_model, api_key, tokens=tokens_used)
                    
                    response_headers = dict(response.headers)
                    for hop_header in ["content-encoding", "transfer-encoding", "connection"]:
                        response_headers.pop(hop_header, None)
                    
                    return Response(
                        content=response.content,
                        status_code=response.status_code,
                        headers=response_headers,
                        media_type=response_headers.get("content-type")
                    )
                    
            except NoAvailableKeyError as e:
                raise HTTPException(status_code=503, detail=str(e))
            except ServiceNotFoundError as e:
                raise HTTPException(status_code=404, detail=str(e))
            except ModelNotFoundError as e:
                raise HTTPException(status_code=404, detail=str(e))
            except httpx.TimeoutException:
                last_error = "Request timed out"
                if key_used:
                    await manager.mark_key_cooldown(x_target_service, resolved_model, key_used, seconds=30)
                logger.warning(f"Request timed out, attempt {attempt + 1}")
                continue
            except Exception as e:
                last_error = str(e)
                logger.error(f"Proxy error (attempt {attempt + 1}): {e}")
                if attempt < MAX_RETRIES - 1:
                    continue
                raise HTTPException(status_code=500, detail=f"Proxy error: {last_error}")
    finally:
        if should_close_client and client:
            await client.aclose()
    
    raise HTTPException(status_code=503, detail=f"All retries exhausted: {last_error}")


async def handle_streaming_request(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: dict,
    body: str,
    api_key: str,
    service: str,
    model: str,
    should_close_client: bool = False,
):
    async def stream_generator():
        total_tokens = 0
        try:
            timeout = httpx.Timeout(STREAMING_TIMEOUT, read=STREAMING_TIMEOUT)
            async with client.stream(
                method=method,
                url=url,
                headers=headers,
                content=body if body else None,
                timeout=timeout,
            ) as response:
                if response.status_code in (429, 503):
                    await manager.mark_key_cooldown(service, model, api_key, seconds=60)
                    yield f"data: {json.dumps({'error': 'rate_limited'})}\n\n"
                    return
                
                async for chunk in response.aiter_bytes():
                    chunk_str = chunk.decode('utf-8', errors='replace')
                    for line in chunk_str.split('\n'):
                        if line.startswith('data: ') and not line.endswith('[DONE]'):
                            try:
                                data = json.loads(line[6:])
                                if 'usage' in data:
                                    total_tokens = data['usage'].get('total_tokens', 0)
                            except json.JSONDecodeError:
                                pass
                    yield chunk
                
                await manager.record_usage(service, model, api_key, tokens=total_tokens)
                
        except httpx.TimeoutException:
            await manager.mark_key_cooldown(service, model, api_key, seconds=30)
            yield f"data: {json.dumps({'error': 'timeout'})}\n\n"
        except Exception as e:
            logger.error(f"Streaming error: {e}")
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
        finally:
            if should_close_client:
                await client.aclose()
    
    return StreamingResponse(
        stream_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        }
    )
