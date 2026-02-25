import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Header, Query, Depends
from fastapi.responses import JSONResponse

from config import ADMIN_TOKEN_HEADER
from core.models import (
    KeyLimits,
    AddKeyRequest,
    UpdateLimitsRequest,
    AddServiceRequest,
    AddModelRequest,
    ServiceInfo,
    ModelInfo,
    KeyInfo,
)
from core.exceptions import (
    ApiKeyManagerError,
    ServiceNotFoundError,
    ModelNotFoundError,
    KeyNotFoundError,
    AuthenticationError,
)

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/admin", tags=["admin"])

manager = None


def init_manager(mgr):
    global manager
    manager = mgr


async def verify_auth(admin_token: Optional[str] = Header(None, alias=ADMIN_TOKEN_HEADER)):
    if manager is None:
        raise HTTPException(status_code=500, detail="Manager not initialized")
    try:
        manager.verify_admin_token(admin_token or "")
        return True
    except AuthenticationError:
        raise HTTPException(status_code=401, detail="Invalid or missing admin token")


@router.get("/services")
async def list_services(_: bool = Depends(verify_auth)):
    try:
        services = await manager.get_services()
        return {"services": [s.model_dump() for s in services]}
    except Exception as e:
        logger.error(f"Error listing services: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/services/{service}")
async def get_service(service: str, _: bool = Depends(verify_auth)):
    try:
        svc = await manager.get_service(service)
        return svc.model_dump()
    except ServiceNotFoundError:
        raise HTTPException(status_code=404, detail=f"Service '{service}' not found")
    except Exception as e:
        logger.error(f"Error getting service: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/services")
async def add_service(request: AddServiceRequest, _: bool = Depends(verify_auth)):
    try:
        await manager.add_service(request.name, request.base_url, request.default_model)
        return {"status": "created", "service": request.name}
    except ApiKeyManagerError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error adding service: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/services/{service}")
async def remove_service(service: str, _: bool = Depends(verify_auth)):
    try:
        await manager.remove_service(service)
        return {"status": "deleted", "service": service}
    except ServiceNotFoundError:
        raise HTTPException(status_code=404, detail=f"Service '{service}' not found")
    except Exception as e:
        logger.error(f"Error removing service: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/services/{service}/models")
async def list_models(service: str, _: bool = Depends(verify_auth)):
    try:
        models = await manager.get_models(service)
        return {"service": service, "models": [m.model_dump() for m in models]}
    except ServiceNotFoundError:
        raise HTTPException(status_code=404, detail=f"Service '{service}' not found")
    except Exception as e:
        logger.error(f"Error listing models: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/services/{service}/models/{model}")
async def get_model(service: str, model: str, _: bool = Depends(verify_auth)):
    try:
        mdl = await manager.get_model_info(service, model)
        return mdl.model_dump()
    except ServiceNotFoundError:
        raise HTTPException(status_code=404, detail=f"Service '{service}' not found")
    except ModelNotFoundError:
        raise HTTPException(status_code=404, detail=f"Model '{model}' not found in service '{service}'")
    except Exception as e:
        logger.error(f"Error getting model: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/services/{service}/models")
async def add_model(service: str, request: AddModelRequest, _: bool = Depends(verify_auth)):
    try:
        await manager.add_model(service, request.name, request.limits)
        return {"status": "created", "service": service, "model": request.name}
    except ServiceNotFoundError:
        raise HTTPException(status_code=404, detail=f"Service '{service}' not found")
    except ApiKeyManagerError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error adding model: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/services/{service}/models/{model}")
async def remove_model(service: str, model: str, _: bool = Depends(verify_auth)):
    try:
        await manager.remove_model(service, model)
        return {"status": "deleted", "service": service, "model": model}
    except ServiceNotFoundError:
        raise HTTPException(status_code=404, detail=f"Service '{service}' not found")
    except ModelNotFoundError:
        raise HTTPException(status_code=404, detail=f"Model '{model}' not found in service '{service}'")
    except Exception as e:
        logger.error(f"Error removing model: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/services/{service}/models/{model}/limits")
async def update_limits(service: str, model: str, limits: KeyLimits, _: bool = Depends(verify_auth)):
    try:
        await manager.update_limits(service, model, limits)
        return {"status": "updated", "service": service, "model": model, "limits": limits.model_dump(exclude_none=True)}
    except ServiceNotFoundError:
        raise HTTPException(status_code=404, detail=f"Service '{service}' not found")
    except ModelNotFoundError:
        raise HTTPException(status_code=404, detail=f"Model '{model}' not found in service '{service}'")
    except Exception as e:
        logger.error(f"Error updating limits: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/services/{service}/models/{model}/keys")
async def list_keys(service: str, model: str, _: bool = Depends(verify_auth)):
    try:
        keys = await manager.get_keys(service, model)
        return {"service": service, "model": model, "keys": [k.model_dump() for k in keys]}
    except ServiceNotFoundError:
        raise HTTPException(status_code=404, detail=f"Service '{service}' not found")
    except ModelNotFoundError:
        raise HTTPException(status_code=404, detail=f"Model '{model}' not found in service '{service}'")
    except Exception as e:
        logger.error(f"Error listing keys: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/services/{service}/models/{model}/keys")
async def add_key(service: str, model: str, request: AddKeyRequest, _: bool = Depends(verify_auth)):
    try:
        await manager.add_key(service, model, request.api_key)
        return {"status": "created", "service": service, "model": model}
    except ServiceNotFoundError:
        raise HTTPException(status_code=404, detail=f"Service '{service}' not found")
    except ModelNotFoundError:
        raise HTTPException(status_code=404, detail=f"Model '{model}' not found in service '{service}'")
    except ApiKeyManagerError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        logger.error(f"Error adding key: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/services/{service}/models/{model}/keys/{key_pattern:path}")
async def remove_key(service: str, model: str, key_pattern: str, _: bool = Depends(verify_auth)):
    try:
        await manager.remove_key(service, model, key_pattern)
        return {"status": "deleted", "service": service, "model": model}
    except ServiceNotFoundError:
        raise HTTPException(status_code=404, detail=f"Service '{service}' not found")
    except ModelNotFoundError:
        raise HTTPException(status_code=404, detail=f"Model '{model}' not found in service '{service}'")
    except KeyNotFoundError:
        raise HTTPException(status_code=404, detail=f"Key not found in '{service}/{model}'")
    except Exception as e:
        logger.error(f"Error removing key: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/analytics")
async def get_analytics(days: int = Query(default=7, ge=1, le=30), _: bool = Depends(verify_auth)):
    try:
        analytics = await manager.get_analytics(days)
        return {"days": days, "analytics": analytics}
    except Exception as e:
        logger.error(f"Error getting analytics: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
async def get_status(_: bool = Depends(verify_auth)):
    try:
        services = await manager.get_services()
        total_keys = 0
        total_available = 0
        
        for svc in services:
            models = await manager.get_models(svc.name)
            for mdl in models:
                total_keys += mdl.key_count
                total_available += mdl.available_keys
        
        return {
            "services_count": len(services),
            "total_keys": total_keys,
            "available_keys": total_available,
        }
    except Exception as e:
        logger.error(f"Error getting status: {e}")
        raise HTTPException(status_code=500, detail=str(e))
