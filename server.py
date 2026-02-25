import logging
import httpx
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config import DATA_FILE, SERVER_HOST, SERVER_PORT, REQUEST_TIMEOUT
from core.manager import ApiKeyManager
from routes import proxy_router, admin_router
from routes.proxy import init_manager as init_proxy_manager
from routes.admin import init_manager as init_admin_manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

manager: ApiKeyManager = None
http_client: httpx.AsyncClient = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global manager, http_client
    logger.info(f"Initializing ApiKeyManager with data file: {DATA_FILE}")
    
    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(REQUEST_TIMEOUT),
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
    )
    
    manager = ApiKeyManager(data_file=DATA_FILE)
    init_proxy_manager(manager, http_client)
    init_admin_manager(manager)
    logger.info("ApiKeyManager initialized successfully")
    yield
    logger.info("Shutting down...")
    await manager.cleanup()
    await http_client.aclose()
    logger.info("Cleanup complete")


app = FastAPI(
    title="API Key Manager",
    description="A proxy server that manages API keys with rate limiting, rotation, and analytics",
    version="2.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(proxy_router)
app.include_router(admin_router)


@app.get("/")
def root():
    return {
        "name": "API Key Manager",
        "version": "2.0.0",
        "docs": "/docs",
        "endpoints": {
            "proxy": "/proxy/{path}",
            "admin": "/admin/...",
        }
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


if __name__ == "__main__":  # pragma: no cover
    uvicorn.run(
        "server:app",
        host=SERVER_HOST,
        port=SERVER_PORT,
        reload=True,
        log_level="info",
    )
