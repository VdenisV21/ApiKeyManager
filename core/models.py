from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from datetime import datetime


class KeyLimits(BaseModel):
    rpm: Optional[int] = Field(None, description="Requests per minute")
    rpd: Optional[int] = Field(None, description="Requests per day")
    tpm: Optional[int] = Field(None, description="Tokens per minute")
    tpd: Optional[int] = Field(None, description="Tokens per day")


class KeyUsage(BaseModel):
    usage_today: int = 0
    tokens_today: int = 0
    last_used_index: int = 0
    cooldown_until: Optional[float] = None


class KeyInfo(BaseModel):
    key_preview: str
    usage_today: int
    tokens_today: int
    last_used_index: int
    is_on_cooldown: bool
    is_usable: bool


class ModelConfig(BaseModel):
    limits: KeyLimits = KeyLimits()
    keys: Dict[str, KeyUsage] = {}
    rotation_index: int = 0


class ServiceConfig(BaseModel):
    base_url: str
    models: Dict[str, ModelConfig] = {}
    default_model: Optional[str] = None


class ServerConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000
    max_retries: int = 3
    request_timeout: int = 120


class AnalyticsEntry(BaseModel):
    requests: int = 0
    tokens: int = 0
    errors: int = 0


class DataManager(BaseModel):
    admin_token: str = "change-me"
    server: ServerConfig = ServerConfig()
    services: Dict[str, ServiceConfig] = {}
    analytics: Dict[str, Dict[str, AnalyticsEntry]] = {}
    last_reset_date: Optional[str] = None


class ServiceInfo(BaseModel):
    name: str
    base_url: str
    models: List[str]
    default_model: Optional[str]


class ModelInfo(BaseModel):
    name: str
    limits: KeyLimits
    key_count: int
    available_keys: int


class AddKeyRequest(BaseModel):
    api_key: str


class UpdateLimitsRequest(BaseModel):
    rpm: Optional[int] = None
    rpd: Optional[int] = None
    tpm: Optional[int] = None
    tpd: Optional[int] = None


class AddServiceRequest(BaseModel):
    name: str
    base_url: str
    default_model: Optional[str] = None


class AddModelRequest(BaseModel):
    name: str
    limits: Optional[KeyLimits] = None


class AnalyticsResponse(BaseModel):
    date: str
    service: str
    model: str
    requests: int
    tokens: int
    errors: int


class ProxyRequest(BaseModel):
    service: str
    model: Optional[str] = None
    path: str = ""
    method: str = "POST"
    headers: Dict[str, str] = {}
    body: Optional[str] = None


class ProxyResponse(BaseModel):
    status_code: int
    headers: Dict[str, str] = {}
    body: Optional[str] = None
    key_used: Optional[str] = None
    retries: int = 0
