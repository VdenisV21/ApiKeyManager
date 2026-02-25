import json
import os
import time
import asyncio
import secrets
import logging
import threading
from datetime import datetime, timezone, timedelta
from collections import defaultdict
from typing import Optional, Dict, List, Tuple, Any

from .exceptions import (
    ApiKeyManagerError,
    NoAvailableKeyError,
    ServiceNotFoundError,
    ModelNotFoundError,
    KeyNotFoundError,
    AuthenticationError,
)
from .models import (
    DataManager,
    ServiceConfig,
    ModelConfig,
    KeyLimits,
    KeyUsage,
    KeyInfo,
    ModelInfo,
    ServiceInfo,
    AnalyticsEntry,
)

logger = logging.getLogger(__name__)


class ApiKeyManager:
    """
    Multi-service API Key Manager with rate limiting, key rotation, and persistence.
    
    Features:
    - Multiple services with multiple models
    - Per-model rate limits (RPM, RPD, TPM, TPD)
    - Queue-based key rotation (spread usage evenly)
    - Automatic daily reset
    - In-memory cooldown tracking
    - Analytics tracking with automatic cleanup
    - Async-safe with asyncio locks
    - Debounced file saves for performance
    """

    def __init__(self, data_file: str = "data/api_keys.json"):
        self.data_file = data_file
        self._lock: Optional[asyncio.Lock] = None
        self._file_lock: Optional[asyncio.Lock] = None
        self._locks_initialized = False
        
        self._key_timestamps: Dict[str, List[float]] = defaultdict(list)
        self._key_token_timestamps: Dict[str, List[Tuple[float, int]]] = defaultdict(list)
        self._key_token_totals: Dict[str, int] = defaultdict(int)
        self._key_cooldowns: Dict[str, float] = {}
        
        self.data: Optional[DataManager] = None
        self._global_usage_index = 0
        
        self._save_pending = False
        self._save_task: Optional[asyncio.Task] = None
        self._analytics_retention_days = 30
        
        self._last_reset_date: Optional[str] = None
        self._sync_lock = threading.RLock()
        
        self._load_or_initialize_sync()

    def _get_now_utc(self) -> datetime:
        return datetime.now(timezone.utc)

    def _get_monotonic_time(self) -> float:
        return time.monotonic()

    def _ensure_locks(self):
        if not self._locks_initialized:
            self._lock = asyncio.Lock()
            self._file_lock = asyncio.Lock()
            self._locks_initialized = True

    def _load_or_initialize_sync(self):
        with self._sync_lock:
            if os.path.exists(self.data_file):
                try:
                    with open(self.data_file, 'r') as f:
                        raw_data = json.load(f)
                    self.data = DataManager(**raw_data)
                    logger.info(f"Loaded data from {self.data_file}")
                except Exception as e:
                    logger.error(f"Error loading {self.data_file}: {e}")
                    self.data = DataManager()
                    self._save_data_sync()
            else:
                self.data = DataManager()
                self._save_data_sync()
                logger.info(f"Initialized new data file at {self.data_file}")
            
            self._check_and_reset_daily_sync()
            self._cleanup_timestamps()
            self._cleanup_old_analytics()

    def _save_data_sync(self):
        with self._sync_lock:
            os.makedirs(os.path.dirname(self.data_file) or '.', exist_ok=True)
            temp_file = self.data_file + ".tmp"
            try:
                with open(temp_file, 'w') as f:
                    json.dump(self.data.model_dump(), f, indent=2, default=str)
                os.replace(temp_file, self.data_file)
            except Exception as e:
                logger.error(f"Error saving data: {e}")
                if os.path.exists(temp_file):
                    os.remove(temp_file)
                raise

    async def _save_data(self, immediate: bool = False):
        self._ensure_locks()
        async with self._file_lock:
            if immediate:
                self._save_data_sync()
                return
            
            self._save_pending = True
            
            if self._save_task is None or self._save_task.done():
                self._save_task = asyncio.create_task(self._debounced_save())

    async def _debounced_save(self):
        await asyncio.sleep(1.0)
        if self._save_pending:
            self._save_pending = False
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, self._save_data_sync)

    def _check_and_reset_daily_sync(self):
        now = self._get_now_utc()
        today_str = now.strftime("%Y-%m-%d")
        
        if self._last_reset_date == today_str:
            return
        
        for service_name, service in self.data.services.items():
            for model_name, model in service.models.items():
                for key, usage in model.keys.items():
                    if usage.usage_today > 0 or usage.tokens_today > 0:
                        usage.usage_today = 0
                        usage.tokens_today = 0
        
        self._last_reset_date = today_str
        self._save_data_sync()

    async def _check_and_reset_daily(self):
        with self._sync_lock:
            self._check_and_reset_daily_sync()

    def _cleanup_timestamps(self):
        now_mono = self._get_monotonic_time()
        cutoff = now_mono - 60.0
        
        for key in list(self._key_timestamps.keys()):
            old_count = len(self._key_timestamps[key])
            self._key_timestamps[key] = [ts for ts in self._key_timestamps[key] if ts >= cutoff]
            new_count = len(self._key_timestamps[key])
        
        for key in list(self._key_token_timestamps.keys()):
            old_tokens = sum(tok for _, tok in self._key_token_timestamps[key])
            self._key_token_timestamps[key] = [(ts, tok) for ts, tok in self._key_token_timestamps[key] if ts >= cutoff]
            new_tokens = sum(tok for _, tok in self._key_token_timestamps[key])
            self._key_token_totals[key] = new_tokens
            
            if not self._key_token_timestamps[key]:
                del self._key_token_timestamps[key]
                if key in self._key_token_totals:
                    del self._key_token_totals[key]
        
        for key in list(self._key_cooldowns.keys()):
            if self._key_cooldowns[key] <= now_mono:
                del self._key_cooldowns[key]

        for key in list(self._key_timestamps.keys()):
            if not self._key_timestamps[key]:
                del self._key_timestamps[key]

    def _cleanup_old_analytics(self):
        now = self._get_now_utc()
        cutoff_date = (now - timedelta(days=self._analytics_retention_days)).strftime("%Y-%m-%d")
        
        dates_to_remove = [d for d in self.data.analytics.keys() if d < cutoff_date]
        for date in dates_to_remove:
            del self.data.analytics[date]
        
        if dates_to_remove:
            logger.info(f"Cleaned up {len(dates_to_remove)} old analytics entries")

    def _get_limits(self, service: str, model: str) -> KeyLimits:
        svc = self._get_service(service)
        mdl = self._get_model(service, model)
        return mdl.limits

    def _get_service(self, service: str) -> ServiceConfig:
        if service not in self.data.services:
            raise ServiceNotFoundError(f"Service '{service}' not found")
        return self.data.services[service]

    def _get_model(self, service: str, model: str) -> ModelConfig:
        svc = self._get_service(service)
        if model not in svc.models:
            raise ModelNotFoundError(f"Model '{model}' not found in service '{service}'")
        return svc.models[model]

    def _resolve_model(self, service: str, model: Optional[str]) -> str:
        svc = self._get_service(service)
        if model:
            return model
        if svc.default_model:
            return svc.default_model
        if svc.models:
            return next(iter(svc.models.keys()))
        raise ModelNotFoundError(f"No models configured for service '{service}'")

    def _is_key_usable(self, key: str, key_usage: KeyUsage, limits: KeyLimits, now_mono: float) -> bool:
        if key in self._key_cooldowns and self._key_cooldowns[key] > now_mono:
            return False
        
        if limits.rpd is not None and key_usage.usage_today >= limits.rpd:
            return False
        
        if limits.tpd is not None and key_usage.tokens_today >= limits.tpd:
            return False
        
        if limits.rpm is not None:
            timestamps = self._key_timestamps.get(key, [])
            if len(timestamps) >= limits.rpm:
                return False
        
        if limits.tpm is not None:
            current_tokens = self._key_token_totals.get(key, 0)
            if current_tokens >= limits.tpm:
                return False
        
        return True

    async def get_key(self, service: str, model: Optional[str] = None) -> Tuple[str, str]:
        """
        Get the next available key for the service/model using round-robin rotation.
        Returns (key, resolved_model_name).
        """
        self._ensure_locks()
        async with self._lock:
            await self._check_and_reset_daily()
            self._cleanup_timestamps()
            
            model = self._resolve_model(service, model)
            mdl = self._get_model(service, model)
            limits = mdl.limits
            now_mono = self._get_monotonic_time()
            
            if not mdl.keys:
                raise NoAvailableKeyError(f"No keys configured for {service}/{model}")
            
            min_index = float('inf')
            best_key = None
            best_usage = None
            
            for key, usage in mdl.keys.items():
                if self._is_key_usable(key, usage, limits, now_mono):
                    if usage.last_used_index < min_index:
                        min_index = usage.last_used_index
                        best_key = key
                        best_usage = usage
            
            if best_key:
                return best_key, model
            
            raise NoAvailableKeyError(f"All keys exhausted for {service}/{model}")

    async def record_usage(self, service: str, model: str, key: str, tokens: int = 0, success: bool = True):
        """Record usage for a key and update analytics."""
        self._ensure_locks()
        async with self._lock:
            mdl = self._get_model(service, model)
            
            if key not in mdl.keys:
                raise KeyNotFoundError(f"Key not found in {service}/{model}")
            
            usage = mdl.keys[key]
            usage.usage_today += 1
            if tokens > 0:
                usage.tokens_today += tokens
            
            self._global_usage_index += 1
            usage.last_used_index = self._global_usage_index
            
            now_mono = self._get_monotonic_time()
            self._key_timestamps[key].append(now_mono)
            if tokens > 0:
                self._key_token_timestamps[key].append((now_mono, tokens))
                self._key_token_totals[key] += tokens
            
            self._record_analytics(service, model, tokens, not success)
            await self._save_data()

    async def mark_key_cooldown(self, service: str, model: str, key: str, seconds: int = 60):
        """Put a key on cooldown."""
        self._ensure_locks()
        async with self._lock:
            mdl = self._get_model(service, model)
            if key not in mdl.keys:
                raise KeyNotFoundError(f"Key not found in {service}/{model}")
            
            self._key_cooldowns[key] = self._get_monotonic_time() + seconds
            logger.info(f"Key {key[:8]}... on cooldown for {seconds}s")

    def _record_analytics(self, service: str, model: str, tokens: int, is_error: bool):
        now = self._get_now_utc()
        date_str = now.strftime("%Y-%m-%d")
        
        if date_str not in self.data.analytics:
            self.data.analytics[date_str] = {}
        
        key = f"{service}:{model}"
        if key not in self.data.analytics[date_str]:
            self.data.analytics[date_str][key] = AnalyticsEntry()
        
        entry = self.data.analytics[date_str][key]
        entry.requests += 1
        entry.tokens += tokens
        if is_error:
            entry.errors += 1

    def verify_admin_token(self, token: str) -> bool:
        if not token:
            raise AuthenticationError("Invalid admin token")
        if not secrets.compare_digest(token, self.data.admin_token):
            raise AuthenticationError("Invalid admin token")
        return True

    async def get_services(self) -> List[ServiceInfo]:
        result = []
        for name, svc in self.data.services.items():
            result.append(ServiceInfo(
                name=name,
                base_url=svc.base_url,
                models=list(svc.models.keys()),
                default_model=svc.default_model
            ))
        return result

    async def get_service(self, service: str) -> ServiceInfo:
        svc = self._get_service(service)
        return ServiceInfo(
            name=service,
            base_url=svc.base_url,
            models=list(svc.models.keys()),
            default_model=svc.default_model
        )

    async def get_models(self, service: str) -> List[ModelInfo]:
        svc = self._get_service(service)
        result = []
        now_mono = self._get_monotonic_time()
        
        for name, mdl in svc.models.items():
            available = sum(
                1 for k, u in mdl.keys.items()
                if self._is_key_usable(k, u, mdl.limits, now_mono)
            )
            result.append(ModelInfo(
                name=name,
                limits=mdl.limits,
                key_count=len(mdl.keys),
                available_keys=available
            ))
        return result

    async def get_model_info(self, service: str, model: str) -> ModelInfo:
        mdl = self._get_model(service, model)
        now_mono = self._get_monotonic_time()
        available = sum(
            1 for k, u in mdl.keys.items()
            if self._is_key_usable(k, u, mdl.limits, now_mono)
        )
        return ModelInfo(
            name=model,
            limits=mdl.limits,
            key_count=len(mdl.keys),
            available_keys=available
        )

    async def get_keys(self, service: str, model: str) -> List[KeyInfo]:
        mdl = self._get_model(service, model)
        limits = mdl.limits
        now_mono = self._get_monotonic_time()
        result = []
        
        for key, usage in mdl.keys.items():
            is_cooldown = key in self._key_cooldowns and self._key_cooldowns[key] > now_mono
            is_usable = self._is_key_usable(key, usage, limits, now_mono)
            result.append(KeyInfo(
                key_preview=f"{key[:8]}...{key[-4:]}",
                usage_today=usage.usage_today,
                tokens_today=usage.tokens_today,
                last_used_index=usage.last_used_index,
                is_on_cooldown=is_cooldown,
                is_usable=is_usable
            ))
        return result

    async def add_key(self, service: str, model: str, api_key: str):
        self._ensure_locks()
        async with self._lock:
            mdl = self._get_model(service, model)
            if api_key in mdl.keys:
                raise ApiKeyManagerError(f"Key already exists in {service}/{model}")
            
            mdl.keys[api_key] = KeyUsage()
            await self._save_data(immediate=True)
            logger.info(f"Added key to {service}/{model}")

    async def remove_key(self, service: str, model: str, key_pattern: str):
        self._ensure_locks()
        async with self._lock:
            mdl = self._get_model(service, model)
            
            matching_keys = [k for k in mdl.keys if k == key_pattern or k.startswith(key_pattern)]
            
            if not matching_keys:
                raise KeyNotFoundError(f"Key not found in {service}/{model}")
            
            for key in matching_keys:
                del mdl.keys[key]
                self._key_timestamps.pop(key, None)
                self._key_token_timestamps.pop(key, None)
                self._key_token_totals.pop(key, None)
                self._key_cooldowns.pop(key, None)
            
            await self._save_data(immediate=True)
            logger.info(f"Removed {len(matching_keys)} key(s) from {service}/{model}")

    async def update_limits(self, service: str, model: str, limits: KeyLimits):
        self._ensure_locks()
        async with self._lock:
            mdl = self._get_model(service, model)
            
            if limits.rpm is not None:
                mdl.limits.rpm = limits.rpm
            if limits.rpd is not None:
                mdl.limits.rpd = limits.rpd
            if limits.tpm is not None:
                mdl.limits.tpm = limits.tpm
            if limits.tpd is not None:
                mdl.limits.tpd = limits.tpd
            
            await self._save_data(immediate=True)
            logger.info(f"Updated limits for {service}/{model}")

    async def add_service(self, name: str, base_url: str, default_model: Optional[str] = None):
        self._ensure_locks()
        async with self._lock:
            if name in self.data.services:
                raise ApiKeyManagerError(f"Service '{name}' already exists")
            
            self.data.services[name] = ServiceConfig(
                base_url=base_url,
                models={},
                default_model=default_model
            )
            await self._save_data(immediate=True)
            logger.info(f"Added service '{name}'")

    async def remove_service(self, name: str):
        self._ensure_locks()
        async with self._lock:
            if name not in self.data.services:
                raise ServiceNotFoundError(f"Service '{name}' not found")
            
            for model_name, model in self.data.services[name].models.items():
                for key in model.keys:
                    self._key_timestamps.pop(key, None)
                    self._key_token_timestamps.pop(key, None)
                    self._key_token_totals.pop(key, None)
                    self._key_cooldowns.pop(key, None)
            
            del self.data.services[name]
            await self._save_data(immediate=True)
            logger.info(f"Removed service '{name}'")

    async def add_model(self, service: str, name: str, limits: Optional[KeyLimits] = None):
        self._ensure_locks()
        async with self._lock:
            svc = self._get_service(service)
            
            if name in svc.models:
                raise ApiKeyManagerError(f"Model '{name}' already exists in service '{service}'")
            
            svc.models[name] = ModelConfig(
                limits=limits or KeyLimits(),
                keys={}
            )
            await self._save_data(immediate=True)
            logger.info(f"Added model '{name}' to service '{service}'")

    async def remove_model(self, service: str, name: str):
        self._ensure_locks()
        async with self._lock:
            svc = self._get_service(service)
            
            if name not in svc.models:
                raise ModelNotFoundError(f"Model '{name}' not found in service '{service}'")
            
            for key in svc.models[name].keys:
                self._key_timestamps.pop(key, None)
                self._key_token_timestamps.pop(key, None)
                self._key_token_totals.pop(key, None)
                self._key_cooldowns.pop(key, None)
            
            del svc.models[name]
            
            if svc.default_model == name:
                svc.default_model = next(iter(svc.models.keys()), None)
            
            await self._save_data(immediate=True)
            logger.info(f"Removed model '{name}' from service '{service}'")

    def get_base_url(self, service: str) -> str:
        svc = self._get_service(service)
        return svc.base_url

    async def get_analytics(self, days: int = 7) -> Dict[str, Any]:
        now = self._get_now_utc()
        result = {}
        
        for i in range(days):
            date = (now - timedelta(days=i)).strftime("%Y-%m-%d")
            if date in self.data.analytics:
                result[date] = self.data.analytics[date].copy()
        
        return result

    async def get_all_key_previews(self, service: str, model: str) -> List[str]:
        """Get all key previews for a model (full keys for admin operations)."""
        mdl = self._get_model(service, model)
        return list(mdl.keys.keys())

    async def cleanup(self):
        """Cleanup resources on shutdown."""
        if self._save_pending:
            self._save_data_sync()
