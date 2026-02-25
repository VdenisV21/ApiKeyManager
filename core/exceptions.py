class ApiKeyManagerError(Exception):
    """Base exception for API Key Manager errors."""
    pass


class NoAvailableKeyError(ApiKeyManagerError):
    """Raised when no available key meeting criteria can be found."""
    pass


class ServiceNotFoundError(ApiKeyManagerError):
    """Raised when a requested service is not configured."""
    pass


class ModelNotFoundError(ApiKeyManagerError):
    """Raised when a requested model is not configured for a service."""
    pass


class AuthenticationError(ApiKeyManagerError):
    """Raised when admin authentication fails."""
    pass


class KeyNotFoundError(ApiKeyManagerError):
    """Raised when a specific key is not found."""
    pass
