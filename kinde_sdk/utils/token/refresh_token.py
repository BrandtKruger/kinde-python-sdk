"""
Kinde Python SDK - Refresh Token Module
Direct port of lib/utils/token/refreshToken.ts from js-utils
"""

import asyncio
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Callable, Dict, Any, Union
import httpx
from urllib.parse import urljoin, urlencode


class RefreshType(Enum):
    """Refresh type enumeration matching js-utils RefreshType"""
    REFRESH_TOKEN = "refresh_token"
    COOKIE = "cookie"


class StorageKeys(Enum):
    """Storage keys enumeration matching js-utils StorageKeys"""
    ACCESS_TOKEN = "accessToken"
    ID_TOKEN = "idToken"
    REFRESH_TOKEN = "refreshToken"
    STATE = "state"
    NONCE = "nonce"
    CODE_VERIFIER = "codeVerifier"


@dataclass
class RefreshTokenResult:
    """
    Result type for refresh token operations
    Matches js-utils RefreshTokenResult interface
    """
    success: bool
    error: Optional[str] = None
    access_token: Optional[str] = None
    id_token: Optional[str] = None
    refresh_token: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with camelCase keys to match JS"""
        result = {"success": self.success}
        if self.error:
            result["error"] = self.error
        if self.access_token:
            result[StorageKeys.ACCESS_TOKEN.value] = self.access_token
        if self.id_token:
            result[StorageKeys.ID_TOKEN.value] = self.id_token
        if self.refresh_token:
            result[StorageKeys.REFRESH_TOKEN.value] = self.refresh_token
        return result


class SessionManager:
    """
    Abstract base class for session management
    Matches js-utils SessionManager interface
    """
    
    async def get_session_item(self, key: Union[StorageKeys, str]) -> Optional[str]:
        """Get item from storage"""
        raise NotImplementedError
    
    async def set_session_item(self, key: Union[StorageKeys, str], value: str) -> None:
        """Set item in storage"""
        raise NotImplementedError
    
    async def remove_session_item(self, key: Union[StorageKeys, str]) -> None:
        """Remove item from storage"""
        raise NotImplementedError
    
    async def destroy_session(self) -> None:
        """Destroy entire session"""
        raise NotImplementedError


class StorageSettings:
    """Storage settings matching js-utils storageSettings"""
    def __init__(self):
        self.use_insecure_for_refresh_token = False


# Global instances matching js-utils pattern
storage_settings = StorageSettings()
_refresh_timer: Optional[asyncio.Task] = None
_active_storage: Optional[SessionManager] = None
_insecure_storage: Optional[SessionManager] = None


def get_active_storage() -> Optional[SessionManager]:
    """Get the active storage instance"""
    return _active_storage


def get_insecure_storage() -> Optional[SessionManager]:
    """Get the insecure storage instance"""
    return _insecure_storage


def set_active_storage(storage: SessionManager) -> None:
    """Set the active storage instance"""
    global _active_storage
    _active_storage = storage


def set_insecure_storage(storage: SessionManager) -> None:
    """Set the insecure storage instance"""
    global _insecure_storage
    _insecure_storage = storage


def is_custom_domain(domain: str) -> bool:
    """
    Check if domain is a custom domain (not *.kinde.com)
    Matches js-utils isCustomDomain logic
    """
    return not domain.endswith('.kinde.com')


def sanitize_url(url: str) -> str:
    """
    Remove trailing slash from URL
    Matches js-utils sanitizeUrl logic
    """
    return url.rstrip('/')


async def clear_refresh_timer() -> None:
    """
    Clear the existing refresh timer
    Matches js-utils clearRefreshTimer logic
    """
    global _refresh_timer
    if _refresh_timer and not _refresh_timer.done():
        _refresh_timer.cancel()
        _refresh_timer = None


async def set_refresh_timer(timer: int, callback: Callable[[], Any]) -> None:
    """
    Set a timer to refresh token before expiration
    Matches js-utils setRefreshTimer logic
    """
    await clear_refresh_timer()
    
    if timer <= 0:
        raise ValueError("Timer duration must be positive")
    
    # Refresh 10 seconds before expiry, max 24 hours (86400 seconds)
    delay = min(timer - 10, 86400)
    
    if delay > 0:
        global _refresh_timer
        _refresh_timer = asyncio.create_task(_delayed_callback(delay, callback))


async def _delayed_callback(delay: int, callback: Callable) -> None:
    """Execute callback after delay"""
    await asyncio.sleep(delay)
    await callback()


async def refresh_token(
    domain: str,
    client_id: str,
    refresh_type: RefreshType = RefreshType.REFRESH_TOKEN,
    on_refresh: Optional[Callable[[RefreshTokenResult], None]] = None
) -> RefreshTokenResult:
    """
    Refreshes the token
    Direct port of js-utils refreshToken function
    
    Args:
        domain: The Kinde domain URL
        client_id: The client ID
        refresh_type: Type of refresh (RefreshType.REFRESH_TOKEN or RefreshType.COOKIE)
        on_refresh: Optional callback function called with the result
        
    Returns:
        RefreshTokenResult with success status and new tokens
    """
    
    def handle_result(result: RefreshTokenResult) -> RefreshTokenResult:
        """Handle result and call callback if provided"""
        if on_refresh:
            on_refresh(result)
        return result
    
    # Validation - matches js-utils validation logic
    if not domain:
        return handle_result(RefreshTokenResult(
            success=False,
            error="Domain is required for token refresh"
        ))
    
    if not client_id:
        return handle_result(RefreshTokenResult(
            success=False,
            error="Client ID is required for token refresh"
        ))
    
    refresh_token_value = ""
    
    # Determine storage to use - matches js-utils storage selection logic
    if storage_settings.use_insecure_for_refresh_token or not is_custom_domain(domain):
        storage = get_insecure_storage()
    else:
        storage = get_active_storage()
    
    # Get refresh token if using refresh token flow
    if refresh_type == RefreshType.REFRESH_TOKEN:
        if not storage:
            return handle_result(RefreshTokenResult(
                success=False,
                error="No active storage found"
            ))
        
        refresh_token_value = await storage.get_session_item(StorageKeys.REFRESH_TOKEN)
        
        if not refresh_token_value:
            return handle_result(RefreshTokenResult(
                success=False,
                error="No refresh token found"
            ))
    
    # Clear existing refresh timer
    await clear_refresh_timer()
    
    try:
        # Prepare request URL - matches js-utils URL construction
        url = f"{sanitize_url(domain)}/oauth2/token"
        
        # Prepare headers - matches js-utils headers
        headers = {
            "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"
        }
        
        # Prepare form data - matches js-utils body construction
        form_data = {
            "grant_type": "refresh_token",
            "client_id": client_id
        }
        
        if refresh_type == RefreshType.REFRESH_TOKEN:
            form_data["refresh_token"] = refresh_token_value
        
        # Make request - matches js-utils fetch logic
        async with httpx.AsyncClient() as client:
            request_kwargs = {
                "method": "POST",
                "url": url,
                "headers": headers,
                "data": form_data
            }
            
            # Include credentials for cookie-based refresh
            if refresh_type == RefreshType.COOKIE:
                request_kwargs["cookies"] = True
            
            response = await client.request(**request_kwargs)
            
            if not response.is_success:
                return handle_result(RefreshTokenResult(
                    success=False,
                    error="Failed to refresh token"
                ))
            
            data = response.json()
            
            if "access_token" not in data:
                return handle_result(RefreshTokenResult(
                    success=False,
                    error="No access token received"
                ))
            
            # Store new tokens - matches js-utils token storage logic
            secure_store = get_active_storage()
            if not secure_store:
                return handle_result(RefreshTokenResult(
                    success=False,
                    error="No active storage found"
                ))
            
            # Set up auto-refresh timer if expires_in is provided
            if "expires_in" in data:
                expires_in = int(data["expires_in"])
                await set_refresh_timer(
                    expires_in,
                    lambda: refresh_token(domain, client_id, refresh_type, on_refresh)
                )
            
            # Store tokens
            if storage:
                await secure_store.set_session_item(
                    StorageKeys.ACCESS_TOKEN,
                    data["access_token"]
                )
                
                if "id_token" in data:
                    await secure_store.set_session_item(
                        StorageKeys.ID_TOKEN,
                        data["id_token"]
                    )
                
                if "refresh_token" in data:
                    await storage.set_session_item(
                        StorageKeys.REFRESH_TOKEN,
                        data["refresh_token"]
                    )
            
            return handle_result(RefreshTokenResult(
                success=True,
                access_token=data["access_token"],
                id_token=data.get("id_token"),
                refresh_token=data.get("refresh_token")
            ))
            
    except Exception as error:
        return handle_result(RefreshTokenResult(
            success=False,
            error=f"No access token received: {error}"
        ))
    
    # Fallback return - matches js-utils fallback
    return handle_result(RefreshTokenResult(
        success=False,
        error="No access token received"
    ))


# Example memory storage implementation for testing
class MemoryStorage(SessionManager):
    """
    In-memory storage implementation for testing
    Matches js-utils MemoryStorage behavior
    """
    
    def __init__(self):
        self._storage: Dict[str, str] = {}
    
    async def get_session_item(self, key: Union[StorageKeys, str]) -> Optional[str]:
        key_str = key.value if isinstance(key, StorageKeys) else key
        return self._storage.get(key_str)
    
    async def set_session_item(self, key: Union[StorageKeys, str], value: str) -> None:
        key_str = key.value if isinstance(key, StorageKeys) else key
        self._storage[key_str] = value
    
    async def remove_session_item(self, key: Union[StorageKeys, str]) -> None:
        key_str = key.value if isinstance(key, StorageKeys) else key
        self._storage.pop(key_str, None)
    
    async def destroy_session(self) -> None:
        self._storage.clear()


# Usage example matching js-utils patterns
async def example_usage():
    """Example usage of the refresh token functionality"""
    
    # Set up storage
    storage = MemoryStorage()
    set_active_storage(storage)
    set_insecure_storage(storage)
    
    # Set a refresh token (normally from login flow)
    await storage.set_session_item(StorageKeys.REFRESH_TOKEN, "your_refresh_token_here")
    
    # Define refresh callback
    def on_refresh_callback(result: RefreshTokenResult):
        if result.success:
            print("Token refreshed successfully!")
        else:
            print(f"Token refresh failed: {result.error}")
    
    # Refresh token
    result = await refresh_token(
        domain="https://yourdomain.kinde.com",
        client_id="your_client_id",
        refresh_type=RefreshType.REFRESH_TOKEN,
        on_refresh=on_refresh_callback
    )
    
    if result.success:
        print("Refresh successful!")
        print(f"New access token: {result.access_token[:20]}...")
    else:
        print(f"Refresh failed: {result.error}")
    
    return result


if __name__ == "__main__":
    asyncio.run(example_usage())
