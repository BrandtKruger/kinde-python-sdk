"""
Kinde Python SDK - Token Manager
Comprehensive token management class that mirrors js-utils token functionality
"""

import asyncio
import time
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Dict, Any, List, Union, Callable, TypeVar, Generic
import jwt
import httpx
from urllib.parse import urljoin

# Type variables for generics
T = TypeVar('T')
V = TypeVar('V')


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
    """Result type for refresh token operations"""
    success: bool
    error: Optional[str] = None
    access_token: Optional[str] = None
    id_token: Optional[str] = None
    refresh_token: Optional[str] = None


@dataclass
class UserProfile:
    """User profile data structure"""
    id: str
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    email: Optional[str] = None
    picture: Optional[str] = None


@dataclass
class Role:
    """Role data structure"""
    id: str
    name: str
    key: str


@dataclass
class Permissions:
    """Permissions data structure"""
    org_code: Optional[str]
    permissions: List[str]


@dataclass
class Claim:
    """Claim data structure"""
    name: str
    value: Any


class SessionManager(ABC):
    """Abstract base class for session management"""
    
    @abstractmethod
    async def get_session_item(self, key: Union[StorageKeys, str]) -> Optional[str]:
        """Get item from storage"""
        pass
    
    @abstractmethod
    async def set_session_item(self, key: Union[StorageKeys, str], value: str) -> None:
        """Set item in storage"""
        pass
    
    @abstractmethod
    async def remove_session_item(self, key: Union[StorageKeys, str]) -> None:
        """Remove item from storage"""
        pass
    
    @abstractmethod
    async def destroy_session(self) -> None:
        """Destroy entire session"""
        pass


class MemoryStorage(SessionManager):
    """In-memory storage implementation for testing"""
    
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


class StorageSettings:
    """Storage settings matching js-utils storageSettings"""
    def __init__(self):
        self.use_insecure_for_refresh_token = False


class TokenManager:
    """
    Comprehensive token manager that mirrors js-utils token functionality
    """
    
    def __init__(self):
        self._secure_storage: Optional[SessionManager] = None
        self._insecure_storage: Optional[SessionManager] = None
        self._refresh_timer: Optional[asyncio.Task] = None
        self.storage_settings = StorageSettings()
    
    # Storage Management (mirrors js-utils storage functions)
    
    def set_active_storage(self, storage: SessionManager) -> None:
        """Set the active (secure) storage"""
        self._secure_storage = storage
    
    def get_active_storage(self) -> Optional[SessionManager]:
        """Get the active (secure) storage"""
        return self._secure_storage
    
    def has_active_storage(self) -> bool:
        """Check if active storage exists"""
        return self._secure_storage is not None
    
    def clear_active_storage(self) -> None:
        """Clear the active storage"""
        self._secure_storage = None
    
    def set_insecure_storage(self, storage: SessionManager) -> None:
        """Set the insecure storage"""
        self._insecure_storage = storage
    
    def get_insecure_storage(self) -> Optional[SessionManager]:
        """Get the insecure storage (falls back to secure storage)"""
        return self._insecure_storage or self._secure_storage
    
    def has_insecure_storage(self) -> bool:
        """Check if insecure storage exists"""
        return self._insecure_storage is not None
    
    def clear_insecure_storage(self) -> None:
        """Clear the insecure storage"""
        self._insecure_storage = None
    
    # Utility Functions
    
    def _is_custom_domain(self, domain: str) -> bool:
        """Check if domain is a custom domain (not *.kinde.com)"""
        return not domain.endswith('.kinde.com')
    
    def _sanitize_url(self, url: str) -> str:
        """Remove trailing slash from URL"""
        return url.rstrip('/')
    
    # Timer Management (mirrors js-utils refresh timer functions)
    
    async def clear_refresh_timer(self) -> None:
        """Clear the existing refresh timer"""
        if self._refresh_timer and not self._refresh_timer.done():
            self._refresh_timer.cancel()
            self._refresh_timer = None
    
    async def set_refresh_timer(self, timer: int, callback: Callable[[], Any]) -> None:
        """Set a timer to refresh token before expiration"""
        await self.clear_refresh_timer()
        
        if timer <= 0:
            raise ValueError("Timer duration must be positive")
        
        # Refresh 10 seconds before expiry, max 24 hours
        delay = min(timer - 10, 86400)
        
        if delay > 0:
            self._refresh_timer = asyncio.create_task(self._delayed_callback(delay, callback))
    
    async def _delayed_callback(self, delay: int, callback: Callable) -> None:
        """Execute callback after delay"""
        await asyncio.sleep(delay)
        await callback()
    
    # Core Token Operations (mirrors js-utils token functions)
    
    async def get_raw_token(self, token_type: str = "accessToken") -> Optional[str]:
        """
        Get raw JWT token from storage
        Mirrors js-utils getRawToken
        """
        storage = self.get_active_storage()
        if not storage:
            return None
        
        storage_key = StorageKeys.ACCESS_TOKEN if token_type == "accessToken" else StorageKeys.ID_TOKEN
        token = await storage.get_session_item(storage_key)
        
        return token if token else None
    
    async def get_decoded_token(self, token_type: str = "accessToken") -> Optional[Dict[str, Any]]:
        """
        Get and decode JWT token from storage
        Mirrors js-utils getDecodedToken
        """
        token = await self.get_raw_token(token_type)
        if not token:
            return None
        
        try:
            # Decode without verification (just to read claims)
            decoded = jwt.decode(token, options={"verify_signature": False})
            return decoded
        except Exception as e:
            print(f"Warning: No decoded token found: {e}")
            return None
    
    async def get_claims(self, token_type: str = "accessToken") -> Optional[Dict[str, Any]]:
        """
        Get all claims from token
        Mirrors js-utils getClaims
        """
        return await self.get_decoded_token(token_type)
    
    async def get_claim(self, key_name: str, token_type: str = "accessToken") -> Optional[Claim]:
        """
        Get a specific claim from token
        Mirrors js-utils getClaim
        """
        claims = await self.get_claims(token_type)
        if not claims or key_name not in claims:
            return None
        
        return Claim(name=key_name, value=claims[key_name])
    
    # Authentication Functions (mirrors js-utils isAuthenticated)
    
    async def is_authenticated(
        self,
        use_refresh_token: bool = False,
        domain: Optional[str] = None,
        client_id: Optional[str] = None
    ) -> bool:
        """
        Check if user is authenticated with optional token refresh
        Mirrors js-utils isAuthenticated
        """
        try:
            token = await self.get_decoded_token("accessToken")
            if not token:
                return False
            
            if "exp" not in token:
                print("Token does not have an expiry")
                return False
            
            is_expired = token["exp"] < time.time()
            
            if is_expired and use_refresh_token:
                if not domain or not client_id:
                    print("Domain and client_id required for token refresh")
                    return False
                
                refresh_result = await self.refresh_token(domain, client_id)
                return refresh_result.success
            
            return not is_expired
            
        except Exception as error:
            print(f"Error checking authentication: {error}")
            return False
    
    # Refresh Token Functions (mirrors js-utils refreshToken)
    
    async def refresh_token(
        self,
        domain: str,
        client_id: str,
        refresh_type: RefreshType = RefreshType.REFRESH_TOKEN,
        on_refresh: Optional[Callable[[RefreshTokenResult], None]] = None
    ) -> RefreshTokenResult:
        """
        Refresh the access token
        Mirrors js-utils refreshToken
        """
        def handle_result(result: RefreshTokenResult) -> RefreshTokenResult:
            if on_refresh:
                on_refresh(result)
            return result
        
        # Validation
        if not domain:
            return handle_result(RefreshTokenResult(
                success=False, error="Domain is required for token refresh"
            ))
        
        if not client_id:
            return handle_result(RefreshTokenResult(
                success=False, error="Client ID is required for token refresh"
            ))
        
        # Determine storage to use
        if self.storage_settings.use_insecure_for_refresh_token or not self._is_custom_domain(domain):
            storage = self.get_insecure_storage()
        else:
            storage = self.get_active_storage()
        
        # Get refresh token if needed
        refresh_token_value = ""
        if refresh_type == RefreshType.REFRESH_TOKEN:
            if not storage:
                return handle_result(RefreshTokenResult(
                    success=False, error="No active storage found"
                ))
            
            refresh_token_value = await storage.get_session_item(StorageKeys.REFRESH_TOKEN)
            if not refresh_token_value:
                return handle_result(RefreshTokenResult(
                    success=False, error="No refresh token found"
                ))
        
        await self.clear_refresh_timer()
        
        try:
            url = f"{self._sanitize_url(domain)}/oauth2/token"
            headers = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
            
            form_data = {
                "grant_type": "refresh_token",
                "client_id": client_id
            }
            
            if refresh_type == RefreshType.REFRESH_TOKEN:
                form_data["refresh_token"] = refresh_token_value
            
            async with httpx.AsyncClient() as client:
                request_kwargs = {
                    "method": "POST",
                    "url": url,
                    "headers": headers,
                    "data": form_data
                }
                
                if refresh_type == RefreshType.COOKIE:
                    request_kwargs["cookies"] = True
                
                response = await client.request(**request_kwargs)
                
                if not response.is_success:
                    return handle_result(RefreshTokenResult(
                        success=False, error="Failed to refresh token"
                    ))
                
                data = response.json()
                
                if "access_token" not in data:
                    return handle_result(RefreshTokenResult(
                        success=False, error="No access token received"
                    ))
                
                # Store new tokens
                secure_store = self.get_active_storage()
                if not secure_store:
                    return handle_result(RefreshTokenResult(
                        success=False, error="No active storage found"
                    ))
                
                # Set up auto-refresh timer
                if "expires_in" in data:
                    expires_in = int(data["expires_in"])
                    await self.set_refresh_timer(
                        expires_in,
                        lambda: self.refresh_token(domain, client_id, refresh_type, on_refresh)
                    )
                
                # Store tokens
                if storage:
                    await secure_store.set_session_item(StorageKeys.ACCESS_TOKEN, data["access_token"])
                    
                    if "id_token" in data:
                        await secure_store.set_session_item(StorageKeys.ID_TOKEN, data["id_token"])
                    
                    if "refresh_token" in data:
                        await storage.set_session_item(StorageKeys.REFRESH_TOKEN, data["refresh_token"])
                
                return handle_result(RefreshTokenResult(
                    success=True,
                    access_token=data["access_token"],
                    id_token=data.get("id_token"),
                    refresh_token=data.get("refresh_token")
                ))
                
        except Exception as error:
            return handle_result(RefreshTokenResult(
                success=False, error=f"No access token received: {error}"
            ))
        
        return handle_result(RefreshTokenResult(
            success=False, error="No access token received"
        ))
    
    # User Profile Functions (mirrors js-utils getUserProfile)
    
    async def get_user_profile(self) -> Optional[UserProfile]:
        """
        Get user profile from ID token
        Mirrors js-utils getUserProfile
        """
        id_token = await self.get_claims("idToken")
        if not id_token:
            return None
        
        if "sub" not in id_token:
            print("No sub in idToken")
            return None
        
        return UserProfile(
            id=id_token["sub"],
            given_name=id_token.get("given_name"),
            family_name=id_token.get("family_name"),
            email=id_token.get("email"),
            picture=id_token.get("picture")
        )
    
    # Permissions Functions (mirrors js-utils getPermissions/getPermission)
    
    async def get_permissions(self) -> Permissions:
        """
        Get all permissions
        Mirrors js-utils getPermissions
        """
        token = await self.get_decoded_token()
        
        if not token:
            return Permissions(org_code=None, permissions=[])
        
        permissions = token.get("permissions", token.get("x-hasura-permissions", []))
        org_code = token.get("org_code", token.get("x-hasura-org-code"))
        
        return Permissions(org_code=org_code, permissions=permissions)
    
    async def get_permission(self, permission_name: str) -> bool:
        """
        Check if user has a specific permission
        Mirrors js-utils getPermission
        """
        permissions = await self.get_permissions()
        return permission_name in permissions.permissions
    
    # Roles Functions (mirrors js-utils getRoles)
    
    async def get_roles(self) -> List[Role]:
        """
        Get all user roles
        Mirrors js-utils getRoles
        """
        token = await self.get_decoded_token()
        
        if not token:
            return []
        
        roles_data = token.get("roles", token.get("x-hasura-roles"))
        
        if not roles_data:
            print("No roles found in token, ensure roles have been included in the token customisation")
            return []
        
        return [
            Role(id=role["id"], name=role["name"], key=role["key"])
            for role in roles_data
        ]
    
    # Feature Flags Functions (mirrors js-utils getFlag)
    
    async def get_flag(self, flag_name: str) -> Any:
        """
        Get feature flag value
        Mirrors js-utils getFlag
        """
        claims = await self.get_decoded_token()
        
        if not claims:
            return None
        
        flags = claims.get("feature_flags", claims.get("x-hasura-feature-flags"))
        
        if not flags:
            return None
        
        flag_data = flags.get(flag_name)
        return flag_data.get("v") if flag_data else None
    
    # Organization Functions (mirrors js-utils getCurrentOrganization/getUserOrganizations)
    
    async def get_current_organization(self) -> Optional[str]:
        """
        Get current organization code
        Mirrors js-utils getCurrentOrganization
        """
        token = await self.get_decoded_token()
        
        if not token:
            return None
        
        return token.get("org_code", token.get("x-hasura-org-code"))
    
    async def get_user_organizations(self) -> Optional[List[str]]:
        """
        Get all organization codes user belongs to
        Mirrors js-utils getUserOrganizations
        """
        token = await self.get_decoded_token("idToken")
        
        if not token:
            return None
        
        org_codes = token.get("org_codes", token.get("x-hasura-org-codes"))
        
        if not org_codes:
            print("Org codes not found in token, ensure org codes have been included in token customisation")
            return None
        
        return org_codes
    
    # Entitlements (placeholder for future implementation)
    
    async def get_entitlements(self) -> List[Any]:
        """
        Get user entitlements
        Placeholder for js-utils getEntitlements functionality
        """
        # This would need to be implemented based on Kinde's entitlements structure
        token = await self.get_decoded_token()
        if not token:
            return []
        
        return token.get("entitlements", [])


# Usage Example
async def example_usage():
    """Example usage of the TokenManager"""
    
    # Initialize TokenManager
    token_manager = TokenManager()
    
    # Set up storage
    storage = MemoryStorage()
    token_manager.set_active_storage(storage)
    token_manager.set_insecure_storage(storage)
    
    # Set some mock tokens (normally from login flow)
    await storage.set_session_item(StorageKeys.REFRESH_TOKEN, "mock_refresh_token")
    await storage.set_session_item(StorageKeys.ACCESS_TOKEN, "mock_access_token")
    
    # Authentication check with refresh
    is_auth = await token_manager.is_authenticated(
        use_refresh_token=True,
        domain="https://yourdomain.kinde.com",
        client_id="your_client_id"
    )
    print(f"Authenticated: {is_auth}")
    
    # Get user profile
    profile = await token_manager.get_user_profile()
    if profile:
        print(f"User: {profile.given_name} {profile.family_name}")
    
    # Get permissions
    permissions = await token_manager.get_permissions()
    print(f"User permissions: {permissions.permissions}")
    
    # Get roles
    roles = await token_manager.get_roles()
    for role in roles:
        print(f"Role: {role.name} ({role.key})")
    
    # Get feature flag
    flag_value = await token_manager.get_flag("feature_flag_name")
    print(f"Feature flag: {flag_value}")
    
    # Get organization info
    current_org = await token_manager.get_current_organization()
    user_orgs = await token_manager.get_user_organizations()
    print(f"Current org: {current_org}")
    print(f"User orgs: {user_orgs}")


if __name__ == "__main__":
    asyncio.run(example_usage())
