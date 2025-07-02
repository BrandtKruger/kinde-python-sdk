"""
Kinde Python SDK - Is Authenticated Module
Direct port of lib/utils/token/isAuthenticated.ts from js-utils
"""

import time
from typing import Optional, Union
import jwt
from dataclasses import dataclass

from refresh_token import (
    get_active_storage,
    StorageKeys,
    refresh_token,
    RefreshType
)


@dataclass
class IsAuthenticatedPropsWithRefreshToken:
    """Props for isAuthenticated with refresh token support"""
    use_refresh_token: bool = True
    domain: str = ""
    client_id: str = ""


@dataclass
class IsAuthenticatedPropsWithoutRefreshToken:
    """Props for isAuthenticated without refresh token support"""
    use_refresh_token: bool = False
    domain: Optional[str] = None
    client_id: Optional[str] = None


# Type alias for the union of props
IsAuthenticatedProps = Union[
    IsAuthenticatedPropsWithRefreshToken,
    IsAuthenticatedPropsWithoutRefreshToken,
    None
]


async def get_decoded_token(token_type: str = "accessToken") -> Optional[dict]:
    """
    Get and decode a JWT token from storage
    
    Args:
        token_type: Type of token to retrieve ("accessToken" or "idToken")
        
    Returns:
        Decoded token payload or None if not found/invalid
    """
    storage = get_active_storage()
    if not storage:
        return None
    
    try:
        # Map token type to storage key
        if token_type == "accessToken":
            storage_key = StorageKeys.ACCESS_TOKEN
        elif token_type == "idToken":
            storage_key = StorageKeys.ID_TOKEN
        else:
            return None
        
        token = await storage.get_session_item(storage_key)
        if not token:
            return None
        
        # Decode without verification (just to read claims)
        decoded = jwt.decode(token, options={"verify_signature": False})
        return decoded
        
    except Exception as e:
        print(f"Error decoding token: {e}")
        return None


async def is_authenticated(props: IsAuthenticatedProps = None) -> bool:
    """
    Check if the user is authenticated with option to refresh the token
    Direct port of js-utils isAuthenticated function
    
    Args:
        props: Configuration object with refresh token options
        
    Returns:
        True if authenticated, False otherwise
    """
    try:
        # Get the decoded access token
        token = await get_decoded_token("accessToken")
        if not token:
            return False
        
        # Check if token has expiry claim
        if "exp" not in token:
            print("Token does not have an expiry")
            return False
        
        # Check if token is expired
        current_time = time.time()
        is_expired = token["exp"] < current_time
        
        # If token is expired and refresh is enabled, try to refresh
        if is_expired and props and getattr(props, 'use_refresh_token', False):
            domain = getattr(props, 'domain', None)
            client_id = getattr(props, 'client_id', None)
            
            if not domain or not client_id:
                print("Domain and client_id required for token refresh")
                return False
            
            # Attempt to refresh the token
            refresh_result = await refresh_token(
                domain=domain,
                client_id=client_id,
                refresh_type=RefreshType.REFRESH_TOKEN
            )
            
            return refresh_result.success
        
        # Return authentication status (not expired = authenticated)
        return not is_expired
        
    except Exception as error:
        print(f"Error checking authentication: {error}")
        return False


# Convenience functions for different authentication patterns
async def is_authenticated_simple() -> bool:
    """Simple authentication check without refresh"""
    return await is_authenticated()


async def is_authenticated_with_refresh(domain: str, client_id: str) -> bool:
    """Authentication check with automatic refresh if expired"""
    props = IsAuthenticatedPropsWithRefreshToken(
        use_refresh_token=True,
        domain=domain,
        client_id=client_id
    )
    return await is_authenticated(props)


# Usage example
async def example_usage():
    """Example usage of the authentication functions"""
    
    # Simple check (no refresh)
    is_auth_simple = await is_authenticated_simple()
    print(f"Simple auth check: {is_auth_simple}")
    
    # Check with automatic refresh
    is_auth_with_refresh = await is_authenticated_with_refresh(
        domain="https://yourdomain.kinde.com",
        client_id="your_client_id"
    )
    print(f"Auth check with refresh: {is_auth_with_refresh}")
    
    # Manual props construction
    props = IsAuthenticatedPropsWithRefreshToken(
        use_refresh_token=True,
        domain="https://yourdomain.kinde.com",
        client_id="your_client_id"
    )
    is_auth_manual = await is_authenticated(props)
    print(f"Manual props auth check: {is_auth_manual}")


if __name__ == "__main__":
    import asyncio
    asyncio.run(example_usage())
