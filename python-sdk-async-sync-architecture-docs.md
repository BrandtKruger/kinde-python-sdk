# Comprehensive Python SDK Documentation for PR #565

This file contains the comprehensive async/sync architecture documentation that should be integrated into the `python-sdk.mdx` file in the `kinde-oss/documentation` repository PR #565.

## Instructions

1. Clone the `kinde-oss/documentation` repository
2. Check out the branch for PR #565
3. Navigate to `src/content/docs/developer-tools/sdks/backend/python-sdk.mdx`
4. Integrate the sections below into the appropriate places in the existing file
5. Ensure proper MDX formatting (use proper heading levels, code blocks, etc.)

## Content to Add

### 1. Enhanced Client Selection Section

Add this after the "Configure your app" section:

```mdx
## Choosing the Right OAuth Client

The Kinde Python SDK provides three different OAuth client types to support various application patterns. Choose the one that best fits your needs:

### OAuth (Synchronous)
- **Use when**: Building traditional Flask applications or any synchronous Python application
- **Benefits**: Simple, straightforward API with no async complexity
- **Limitations**: Cannot be used in async contexts without special handling

```python
from kinde_sdk.auth.oauth import OAuth

oauth = OAuth(framework="flask", app=app)
user_info = oauth.get_user_info()  # Synchronous
```

### AsyncOAuth (Asynchronous)
- **Use when**: Building FastAPI applications or any async Python application
- **Benefits**: Fully async API that works seamlessly with async/await patterns
- **Limitations**: Cannot be used in sync contexts

```python
from kinde_sdk.auth.async_oauth import AsyncOAuth

oauth = AsyncOAuth(framework="fastapi", app=app)
user_info = await oauth.get_user_info_async()  # Asynchronous
```

### SmartOAuth (Context-Aware)
- **Use when**: Building applications that need to work in both sync and async contexts
- **Benefits**: Automatically adapts to the execution context, provides warnings for suboptimal usage
- **Limitations**: Slightly more complex, may show deprecation warnings

```python
from kinde_sdk.auth.smart_oauth import SmartOAuth

oauth = SmartOAuth(framework="fastapi", app=app)

# In async context - uses async methods automatically
async def async_function():
    user_info = await oauth.get_user_info_async()

# In sync context - uses sync methods with warnings
def sync_function():
    user_info = oauth.get_user_info()  # Shows warning in async context
```

### Standalone Usage (No Framework)
- **Use when**: Building serverless functions, Lambda functions, or applications without web frameworks
- **Benefits**: No framework dependencies, works in any Python environment
- **Requirements**: Manual session management using `KindeSessionManagement`

```python
from kinde_sdk.auth.async_oauth import AsyncOAuth
from kinde_sdk import KindeSessionManagement

# Initialize OAuth without framework
oauth = AsyncOAuth(
    framework=None,  # Uses null framework
    client_id="your_client_id",
    client_secret="your_client_secret",
    redirect_uri="your_redirect_uri",
    host="https://yourdomain.kinde.com"
)

# Initialize session management
session_mgmt = KindeSessionManagement()

# In your serverless function
async def lambda_handler(event, context):
    session_id = event.get("headers", {}).get("x-session-id", "default")
    
    # Set the current user session
    session_mgmt.set_user_id(session_id)
    
    # Now you can use OAuth methods
    if oauth.is_authenticated():
        user_info = await oauth.get_user_info_async()
        return {"user": user_info}
```

### Quick Decision Tree

```
Is your application fully async (FastAPI, async endpoints)?
├─ Yes → Use AsyncOAuth
└─ No
   ├─ Is your application fully sync (Flask, traditional Python)?
   │  └─ Yes → Use OAuth
   └─ Do you need to support both sync and async contexts?
      └─ Yes → Use SmartOAuth
```
```

### 2. Enhanced Standalone Usage Section

Add this as a new section after the manual route implementation:

```mdx
## Standalone Usage (Serverless/Lambda)

For serverless functions (AWS Lambda, Google Cloud Functions, etc.), you need to manage sessions manually using `KindeSessionManagement`.

### AWS Lambda Example

```python
import json
import os
from kinde_sdk import AsyncOAuth, KindeSessionManagement
from kinde_sdk.core.exceptions import KindeConfigurationException

# Initialize session management
session_mgmt = KindeSessionManagement()

# Initialize OAuth client without framework
oauth = AsyncOAuth(
    framework=None,  # No framework for serverless
    client_id=os.getenv("KINDE_CLIENT_ID"),
    client_secret=os.getenv("KINDE_CLIENT_SECRET"),
    redirect_uri=os.getenv("KINDE_REDIRECT_URI"),
    host=os.getenv("KINDE_HOST", "https://app.kinde.com")
)

def lambda_handler(event, context):
    """AWS Lambda handler for OAuth flow."""
    path = event.get("path", "")
    query_params = event.get("queryStringParameters") or {}
    
    # Extract session ID from event (could be from cookies, headers, etc.)
    session_id = event.get("headers", {}).get("x-session-id") or "default-session"
    
    # Set user session
    session_mgmt.set_user_id(session_id)
    
    if path == "/login":
        # Generate login URL
        import asyncio
        login_url = asyncio.run(oauth.login())
        return {
            "statusCode": 302,
            "headers": {"Location": login_url}
        }
    
    elif path == "/callback":
        # Handle OAuth callback
        code = query_params.get("code")
        state = query_params.get("state")
        
        try:
            import asyncio
            result = asyncio.run(oauth.handle_redirect(code=code, state=state))
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "Authentication successful"})
            }
        except Exception as e:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": str(e)})
            }
    
    elif path == "/user":
        # Get user info
        if oauth.is_authenticated():
            import asyncio
            user_info = asyncio.run(oauth.get_user_info_async())
            return {
                "statusCode": 200,
                "body": json.dumps({"user": user_info})
            }
        return {
            "statusCode": 401,
            "body": json.dumps({"error": "Not authenticated"})
        }
    
    elif path == "/logout":
        # Logout
        import asyncio
        logout_url = asyncio.run(oauth.logout(user_id=session_id))
        session_mgmt.clear_user_id()
        return {
            "statusCode": 302,
            "headers": {"Location": logout_url}
        }
    
    return {
        "statusCode": 404,
        "body": json.dumps({"error": "Not found"})
    }
```

### Google Cloud Functions Example

```python
import json
import os
from kinde_sdk import AsyncOAuth, KindeSessionManagement

session_mgmt = KindeSessionManagement()

oauth = AsyncOAuth(
    framework=None,
    client_id=os.getenv("KINDE_CLIENT_ID"),
    client_secret=os.getenv("KINDE_CLIENT_SECRET"),
    redirect_uri=os.getenv("KINDE_REDIRECT_URI"),
    host=os.getenv("KINDE_HOST", "https://app.kinde.com")
)

async def cloud_function_handler(request):
    """Google Cloud Functions handler."""
    path = request.path
    session_id = request.headers.get("X-Session-ID", "default-session")
    
    # Set user session
    session_mgmt.set_user_id(session_id)
    
    if path == "/login":
        login_url = await oauth.login()
        return {"status": 302, "headers": {"Location": login_url}}
    
    elif path == "/callback":
        code = request.args.get("code")
        state = request.args.get("state")
        
        try:
            result = await oauth.handle_redirect(code=code, state=state)
            return {"status": 200, "body": {"message": "Authentication successful"}}
        except Exception as e:
            return {"status": 400, "body": {"error": str(e)}}
    
    elif path == "/user":
        if oauth.is_authenticated():
            user_info = await oauth.get_user_info_async()
            return {"status": 200, "body": {"user": user_info}}
        return {"status": 401, "body": {"error": "Not authenticated"}}
    
    elif path == "/logout":
        logout_url = await oauth.logout(user_id=session_id)
        session_mgmt.clear_user_id()
        return {"status": 302, "headers": {"Location": logout_url}}
    
    return {"status": 404, "body": {"error": "Not found"}}
```
```

### 3. Enhanced Error Handling Section

Add this as a new section before "Best practices":

```mdx
## Error Handling

The SDK raises several exception types that you should handle appropriately:

- `KindeConfigurationException` - Configuration errors (missing client ID, etc.)
- `KindeLoginException` - Login/authentication errors
- `KindeTokenException` - Token-related errors (token exchange failures, etc.)
- `KindeRetrieveException` - Data retrieval errors

### Error Handling in Flask (Sync)

```python
from flask import Flask, jsonify, redirect
from kinde_sdk import OAuth
from kinde_sdk.core.exceptions import (
    KindeConfigurationException,
    KindeLoginException,
    KindeTokenException
)
import asyncio

app = Flask(__name__)
oauth = OAuth(framework="flask", app=app)

@app.route("/login")
def login():
    """Handle login with error handling."""
    try:
        login_url = asyncio.run(oauth.login())
        return redirect(login_url)
    except KindeConfigurationException as e:
        return jsonify({"error": f"Configuration error: {str(e)}"}), 500
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500

@app.route("/callback")
def callback():
    """Handle callback with error handling."""
    code = request.args.get("code")
    state = request.args.get("state")
    
    try:
        result = asyncio.run(oauth.handle_redirect(code=code, state=state))
        return redirect("/")
    except KindeTokenException as e:
        return jsonify({"error": f"Token error: {str(e)}"}), 400
    except KindeLoginException as e:
        return jsonify({"error": f"Login error: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": f"Unexpected error: {str(e)}"}), 500
```

### Error Handling in FastAPI (Async)

```python
from fastapi import FastAPI, HTTPException
from fastapi.responses import RedirectResponse
from kinde_sdk import AsyncOAuth
from kinde_sdk.core.exceptions import (
    KindeConfigurationException,
    KindeLoginException,
    KindeTokenException
)

app = FastAPI()
oauth = AsyncOAuth(framework="fastapi", app=app)

@app.get("/login")
async def login():
    """Handle login with error handling."""
    try:
        login_url = await oauth.login()
        return RedirectResponse(url=login_url)
    except KindeConfigurationException as e:
        raise HTTPException(status_code=500, detail=f"Configuration error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")

@app.get("/callback")
async def callback(code: str, state: str = None):
    """Handle callback with error handling."""
    try:
        result = await oauth.handle_redirect(code=code, state=state)
        return RedirectResponse(url="/")
    except KindeTokenException as e:
        raise HTTPException(status_code=400, detail=f"Token error: {str(e)}")
    except KindeLoginException as e:
        raise HTTPException(status_code=400, detail=f"Login error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {str(e)}")
```

### Error Handling for Auth Modules

```python
from kinde_sdk.auth import permissions, claims, feature_flags
from kinde_sdk.core.exceptions import KindeConfigurationException

async def safe_get_permission(permission_key: str):
    """Safely get permission with error handling."""
    try:
        permission = await permissions.get_permission(permission_key)
        return permission
    except KindeConfigurationException:
        # User not authenticated or token manager not available
        return {"permissionKey": permission_key, "isGranted": False, "orgCode": None}
    except Exception as e:
        # Log error and return safe default
        logger.error(f"Error getting permission: {e}")
        return {"permissionKey": permission_key, "isGranted": False, "orgCode": None}
```
```

### 4. Enhanced Best Practices Section

Replace or enhance the existing "Best practices" section:

```mdx
## Best Practices

### 1. Choose the Right Client

- **Flask applications**: Use `OAuth` (sync client)
- **FastAPI applications**: Use `AsyncOAuth` or `SmartOAuth`
- **Serverless/Lambda**: Use `AsyncOAuth` with `KindeSessionManagement`
- **Mixed contexts**: Use `SmartOAuth`

### 2. Consistent Async Patterns

- Always use `await` for async methods
- Use `asyncio.run()` in sync contexts when calling async methods
- Prefer async methods in async contexts for better performance

### 3. Error Handling

- Always wrap OAuth operations in try/except blocks
- Handle specific exception types appropriately
- Provide meaningful error messages to users
- Log errors for debugging

### 4. Session Management

- Use framework session management when available (Flask, FastAPI)
- Use `KindeSessionManagement` for serverless/standalone usage
- Always clear sessions on logout

### 5. Token Management

- Let the SDK handle token refresh automatically
- Don't manually manipulate tokens unless necessary
- Store tokens securely using the SDK's storage mechanisms

### 6. Performance Optimization

- Use async clients in async contexts for better performance
- Cache permission/claim/flag results when appropriate
- Avoid unnecessary token refreshes

### 7. Security Best Practices

- Always validate state parameters in OAuth callbacks
- Use HTTPS in production
- Store secrets securely (environment variables, secret managers)
- Implement proper session timeout handling

### 8. Testing

- Test both sync and async paths
- Mock external API calls in tests
- Test error handling scenarios
- Test session management edge cases
```

### 5. Migration Recommendations Section

Add this as a new section:

```mdx
## Migration Recommendations

### From OAuth to AsyncOAuth

If you're using `OAuth` in a FastAPI application, migrate to `AsyncOAuth`:

**Before:**
```python
from kinde_sdk import OAuth
import asyncio

oauth = OAuth(framework="fastapi", app=app)

@app.get("/")
async def home():
    if oauth.is_authenticated():
        user_info = oauth.get_user_info()  # Sync method
        return {"user": user_info}
```

**After:**
```python
from kinde_sdk import AsyncOAuth

oauth = AsyncOAuth(framework="fastapi", app=app)

@app.get("/")
async def home():
    if oauth.is_authenticated():
        user_info = await oauth.get_user_info_async()  # Async method
        return {"user": user_info}
```

### Migrating to SmartOAuth

For applications that need flexibility:

**Before:**
```python
from kinde_sdk import OAuth

oauth = OAuth(framework="fastapi", app=app)
```

**After:**
```python
from kinde_sdk import SmartOAuth

oauth = SmartOAuth(framework="fastapi", app=app)

# Can use both sync and async methods
# In async context, prefer async methods
user_info = await oauth.get_user_info_async()
```

### Common Migration Issues

1. **"RuntimeError: no running event loop"**
   - Solution: Use `asyncio.run()` in sync contexts or use sync client

2. **"DeprecationWarning: Using sync method in async context"**
   - Solution: Use `_async` version of methods or switch to `AsyncOAuth`

3. **"AttributeError: 'OAuth' object has no attribute 'get_user_info_async'"**
   - Solution: Use `AsyncOAuth` or `SmartOAuth` for async methods
```

### 6. Important Notes Section

Add this near the end, before the Management API section:

```mdx
## Important Notes

### Async/Sync Consistency

The SDK now provides consistent async and sync APIs to address previous inconsistencies:
- **Auth modules** (permissions, claims, feature_flags) are async and work with all client types
- **OAuth methods** are now properly separated into sync and async versions
- **SmartOAuth** provides a unified interface that adapts to the execution context

### Backward Compatibility

All existing code continues to work without changes:
- The original `OAuth` class remains unchanged
- Existing sync methods remain sync
- Existing async methods remain async
- No breaking changes to the public API

### Migration Recommendations

- **New Flask projects**: Use `OAuth` for simplicity
- **New FastAPI projects**: Use `AsyncOAuth` for best performance
- **Mixed projects**: Use `SmartOAuth` for flexibility
- **Serverless/Lambda**: Use `AsyncOAuth` with `framework=None`
- **Existing projects**: No changes required, but consider migrating for better consistency
```

## Summary

This comprehensive documentation covers:

1. ✅ AsyncOAuth client for native async applications
2. ✅ SmartOAuth client for context-aware async/sync usage
3. ✅ Standalone usage patterns for serverless/Lambda functions
4. ✅ Updated code examples with proper sync/async patterns
5. ✅ Framework-specific implementation guides (Flask, FastAPI)
6. ✅ Restructured authentication flow documentation
7. ✅ Migration recommendations and client selection guide
8. ✅ Updated permissions, claims, and feature flags examples
9. ✅ Management API sync/async usage patterns
10. ✅ Improved error handling and best practices sections

Integrate these sections into the existing `python-sdk.mdx` file in the documentation repository PR #565.
