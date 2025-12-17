# Kinde Python SDK: Comprehensive Async/Sync Architecture Guide

## Table of Contents

1. [Overview](#overview)
2. [Client Selection Guide](#client-selection-guide)
3. [Client Types](#client-types)
4. [Authentication Flows](#authentication-flows)
5. [Framework-Specific Implementations](#framework-specific-implementations)
6. [Standalone Usage (Serverless/Lambda)](#standalone-usage-serverlesslambda)
7. [Permissions, Claims, and Feature Flags](#permissions-claims-and-feature-flags)
8. [Management API Usage](#management-api-usage)
9. [Error Handling](#error-handling)
10. [Best Practices](#best-practices)
11. [Migration Guide](#migration-guide)

## Overview

The Kinde Python SDK provides three client types to support both synchronous and asynchronous applications:

- **`OAuth`**: Synchronous client for traditional Python applications
- **`AsyncOAuth`**: Native async client for fully asynchronous applications
- **`SmartOAuth`**: Context-aware client that automatically adapts to sync/async contexts

This guide provides comprehensive documentation for using these clients effectively in different scenarios.

## Client Selection Guide

### When to Use Each Client

#### Use `OAuth` (Sync Client) When:
- Building traditional Flask applications
- Working with synchronous Python codebases
- Using blocking I/O operations
- You prefer explicit synchronous APIs

#### Use `AsyncOAuth` (Async Client) When:
- Building FastAPI applications
- Working with fully async codebases
- Using async/await patterns throughout your application
- You want optimal async performance

#### Use `SmartOAuth` (Smart Client) When:
- Building applications that mix sync and async code
- Migrating from sync to async gradually
- You want automatic context detection
- You need flexibility across different execution contexts

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

## Client Types

### 1. Sync Client (`OAuth`)

The original synchronous client for traditional Python applications.

#### Basic Usage

```python
from kinde_sdk import OAuth

# Initialize with Flask
from flask import Flask
app = Flask(__name__)

oauth = OAuth(
    framework="flask",
    app=app
)

# Sync methods
@app.route('/')
def home():
    if oauth.is_authenticated():
        user_info = oauth.get_user_info()  # Sync method
        return f"Welcome, {user_info['email']}!"
    return "Please login"
```

#### Available Methods

- `is_authenticated()` - Check authentication status (sync)
- `get_user_info()` - Get user information (sync)
- `login()` - Generate login URL (async - for OAuth flow)
- `register()` - Generate registration URL (async - for OAuth flow)
- `logout()` - Generate logout URL (async - for OAuth flow)
- `handle_redirect()` - Handle OAuth callback (async)

### 2. Async Client (`AsyncOAuth`)

Native async client for fully asynchronous applications.

#### Basic Usage

```python
from kinde_sdk import AsyncOAuth

# Initialize with FastAPI
from fastapi import FastAPI
app = FastAPI()

oauth = AsyncOAuth(
    framework="fastapi",
    app=app
)

# Async methods
@app.get('/')
async def home():
    if oauth.is_authenticated():
        user_info = await oauth.get_user_info_async()  # Async method
        return {"message": f"Welcome, {user_info['email']}!"}
    return {"message": "Please login"}
```

#### Available Methods

- `is_authenticated()` - Check authentication status (sync - reads from session)
- `get_user_info_async()` - Get user information (async)
- `login()` - Generate login URL (async)
- `register()` - Generate registration URL (async)
- `logout()` - Generate logout URL (async)
- `handle_redirect()` - Handle OAuth callback (async)

### 3. Smart Client (`SmartOAuth`)

Context-aware client that automatically adapts to sync/async contexts.

#### Basic Usage

```python
from kinde_sdk import SmartOAuth

# Initialize with FastAPI
from fastapi import FastAPI
app = FastAPI()

oauth = SmartOAuth(
    framework="fastapi",
    app=app
)

# Works in both sync and async contexts
def sync_function():
    if oauth.is_authenticated():
        user_info = oauth.get_user_info()  # Sync
        return user_info

async def async_function():
    if oauth.is_authenticated():
        user_info = await oauth.get_user_info_async()  # Async
        return user_info
```

#### Available Methods

- `is_authenticated()` - Check authentication status (sync, warns in async context)
- `get_user_info()` - Get user information (sync, warns in async context)
- `get_user_info_async()` - Get user information (async, recommended)
- `login()` - Generate login URL (async)
- `register()` - Generate registration URL (async)
- `logout()` - Generate logout URL (async)
- `handle_redirect()` - Handle OAuth callback (async)

#### Factory Function

Use the factory function for explicit control:

```python
from kinde_sdk import create_oauth_client

# Explicit sync client
oauth = create_oauth_client(
    async_mode=False,
    framework="flask",
    app=app
)

# Explicit async client
oauth = create_oauth_client(
    async_mode=True,
    framework="fastapi",
    app=app
)

# Smart client (default - auto-detect)
oauth = create_oauth_client(
    framework="fastapi",
    app=app
)
```

## Authentication Flows

### Standard OAuth Flow

The authentication flow consists of several steps:

1. **Initialize Client** - Create an OAuth client instance
2. **Generate Login URL** - Redirect user to Kinde login
3. **Handle Callback** - Exchange authorization code for tokens
4. **Access User Data** - Retrieve user information, permissions, etc.
5. **Logout** - Clear session and redirect to logout

### Complete Flow Example (AsyncOAuth)

```python
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from kinde_sdk import AsyncOAuth

app = FastAPI()
oauth = AsyncOAuth(framework="fastapi", app=app)

@app.get("/login")
async def login():
    """Redirect to Kinde login."""
    login_url = await oauth.login()
    return RedirectResponse(url=login_url)

@app.get("/callback")
async def callback(request: Request, code: str, state: str = None):
    """Handle OAuth callback."""
    try:
        # Exchange code for tokens
        result = await oauth.handle_redirect(code=code, state=state)
        
        # Redirect to home page
        return RedirectResponse(url="/")
    except Exception as e:
        return {"error": str(e)}, 400

@app.get("/")
async def home():
    """Home page with user info."""
    if oauth.is_authenticated():
        user_info = await oauth.get_user_info_async()
        return {"user": user_info}
    return {"message": "Please login"}

@app.get("/logout")
async def logout():
    """Logout user."""
    logout_url = await oauth.logout()
    return RedirectResponse(url=logout_url)
```

### Complete Flow Example (OAuth - Sync)

```python
from flask import Flask, redirect, session
from kinde_sdk import OAuth

app = Flask(__name__)
app.secret_key = "your-secret-key"
oauth = OAuth(framework="flask", app=app)

@app.route("/login")
def login():
    """Redirect to Kinde login."""
    # Note: login() is async, but Flask handles it
    import asyncio
    login_url = asyncio.run(oauth.login())
    return redirect(login_url)

@app.route("/callback")
def callback():
    """Handle OAuth callback."""
    code = request.args.get("code")
    state = request.args.get("state")
    
    try:
        # Exchange code for tokens
        import asyncio
        result = asyncio.run(oauth.handle_redirect(code=code, state=state))
        
        # Redirect to home page
        return redirect("/")
    except Exception as e:
        return {"error": str(e)}, 400

@app.route("/")
def home():
    """Home page with user info."""
    if oauth.is_authenticated():
        user_info = oauth.get_user_info()  # Sync method
        return {"user": user_info}
    return {"message": "Please login"}

@app.route("/logout")
def logout():
    """Logout user."""
    import asyncio
    logout_url = asyncio.run(oauth.logout())
    return redirect(logout_url)
```

## Framework-Specific Implementations

### Flask Integration

Flask is a synchronous framework, so use the `OAuth` client.

#### Installation

```bash
pip install flask python-dotenv flask-session
```

#### Basic Setup

```python
from flask import Flask, session
from kinde_sdk import OAuth

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SESSION_TYPE'] = 'filesystem'

# Initialize OAuth
oauth = OAuth(
    framework="flask",
    app=app
)
```

#### Complete Example

```python
from flask import Flask, redirect, request, jsonify
from kinde_sdk import OAuth
import asyncio

app = Flask(__name__)
app.secret_key = "your-secret-key"
oauth = OAuth(framework="flask", app=app)

@app.route("/login")
def login():
    """Redirect to Kinde login."""
    login_url = asyncio.run(oauth.login())
    return redirect(login_url)

@app.route("/callback")
def callback():
    """Handle OAuth callback."""
    code = request.args.get("code")
    state = request.args.get("state")
    
    try:
        result = asyncio.run(oauth.handle_redirect(code=code, state=state))
        return redirect("/")
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/")
def home():
    """Home page."""
    if oauth.is_authenticated():
        user_info = oauth.get_user_info()
        return jsonify({"user": user_info})
    return jsonify({"message": "Please login"})

@app.route("/logout")
def logout():
    """Logout user."""
    logout_url = asyncio.run(oauth.logout())
    return redirect(logout_url)
```

#### Protected Routes

```python
from functools import wraps
from flask import redirect

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not oauth.is_authenticated():
            return redirect('/login')
        return f(*args, **kwargs)
    return decorated_function

@app.route("/protected")
@login_required
def protected():
    user_info = oauth.get_user_info()
    return jsonify({"message": "This is protected", "user": user_info})
```

### FastAPI Integration

FastAPI is an asynchronous framework, so use `AsyncOAuth` or `SmartOAuth`.

#### Installation

```bash
pip install fastapi uvicorn python-dotenv
```

#### Basic Setup with AsyncOAuth

```python
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from kinde_sdk import AsyncOAuth

app = FastAPI()

# Initialize AsyncOAuth
oauth = AsyncOAuth(
    framework="fastapi",
    app=app
)
```

#### Complete Example with AsyncOAuth

```python
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse
from kinde_sdk import AsyncOAuth

app = FastAPI()
oauth = AsyncOAuth(framework="fastapi", app=app)

@app.get("/login")
async def login():
    """Redirect to Kinde login."""
    login_url = await oauth.login()
    return RedirectResponse(url=login_url)

@app.get("/callback")
async def callback(request: Request, code: str, state: str = None):
    """Handle OAuth callback."""
    try:
        result = await oauth.handle_redirect(code=code, state=state)
        return RedirectResponse(url="/")
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/")
async def home():
    """Home page."""
    if oauth.is_authenticated():
        user_info = await oauth.get_user_info_async()
        return {"user": user_info}
    return {"message": "Please login"}

@app.get("/logout")
async def logout():
    """Logout user."""
    logout_url = await oauth.logout()
    return RedirectResponse(url=logout_url)
```

#### Complete Example with SmartOAuth

```python
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from kinde_sdk import SmartOAuth

app = FastAPI()
oauth = SmartOAuth(framework="fastapi", app=app)

@app.get("/")
async def home():
    """Home page - SmartOAuth automatically uses async methods."""
    if oauth.is_authenticated():
        # Recommended: use async method explicitly
        user_info = await oauth.get_user_info_async()
        return {"user": user_info}
    return {"message": "Please login"}
```

#### Protected Routes with Dependencies

```python
from fastapi import Depends, HTTPException
from kinde_sdk import AsyncOAuth

async def require_auth():
    """Dependency to require authentication."""
    if not oauth.is_authenticated():
        raise HTTPException(status_code=401, detail="Not authenticated")
    return await oauth.get_user_info_async()

@app.get("/protected")
async def protected(user_info: dict = Depends(require_auth)):
    return {"message": "This is protected", "user": user_info}
```

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

### Standalone HTTP Server Example

See `examples/simple_http_oauth_server.py` for a complete standalone HTTP server implementation.

## Permissions, Claims, and Feature Flags

All auth modules (permissions, claims, feature_flags) are async and work consistently across all client types.

### Permissions

#### Sync Context (Flask with OAuth)

```python
from flask import Flask
from kinde_sdk import OAuth
from kinde_sdk.auth import permissions
import asyncio

app = Flask(__name__)
oauth = OAuth(framework="flask", app=app)

@app.route("/check-permission")
def check_permission():
    """Check if user has a specific permission."""
    if not oauth.is_authenticated():
        return {"error": "Not authenticated"}, 401
    
    # Permissions module is async
    permission = asyncio.run(permissions.get_permission("create:todos"))
    
    if permission["isGranted"]:
        return {"message": "User has permission"}
    return {"message": "User does not have permission"}, 403

@app.route("/all-permissions")
def all_permissions():
    """Get all user permissions."""
    if not oauth.is_authenticated():
        return {"error": "Not authenticated"}, 401
    
    all_perms = asyncio.run(permissions.get_permissions())
    return {"permissions": all_perms}
```

#### Async Context (FastAPI with AsyncOAuth)

```python
from fastapi import FastAPI, HTTPException
from kinde_sdk import AsyncOAuth
from kinde_sdk.auth import permissions

app = FastAPI()
oauth = AsyncOAuth(framework="fastapi", app=app)

@app.get("/check-permission")
async def check_permission():
    """Check if user has a specific permission."""
    if not oauth.is_authenticated():
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Permissions module is async
    permission = await permissions.get_permission("create:todos")
    
    if permission["isGranted"]:
        return {"message": "User has permission"}
    raise HTTPException(status_code=403, detail="User does not have permission")

@app.get("/all-permissions")
async def all_permissions():
    """Get all user permissions."""
    if not oauth.is_authenticated():
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    all_perms = await permissions.get_permissions()
    return {"permissions": all_perms}
```

### Claims

#### Sync Context (Flask with OAuth)

```python
from flask import Flask
from kinde_sdk import OAuth
from kinde_sdk.auth import claims
import asyncio

app = Flask(__name__)
oauth = OAuth(framework="flask", app=app)

@app.route("/user-claims")
def user_claims():
    """Get user claims."""
    if not oauth.is_authenticated():
        return {"error": "Not authenticated"}, 401
    
    # Get specific claim
    email_claim = asyncio.run(claims.get_claim("email", token_type="id_token"))
    
    # Get all claims
    all_claims = asyncio.run(claims.get_all_claims())
    
    return {
        "email": email_claim["value"],
        "all_claims": all_claims
    }
```

#### Async Context (FastAPI with AsyncOAuth)

```python
from fastapi import FastAPI, HTTPException
from kinde_sdk import AsyncOAuth
from kinde_sdk.auth import claims

app = FastAPI()
oauth = AsyncOAuth(framework="fastapi", app=app)

@app.get("/user-claims")
async def user_claims():
    """Get user claims."""
    if not oauth.is_authenticated():
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Get specific claim
    email_claim = await claims.get_claim("email", token_type="id_token")
    
    # Get all claims
    all_claims = await claims.get_all_claims()
    
    return {
        "email": email_claim["value"],
        "all_claims": all_claims
    }
```

### Feature Flags

#### Sync Context (Flask with OAuth)

```python
from flask import Flask
from kinde_sdk import OAuth
from kinde_sdk.auth import feature_flags
import asyncio

app = Flask(__name__)
oauth = OAuth(framework="flask", app=app)

@app.route("/feature-flags")
def feature_flags_route():
    """Get user feature flags."""
    if not oauth.is_authenticated():
        return {"error": "Not authenticated"}, 401
    
    # Get specific flag
    theme_flag = asyncio.run(feature_flags.get_flag("theme", default_value="light"))
    
    # Get all flags
    all_flags = asyncio.run(feature_flags.get_all_flags())
    
    return {
        "theme": theme_flag.value,
        "all_flags": {k: v.value for k, v in all_flags.items()}
    }
```

#### Async Context (FastAPI with AsyncOAuth)

```python
from fastapi import FastAPI, HTTPException
from kinde_sdk import AsyncOAuth
from kinde_sdk.auth import feature_flags

app = FastAPI()
oauth = AsyncOAuth(framework="fastapi", app=app)

@app.get("/feature-flags")
async def feature_flags_route():
    """Get user feature flags."""
    if not oauth.is_authenticated():
        raise HTTPException(status_code=401, detail="Not authenticated")
    
    # Get specific flag
    theme_flag = await feature_flags.get_flag("theme", default_value="light")
    
    # Get all flags
    all_flags = await feature_flags.get_all_flags()
    
    return {
        "theme": theme_flag.value,
        "all_flags": {k: v.value for k, v in all_flags.items()}
    }
```

## Management API Usage

The Management API client is synchronous by default, but can be used in both sync and async contexts.

### Sync Usage

```python
from kinde_sdk.management import ManagementClient

# Initialize client
client = ManagementClient(
    domain="your-domain.kinde.com",
    client_id="your-management-client-id",
    client_secret="your-management-client-secret"
)

# All methods are synchronous
users = client.get_users(page_size=10)
user = client.get_user(user_id="user_id")
organizations = client.get_organizations()
```

### Async Usage (Wrapping in Async Functions)

```python
from kinde_sdk.management import ManagementClient
import asyncio

# Initialize client
client = ManagementClient(
    domain="your-domain.kinde.com",
    client_id="your-management-client-id",
    client_secret="your-management-client-secret"
)

# Wrap in async function for use in async contexts
async def get_users_async():
    """Get users asynchronously."""
    # Run sync method in thread pool
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, client.get_users, 10)

# Use in FastAPI
@app.get("/users")
async def users():
    users_data = await get_users_async()
    return {"users": users_data}
```

### Complete Management API Example

```python
from fastapi import FastAPI, HTTPException
from kinde_sdk.management import ManagementClient
import asyncio

app = FastAPI()

# Initialize Management Client
management_client = ManagementClient(
    domain=os.getenv("KINDE_DOMAIN"),
    client_id=os.getenv("KINDE_MANAGEMENT_CLIENT_ID"),
    client_secret=os.getenv("KINDE_MANAGEMENT_CLIENT_SECRET")
)

# Helper to run sync methods in async context
async def run_sync(func, *args, **kwargs):
    """Run synchronous function in async context."""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: func(*args, **kwargs))

@app.get("/users")
async def get_users():
    """Get all users."""
    try:
        users = await run_sync(management_client.get_users, page_size=10)
        return {"users": users}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/users/{user_id}")
async def get_user(user_id: str):
    """Get specific user."""
    try:
        user = await run_sync(management_client.get_user, user_id=user_id)
        return {"user": user}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/users")
async def create_user(user_data: dict):
    """Create new user."""
    try:
        new_user = await run_sync(
            management_client.create_user,
            first_name=user_data.get("first_name"),
            last_name=user_data.get("last_name"),
            email=user_data.get("email")
        )
        return {"user": new_user}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
```

## Error Handling

### Common Exceptions

The SDK raises several exception types:

- `KindeConfigurationException` - Configuration errors
- `KindeLoginException` - Login/authentication errors
- `KindeTokenException` - Token-related errors
- `KindeRetrieveException` - Data retrieval errors

### Error Handling Patterns

#### Sync Context (Flask)

```python
from flask import Flask, jsonify
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

#### Async Context (FastAPI)

```python
from fastapi import FastAPI, HTTPException
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

async def safe_get_claim(claim_name: str, token_type: str = "access_token"):
    """Safely get claim with error handling."""
    try:
        claim = await claims.get_claim(claim_name, token_type=token_type)
        return claim
    except KindeConfigurationException:
        return {"name": claim_name, "value": None}
    except Exception as e:
        logger.error(f"Error getting claim: {e}")
        return {"name": claim_name, "value": None}

async def safe_get_flag(flag_code: str, default_value=None):
    """Safely get feature flag with error handling."""
    try:
        flag = await feature_flags.get_flag(flag_code, default_value=default_value)
        return flag
    except KindeConfigurationException:
        # Return default value
        from kinde_sdk.auth.feature_flags import FeatureFlag
        return FeatureFlag(code=flag_code, type="unknown", value=default_value, is_default=True)
    except Exception as e:
        logger.error(f"Error getting feature flag: {e}")
        from kinde_sdk.auth.feature_flags import FeatureFlag
        return FeatureFlag(code=flag_code, type="unknown", value=default_value, is_default=True)
```

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

## Migration Guide

### Migrating from OAuth to AsyncOAuth

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

### Migrating Auth Module Calls

Auth modules are already async, but ensure you're using them correctly:

**Before (Incorrect):**
```python
# This won't work - permissions is async
permission = permissions.get_permission("create:todos")
```

**After (Correct):**
```python
# In sync context
import asyncio
permission = asyncio.run(permissions.get_permission("create:todos"))

# In async context
permission = await permissions.get_permission("create:todos")
```

### Common Migration Issues

1. **"RuntimeError: no running event loop"**
   - Solution: Use `asyncio.run()` in sync contexts or use sync client

2. **"DeprecationWarning: Using sync method in async context"**
   - Solution: Use `_async` version of methods or switch to `AsyncOAuth`

3. **"AttributeError: 'OAuth' object has no attribute 'get_user_info_async'"**
   - Solution: Use `AsyncOAuth` or `SmartOAuth` for async methods

## Troubleshooting

### Common Issues

1. **State mismatch errors**
   - Ensure state parameter is properly stored and validated
   - Check that session storage is working correctly

2. **Token refresh failures**
   - Verify client credentials are correct
   - Check network connectivity
   - Ensure tokens are stored securely

3. **Session not persisting**
   - Verify session configuration (Flask: SECRET_KEY, FastAPI: middleware)
   - Check storage backend configuration
   - Ensure cookies are enabled

4. **Async/sync context errors**
   - Use appropriate client for your context
   - Wrap sync calls in `asyncio.run()` when needed
   - Use async methods in async contexts

### Getting Help

- Check the examples in `/examples` directory
- Review the test files in `/testv2` directory
- See framework-specific examples in `/kinde_flask` and `/kinde_fastapi`
- Open an issue on GitHub for bugs or feature requests
