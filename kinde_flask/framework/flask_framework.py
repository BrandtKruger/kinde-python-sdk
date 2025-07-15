from typing import Optional, Dict, Any, TYPE_CHECKING
from flask import Flask, request, redirect, session
from kinde_sdk.core.framework.framework_interface import FrameworkInterface
from kinde_sdk.auth.oauth import OAuth
from ..middleware.framework_middleware import FrameworkMiddleware
import os
import uuid
import asyncio
import threading
import logging
import nest_asyncio
from flask_session import Session

import base64
import json
from urllib.parse import urlparse, urlunparse, urlencode, parse_qs

import re

if TYPE_CHECKING:
    from flask import Request

class FlaskFramework(FrameworkInterface):
    """
    Flask framework implementation.
    This class provides Flask-specific functionality and integration.
    """
    
    def __init__(self, app: Optional[Flask] = None):
        """
        Initialize the Flask framework.
        
        Args:
            app (Optional[Flask]): The Flask application instance.
                If not provided, a new instance will be created.
        """
        self.app = app or Flask(__name__)
        self._initialized = False
        self._oauth = None
        
        # Configure Flask session
        self.app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key')
        self.app.config['SESSION_TYPE'] = 'filesystem'
        self.app.config['SESSION_PERMANENT'] = False
        
        # Enable nested event loops
        nest_asyncio.apply()
    
    def get_name(self) -> str:
        """
        Get the name of the framework.
        
        Returns:
            str: The name of the framework
        """
        return "flask"
    
    def get_description(self) -> str:
        """
        Get a description of the framework.
        
        Returns:
            str: A description of the framework
        """
        return "Flask framework implementation for Kinde authentication"
    
    def start(self) -> None:
        """
        Start the framework.
        This method initializes any necessary Flask components and registers Kinde routes.
        """
        if not self._initialized:
            # Add framework middleware
            self.app.before_request(FrameworkMiddleware.before_request)
            self.app.after_request(FrameworkMiddleware.after_request)
            
            # Register Kinde routes
            self._register_kinde_routes()
            
            self._initialized = True
    
    def stop(self) -> None:
        """
        Stop the framework.
        This method cleans up any Flask resources.
        """
        if self._initialized:
            self._initialized = False
    
    def get_app(self) -> Flask:
        """
        Get the Flask application instance.
        
        Returns:
            Flask: The Flask application instance
        """
        return self.app
    
    def get_request(self) -> Optional['Request']:
        """
        Get the current request object.
        
        Returns:
            Optional[Request]: The current Flask request object, if available
        """
        from kinde_sdk.core.framework.framework_context import FrameworkContext
        return FrameworkContext.get_request()
    
    def get_user_id(self) -> Optional[str]:
        """
        Get the user ID from the current request.
        
        Returns:
            Optional[str]: The user ID, or None if not available
        """
        session_id = session.get('user_id')
        if not session_id:
            return None
        return session_id
    
    def set_oauth(self, oauth: OAuth) -> None:
        """
        Set the OAuth instance for this framework.
        
        Args:
            oauth (OAuth): The OAuth instance
        """
        self._oauth = oauth
    
    def _register_kinde_routes(self) -> None:
        """
        Register all Kinde-specific routes with the Flask application.
        """
        # Login route
        @self.app.route('/login')
        def login():
            """Redirect to Kinde login page."""
            post_login_redirect = request.args.get('post_login_redirect_url')
            if post_login_redirect:
                session['post_login_redirect_url'] = post_login_redirect  # type: ignore

            loop = asyncio.get_event_loop()
            login_url = loop.run_until_complete(self._oauth.login({"auth_params": {"supports_reauth": "true"}}))
            return redirect(login_url)
        

        # Callback route
        @self.app.route('/callback')
        def callback():
            """Handle the OAuth callback from Kinde."""
            error = request.args.get('error')
            if error:
                if error.lower() == 'login_link_expired':
                    reauth_state = request.args.get('reauth_state')
                    if reauth_state:
                        try:
                            decoded_auth_state = base64.b64decode(reauth_state).decode('utf-8')
                            reauth_dict = json.loads(decoded_auth_state)
                            params = urlencode(reauth_dict)
                            login_url = request.url_root + 'login?' + params
                            return redirect(login_url)
                        except Exception as ex:
                            return f"Error parsing reauth state: {str(ex)}", 400
                return f"Authentication failed: {error}", 400

            post_login_redirect = session.pop('post_login_redirect_url', None).get('url') or '/'

            code = request.args.get('code')
            state = request.args.get('state')

            if not code:
                return "Authentication failed: No code provided", 400

            user_id = session.get('user_id') or str(uuid.uuid4())

            try:
                loop = asyncio.get_event_loop()
                result = loop.run_until_complete(self._oauth.handle_redirect(code, user_id, state))
            except Exception as e:
                if "State not found" in str(e):
                    return "Error: State not found. Please check Kinde Python SDK documentation.\n" + str(e), 500
                raise e

            session['user_id'] = user_id

            if not post_login_redirect.startswith('http'):
                post_login_redirect = request.url_root.rstrip('/') + post_login_redirect

            parsed = urlparse(post_login_redirect)
            if state:
                query_dict = parse_qs(parsed.query)
                query_dict['state'] = [state]
                new_query = urlencode(query_dict, doseq=True)
                redirect_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
            else:
                redirect_url = post_login_redirect

            return redirect(redirect_url)
        
        # Logout route
        @self.app.route('/logout')
        def logout():
            """Logout the user and redirect to Kinde logout page."""
            user_id = session.get('user_id')
            session.clear()
            loop = asyncio.get_event_loop()
            logout_url = loop.run_until_complete(self._oauth.logout(user_id))
            return redirect(logout_url)
        
        # Register route
        @self.app.route('/register')
        def register():
            """Redirect to Kinde registration page."""
            post_login_redirect = request.args.get('post_login_redirect_url')
            if post_login_redirect:
                session['post_login_redirect_url'] = post_login_redirect  # type: ignore

            passed_state = request.args.get('state')
            if passed_state:
                if not re.match(r'^[a-zA-Z0-9+/=_-]+$', passed_state):
                    return "Invalid state supplied", 400

            login_options = {
                "auth_params": {"supports_reauth": "true"}
            }
            if passed_state:
                login_options["state"] = passed_state

            loop = asyncio.get_event_loop()
            register_url = loop.run_until_complete(self._oauth.register(login_options))
            return redirect(register_url)
        
        # User info route
        @self.app.route('/user')
        def get_user():
            """Get the current user's information."""
            try:
                if not self._oauth.is_authenticated(request):
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        login_url = loop.run_until_complete(self._oauth.login())
                        return redirect(login_url)
                    finally:
                        loop.close()
                
                return self._oauth.get_user_info(request)
            except Exception as e:
                return f"Failed to get user info: {str(e)}", 400
    
    def can_auto_detect(self) -> bool:
        """
        Check if this framework can be auto-detected.
        
        Returns:
            bool: True if Flask is installed and available
        """
        try:
            import flask
            return True
        except ImportError:
            return False 