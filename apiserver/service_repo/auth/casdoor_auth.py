# # File 1: apiserver/service_repo/auth/casdoor_auth.py
# """
# Casdoor Authentication Backend for ClearML
# This file should be placed in: apiserver/service_repo/auth/casdoor_auth.py
# """

# import os
# import logging
# import traceback
# import jwt
# from typing import Optional, Dict, Any
# from datetime import datetime
# from functools import wraps


# from apiserver.service_repo.auth.payload import Payload
# from apiserver.service_repo.auth.payload.auth_type import AuthType

# from apiserver.service_repo.auth import Identity
# from apiserver.config_repo import config
# from apiserver.database.model.user import User
# from apiserver.database.model.company import Company

# # Import your base Casdoor authenticator
# from apiserver.service_repo.auth.casdoor_authenticator import CasdoorAuthenticator, AuthResult

# def log_workflow(func):
#     """A decorator to log the entry, exit, and errors of a method to a single file."""
#     @wraps(func)
#     def wrapper(*args, **kwargs):
#         # The first arg is 'self', the instance of CasdoorAuth
#         class_name = args[0].__class__.__name__
#         func_name = func.__name__
#         log_file = "/tmp/casdoor_full_trace.log"
        
#         try:
#             # Log entry
#             with open(log_file, "a") as f:
#                 f.write(f"--- ENTERING: {class_name}.{func_name} ---\n")
            
#             # Execute the actual method
#             result = func(*args, **kwargs)
            
#             # Log successful exit and return value
#             with open(log_file, "a") as f:
#                 f.write(f"--- EXITING: {class_name}.{func_name} ---\n")
#                 f.write(f"Result: {result}\n\n")
            
#             return result
#         except Exception as e:
#             # Log any exception
#             with open(log_file, "a") as f:
#                 f.write(f"--- EXCEPTION in {class_name}.{func_name} ---\n")
#                 f.write(f"Exception: {e}\n")
#                 f.write(f"Traceback:\n{traceback.format_exc()}\n\n")
#             # Re-raise the exception so the program still fails as expected
#             raise
            
#     return wrapper

# class CasdoorAuth:
#     """ClearML Casdoor Authentication Handler"""
    
#     @log_workflow
#     def __init__(self):
#         self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
#         self.casdoor_auth = CasdoorAuthenticator(logger=self.logger)
#         self.logger.info("Casdoor authenticator initialized successfully")
#         self.enabled = config.get("auth.casdoor.enabled", default=True)
#         self.auto_create_users = config.get("auth.casdoor.auto_create_users", default=True)
#         self.default_company = config.get("auth.casdoor.default_company", default="casdoor_users")
    
#     @log_workflow
#     def _is_casdoor_token(self, token: str) -> bool:
#         """Check if this token is from Casdoor"""
#         try:
#             # Decode without verification to check the structure
#             decoded = jwt.decode(token, options={"verify_signature": False})
            
#             # Check for Casdoor-specific claims
#             casdoor_indicators = [
#                 decoded.get('iss') == 'https://iam.ai-lab.ir',  # Your Casdoor issuer
#                 'displayName' in decoded,  # Casdoor-specific claim
#                 'tokenType' in decoded,    # Casdoor-specific claim
#                 decoded.get('aud') and 'org-built-in' in str(decoded.get('aud')),  # Casdoor audience pattern
#             ]
            
#             # If any Casdoor indicator is present, treat as Casdoor token
#             return any(casdoor_indicators)
            
#         except Exception as e:
#             self.logger.debug(f"Failed to decode token for Casdoor check: {e}")
#             return False
        

#     @log_workflow
#     def is_enabled(self) -> bool:
#         return self.enabled
    
#     # @log_workflow
#     # def authenticate_user(self, token: str) -> Optional[Payload]:
#     #     if not self.is_enabled():
#     #         return None
        
#     #     auth_result = self.casdoor_auth.authenticate_user(token)
        
#     #     if not auth_result.is_authenticated:
#     #         self.logger.warning(f"Casdoor authentication failed: {auth_result.error_message}")
#     #         return None
        
#     #     self.logger.info(f"User authenticated via Casdoor: {auth_result.username}")
        
#     #     user = self._get_or_create_user(auth_result)
#     #     if not user:
#     #         self.logger.error(f"Failed to get or create user for {auth_result.username}")
#     #         return None
        
#     #     identity = Identity(
#     #         user=user.id,
#     #         company=user.company,
#     #         role='user',  # Provide the required role
#     #         user_name=user.name
#     #     )
        
#     #     payload = Payload(
#     #         auth_type=AuthType.bearer_token,
#     #         identity=identity
#     #     )
#     #     return payload

#     @log_workflow
#     def authenticate_user(self, token: str) -> Optional[Payload]:
#         """
#         Authenticate a user using Casdoor JWT token
        
#         Args:
#             token: JWT token from Casdoor (could be from cookie or header)
            
#         Returns:
#             Payload: Authentication payload if successful, None otherwise
#         """
#         if not self.is_enabled():
#             return None
        
#         try:
#             # First check if this looks like a Casdoor token
#             if not self._is_casdoor_token(token):
#                 self.logger.info("Token doesn't appear to be from Casdoor, skipping")
#                 return None
            
#             # Authenticate with Casdoor
#             auth_result = self.casdoor_auth.authenticate_user(token)
            
#             if not auth_result.is_authenticated:
#                 self.logger.warning(f"Casdoor authentication failed: {auth_result.error_message}")
#                 return None
            
#             self.logger.info(f"User authenticated via Casdoor: {auth_result.username}")
            
#             # Get or create ClearML user
#             user = self._get_or_create_user(auth_result)
#             if not user:
#                 self.logger.error(f"Failed to get or create user for {auth_result.username}")
#                 return None
            
#             # Get company information
#             company = Company.objects(id=user.company).only("id", "name").first()
#             if not company:
#                 self.logger.error("User company not found")
#                 return None
            
#             # Create authentication payload
#             identity = Identity(
#                 user=user.id,
#                 company=user.company,
#                 role='user',  # You can customize this based on Casdoor roles
#                 user_name=user.name,
#                 company_name=company.name
#             )
            
#             payload = Payload(
#                 auth_type=AuthType.bearer_token,
#                 identity=identity
#             )
            
#             return payload
            
#         except Exception as e:
#             self.logger.error(f"Error during Casdoor authentication: {e}")
#             return None


    
#     @log_workflow
#     def get_sso_config(self) -> Dict[str, Any]:
#         # ... (method content is unchanged)
#         if not self.enabled:
#             return {}
#         casdoor_endpoint = os.getenv('CASDOOR_ENDPOINT', '')
#         casdoor_client_id = os.getenv('CASDOOR_CLIENT_ID', '')
#         casdoor_org = os.getenv('CASDOOR_ORG_NAME', 'built-in')
#         casdoor_app = os.getenv('CASDOOR_APP_NAME', 'app-built-in')
#         login_url = f"{casdoor_endpoint}/login/oauth/authorize"
#         return {"casdoor": {"login_url": login_url, "client_id": casdoor_client_id, "organization": casdoor_org, "application": casdoor_app, "callback_url": "/auth/casdoor/callback"}}
    
#     @log_workflow
#     def get_sso_providers(self) -> list:
#         # ... (method content is unchanged)
#         if not self.enabled:
#             return []
#         return [{"name": "casdoor", "display_name": "Casdoor SSO", "login_url": self.get_sso_config().get("casdoor", {}).get("login_url", ""), "enabled": True, "icon": "casdoor", "description": "Sign in with your organization account"}]
    
#     @log_workflow
#     def test_connection(self) -> bool:
#         # ... (method content is unchanged)
#         return self.casdoor_auth.test_connection()
    
#     @log_workflow
#     def _get_or_create_user(self, auth_result: AuthResult) -> Optional[User]:
#         user = User.objects(id=f"casdoor_{auth_result.user_id}").first()
#         if user:
#             self._update_user_info(user, auth_result)
#             return user
        
#         user = User.objects(name=auth_result.username).first()
#         if user:
#             self.logger.info(f"Found existing user '{user.name}'. Linking to Casdoor ID.")
#             user.id = f"casdoor_{auth_result.user_id}"
#             self._update_user_info(user, auth_result)
#             return user

#         if self.auto_create_users:
#             return self._create_new_user(auth_result)
            
#         return None
    
#     @log_workflow
#     def _create_new_user(self, auth_result: AuthResult) -> Optional[User]:
#         company = self._get_or_create_company()
#         if not company:
#             return None
        
#         user_data = auth_result.user_data or {}
        
#         user = User(
#             id=f"casdoor_{auth_result.user_id}",
#             name=auth_result.username,
#             company=company.id,
#             given_name=user_data.get('display_name', auth_result.username),
#             family_name=user_data.get('family_name', ''),
#             avatar=user_data.get('avatar', ''),
#             created=datetime.utcnow()
#         )
        
#         user.save()
#         self.logger.info(f"Created new user: {user.name} ({user.id})")
#         return user
    
#     @log_workflow
#     def _update_user_info(self, user: User, auth_result: AuthResult):
#         updated = False
#         if user.name != auth_result.username:
#             user.name = auth_result.username
#             updated = True
        
#         if updated:
#             user.save()
#             self.logger.info(f"Updated user information: {user.name}")
    
#     @log_workflow
#     def _get_or_create_company(self) -> Optional[Company]:
#         company = Company.objects(id=self.default_company).first()
#         if company:
#             return company
        
#         company = Company(
#             id=self.default_company,
#             name="Casdoor Users",
#         )
#         company.save()
#         self.logger.info(f"Created default company: {company.name}")
#         return company
    
#     @log_workflow
#     def _get_token_expiry(self, token: str) -> Optional[datetime]:
#         decoded = jwt.decode(token, options={"verify_signature": False})
#         exp_timestamp = decoded.get('exp')
        
#         if exp_timestamp:
#             return datetime.fromtimestamp(exp_timestamp)
#         return None

# # class CasdoorAuth:
# #     """ClearML Casdoor Authentication Handler"""
    
# #     def __init__(self):
# #         self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
# #         # Initialize Casdoor authenticator
# #         try:
# #             self.casdoor_auth = CasdoorAuthenticator(logger=self.logger)
# #             self.logger.info("Casdoor authenticator initialized successfully")
# #         except Exception as e:
# #             self.logger.error(f"Failed to initialize Casdoor authenticator: {e}")
# #             raise
        
# #         # Configuration
# #         # self.enabled = config.get("auth.casdoor.enabled", default=False)
# #         self.enabled = config.get("auth.casdoor.enabled", default=True)
# #         self.auto_create_users = config.get("auth.casdoor.auto_create_users", default=True)
# #         self.default_company = config.get("auth.casdoor.default_company", default="casdoor_users")
    
# #     def is_enabled(self) -> bool:
# #         """Check if Casdoor authentication is enabled"""
# #         return self.enabled
    
# #     def authenticate_user(self, token: str) -> Optional[Payload]:
# #         """
# #         Authenticate a user using Casdoor JWT token
        
# #         Args:
# #             token: JWT token from Casdoor
            
# #         Returns:
# #             Payload: Authentication payload if successful, None otherwise
# #         """
# #         if not self.enabled:
# #             return None
        
# #         try:
# #             # Authenticate with Casdoor
# #             auth_result = self.casdoor_auth.authenticate_user(token)
            
# #             if not auth_result.is_authenticated:
# #                 with open("/tmp/casdoor_auth_errors.log", "a") as f:
# #                     f.write(
# #                         f"--- AUTH FAILED AT {datetime.utcnow().isoformat()} ---\n"
# #                         f"SDK Error: {auth_result.error_message}\n\n"
# #                     )

# #                 self.logger.warning(f"Casdoor authentication failed: {auth_result.error_message}")
# #                 return None
            
# #             self.logger.info(f"User authenticated via Casdoor: {auth_result.username}")
            
# #             # Get or create ClearML user
# #             user = self._get_or_create_user(auth_result)
# #             if not user:
# #                 self.logger.error(f"Failed to get or create user for {auth_result.username}")
# #                 return None
            
# #             # Create authentication payload
# #             identity = Identity(
# #                 user=user.id,
# #                 company=user.company,
# #                 role=user.role,
# #                 user_name=user.name,
# #                 given_name=auth_result.user_data.get('display_name', user.name) if auth_result.user_data else user.name,
# #                 user_email=user.email
# #             )
            
# #             payload = Payload(
# #                 identity=identity,
# #                 token_type=AuthType.bearer,
# #                 exp=self._get_token_expiry(token)
# #             )
            
# #             return payload
            
# #         except Exception as e:

# #             error_details = (
# #                 f"--- EXCEPTION AT {datetime.utcnow().isoformat()} ---\n"
# #                 f"Token (first 30 chars): {token[:30]}...\n"
# #                 f"Exception Type: {type(e).__name__}\n"
# #                 f"Exception Details: {e}\n"
# #                 f"--- TRACEBACK ---\n{traceback.format_exc()}\n\n"
# #             )
# #             with open("/tmp/casdoor_auth_errors.log", "a") as f:
# #                 f.write(error_details)

# #             self.logger.error(f"Error during Casdoor authentication: {e}")
# #             return None
    
# #     def get_sso_config(self) -> Dict[str, Any]:
# #         """Get SSO configuration for frontend"""
# #         if not self.enabled:
# #             return {}
        
# #         # Get Casdoor configuration from environment
# #         casdoor_endpoint = os.getenv('CASDOOR_ENDPOINT', '')
# #         casdoor_client_id = os.getenv('CASDOOR_CLIENT_ID', '')
# #         casdoor_org = os.getenv('CASDOOR_ORG_NAME', 'built-in')
# #         casdoor_app = os.getenv('CASDOOR_APP_NAME', 'app-built-in')
        
# #         # Build login URL
# #         login_url = f"{casdoor_endpoint}/login/oauth/authorize"
        
# #         return {
# #             "casdoor": {
# #                 "login_url": login_url,
# #                 "client_id": casdoor_client_id,
# #                 "organization": casdoor_org,
# #                 "application": casdoor_app,
# #                 "callback_url": "/auth/casdoor/callback"
# #             }
# #         }
    
# #     def get_sso_providers(self) -> list:
# #         """Get list of SSO providers for frontend"""
# #         if not self.enabled:
# #             return []
        
# #         return [{
# #             "name": "casdoor",
# #             "display_name": "Casdoor SSO",
# #             "login_url": self.get_sso_config().get("casdoor", {}).get("login_url", ""),
# #             "enabled": True,
# #             "icon": "casdoor",
# #             "description": "Sign in with your organization account"
# #         }]
    
# #     def test_connection(self) -> bool:
# #         """Test connection to Casdoor"""
# #         try:
# #             return self.casdoor_auth.test_connection()
# #         except Exception as e:
# #             self.logger.error(f"Casdoor connection test failed: {e}")
# #             return False
    
# #     def _get_or_create_user(self, auth_result: AuthResult) -> Optional[User]:
# #         """Get existing user or create new one"""
# #         try:
# #             # Try to find existing user by Casdoor user ID
# #             user = User.objects(id=f"casdoor_{auth_result.user_id}").first()
            
            
# #             if user:
# #                 self._update_user_info(user, auth_result)
# #                 return user
            
# #             # If not found, try to find an existing ClearML user by username to link accounts
# #             user = User.objects(name=auth_result.username).first()
# #             if user:
# #                 self.logger.info(f"Found existing user '{user.name}'. Linking to Casdoor ID.")
# #                 user.id = f"casdoor_{auth_result.user_id}"
# #                 self._update_user_info(user, auth_result) # This saves the user
# #                 return user

# #             # If still not found, create a new user if auto-creation is enabled
# #             if self.auto_create_users:
# #                 return self._create_new_user(auth_result)
            
# #         except Exception as e:
# #             # Add detailed logging to the error file
# #             error_details = (
# #                 f"--- EXCEPTION IN _get_or_create_user AT {datetime.utcnow().isoformat()} ---\n"
# #                 f"Attempting to find/create user: {auth_result.username}\n"
# #                 f"Exception: {e}\n"
# #                 f"--- TRACEBACK ---\n{traceback.format_exc()}\n\n"
# #             )
# #             with open("/tmp/casdoor_auth_errors.log", "a") as f:
# #                 f.write(error_details)
# #             self.logger.error(f"Error getting or creating user: {e}")
        
# #         return None
    
# #     def _create_new_user(self, auth_result: AuthResult) -> Optional[User]:
# #         """Create a new ClearML user"""
# #         try:
# #             # Get or create default company
# #             company = self._get_or_create_company()
# #             if not company:
# #                 return None
            
# #             user_data = auth_result.user_data or {}
            
# #             # Create new user
# #             user = User(
# #                 id=f"casdoor_{auth_result.user_id}",
# #                 name=auth_result.username,
# #                 company=company.id,
# #                 given_name=user_data.get('display_name', auth_result.username),
# #                 family_name=user_data.get('family_name', ''),
# #                 created=datetime.utcnow()
# #             )
                
# #             user.save()
# #             self.logger.info(f"Created new user: {user.name} ({user.id})")
# #             return user
            
# #         except Exception as e:
# #             # --- ADDED DETAILED ERROR HANDLING HERE ---
# #             error_details = (
# #                 f"--- EXCEPTION IN _create_new_user AT {datetime.utcnow().isoformat()} ---\n"
# #                 f"Attempting to create user: {auth_result.username}\n"
# #                 f"Exception: {e}\n"
# #                 f"--- TRACEBACK ---\n{traceback.format_exc()}\n\n"
# #             )
# #             with open("/tmp/casdoor_auth_errors.log", "a") as f:
# #                 f.write(error_details)
                
# #             self.logger.error(f"Error creating new user: {e}")
# #             return None
    
# #     def _update_user_info(self, user: User, auth_result: AuthResult):
# #         """Update existing user information"""
# #         try:
# #             user_data = auth_result.user_data or {}
# #             updated = False
            
# #             # Update name if different
# #             if user.name != auth_result.username:
# #                 user.name = auth_result.username
# #                 updated = True
            
# #             # Update email if available and different
# #             new_email = user_data.get('email')
# #             if new_email and user.email != new_email:
# #                 user.email = new_email
# #                 updated = True
            
# #             if updated:
# #                 user.save()
# #                 self.logger.info(f"Updated user information: {user.name}")
                
# #         except Exception as e:
# #             self.logger.error(f"Error updating user info: {e}")
    
# #     def _get_or_create_company(self) -> Optional[Company]:
# #         """Get or create the default company for Casdoor users"""
# #         try:
# #             # Try to find existing company
# #             company = Company.objects(id=self.default_company).first()
# #             if company:
# #                 return company
            
# #             # Create new company
# #             company = Company(
# #                 id=self.default_company,
# #                 name="Casdoor Users",
# #                 created=datetime.utcnow()
# #             )
# #             company.save()
            
# #             self.logger.info(f"Created default company: {company.name}")
# #             return company
            
# #         except Exception as e:
# #             self.logger.error(f"Error getting or creating company: {e}")
# #             return None
    
# #     def _get_token_expiry(self, token: str) -> Optional[datetime]:
# #         """Extract token expiry from JWT token"""
# #         try:
# #             decoded = jwt.decode(token, options={"verify_signature": False})
# #             exp_timestamp = decoded.get('exp')
            
# #             if exp_timestamp:
# #                 return datetime.fromtimestamp(exp_timestamp)
# #         except Exception as e:
# #             self.logger.warning(f"Could not extract token expiry: {e}")
        
# #         return None


# # Global instance
# casdoor_auth = CasdoorAuth()
# File: apiserver/service_repo/auth/casdoor_auth.py
"""
Casdoor Authentication Backend for ClearML with Enhanced Logging
This file should be placed in: apiserver/service_repo/auth/casdoor_auth.py
"""

import os
import logging
import traceback
import jwt
from typing import Optional, Dict, Any
from datetime import datetime
from functools import wraps

from apiserver.service_repo.auth.payload import Payload
from apiserver.service_repo.auth.payload.auth_type import AuthType

from apiserver.service_repo.auth import Identity
from apiserver.config_repo import config
from apiserver.database.model.user import User
from apiserver.database.model.company import Company

# Import your base Casdoor authenticator
from apiserver.service_repo.auth.casdoor_authenticator import CasdoorAuthenticator, AuthResult

def detailed_log(message: str, level: str = "INFO", include_trace: bool = False):
    """Enhanced logging function that writes to both standard logger and debug file"""
    log_file = "/tmp/casdoor_detailed_debug.log"
    timestamp = datetime.utcnow().isoformat()
    
    log_entry = f"[{timestamp}] [{level}] {message}"
    
    if include_trace:
        log_entry += f"\nTraceback:\n{traceback.format_exc()}"
    
    log_entry += "\n" + "="*80 + "\n"
    
    try:
        with open(log_file, "a") as f:
            f.write(log_entry)
    except Exception as e:
        print(f"Failed to write to debug log: {e}")

def log_workflow(func):
    """Enhanced decorator with more detailed logging"""
    @wraps(func)
    def wrapper(*args, **kwargs):
        class_name = args[0].__class__.__name__
        func_name = func.__name__
        
        detailed_log(f">>> ENTERING: {class_name}.{func_name}")
        detailed_log(f"Arguments: args={len(args)}, kwargs={kwargs}")
        
        try:
            result = func(*args, **kwargs)
            detailed_log(f"<<< EXITING: {class_name}.{func_name} - SUCCESS")
            detailed_log(f"Return value: {result}")
            return result
            
        except Exception as e:
            detailed_log(f"<<< EXCEPTION in {class_name}.{func_name}: {e}", "ERROR", include_trace=True)
            raise
            
    return wrapper

class CasdoorAuth:
    """ClearML Casdoor Authentication Handler with Enhanced Debug Logging"""
    
    @log_workflow
    def __init__(self):
        detailed_log("=== INITIALIZING CASDOOR AUTH ===")
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
        
        try:
            self.casdoor_auth = CasdoorAuthenticator(logger=self.logger)
            detailed_log("CasdoorAuthenticator created successfully")
        except Exception as e:
            detailed_log(f"Failed to create CasdoorAuthenticator: {e}", "ERROR", include_trace=True)
            raise
            
        self.enabled = config.get("auth.casdoor.enabled", default=True)
        self.auto_create_users = config.get("auth.casdoor.auto_create_users", default=True)
        self.default_company = config.get("auth.casdoor.default_company", default="casdoor_users")
        
        detailed_log(f"Configuration - enabled: {self.enabled}, auto_create: {self.auto_create_users}, company: {self.default_company}")
    
    @log_workflow
    def _is_casdoor_token(self, token: str) -> bool:
        """Check if this token is from Casdoor with detailed logging"""
        detailed_log(f"Checking if token is from Casdoor - token length: {len(token)}")
        detailed_log(f"Token preview: {token[:50]}...{token[-10:]}")
        
        try:
            # Decode without verification to check the structure
            decoded = jwt.decode(token, options={"verify_signature": False})
            detailed_log(f"Token decoded successfully. Claims: {list(decoded.keys())}")
            detailed_log(f"Issuer: {decoded.get('iss')}")
            detailed_log(f"Audience: {decoded.get('aud')}")
            detailed_log(f"Subject: {decoded.get('sub')}")
            detailed_log(f"Token type: {decoded.get('tokenType')}")
            detailed_log(f"Display name: {decoded.get('displayName')}")
            
            # Check for Casdoor-specific claims
            iss_check = decoded.get('iss') == 'https://iam.ai-lab.ir'
            display_name_check = 'displayName' in decoded
            token_type_check = 'tokenType' in decoded
            aud_check = decoded.get('aud') and 'org-built-in' in str(decoded.get('aud'))
            
            detailed_log(f"Casdoor checks - ISS: {iss_check}, DisplayName: {display_name_check}, TokenType: {token_type_check}, AUD: {aud_check}")
            
            casdoor_indicators = [iss_check, display_name_check, token_type_check, aud_check]
            is_casdoor = any(casdoor_indicators)
            
            detailed_log(f"Token is Casdoor token: {is_casdoor}")
            return is_casdoor
            
        except Exception as e:
            detailed_log(f"Failed to decode token for Casdoor check: {e}", "ERROR", include_trace=True)
            return False

    @log_workflow
    def is_enabled(self) -> bool:
        detailed_log(f"Casdoor auth enabled: {self.enabled}")
        return self.enabled

    @log_workflow
    def authenticate_user(self, token: str) -> Optional[Payload]:
        """Enhanced authenticate_user with step-by-step logging"""
        detailed_log("=== STARTING AUTHENTICATION PROCESS ===")
        detailed_log(f"Token received - length: {len(token)}")
        
        if not self.is_enabled():
            detailed_log("Casdoor auth is disabled, returning None")
            return None
        
        try:
            # Step 1: Check if this is a Casdoor token
            detailed_log("STEP 1: Checking if token is from Casdoor")
            if not self._is_casdoor_token(token):
                detailed_log("Token is not from Casdoor, skipping authentication")
                return None
            
            detailed_log("STEP 2: Authenticating with CasdoorAuthenticator")
            # Step 2: Authenticate with Casdoor SDK
            auth_result = self.casdoor_auth.authenticate_user(token)
            detailed_log(f"CasdoorAuthenticator returned: {auth_result}")
            
            if auth_result is None:
                detailed_log("auth_result is None - authentication failed", "ERROR")
                return None
            
            detailed_log(f"auth_result.is_authenticated: {auth_result.is_authenticated}")
            if hasattr(auth_result, 'error_message'):
                detailed_log(f"auth_result.error_message: {auth_result.error_message}")
            if hasattr(auth_result, 'username'):
                detailed_log(f"auth_result.username: {auth_result.username}")
            if hasattr(auth_result, 'user_id'):
                detailed_log(f"auth_result.user_id: {auth_result.user_id}")
            if hasattr(auth_result, 'user_data'):
                detailed_log(f"auth_result.user_data: {auth_result.user_data}")
            
            if not auth_result.is_authenticated:
                detailed_log(f"Authentication failed: {auth_result.error_message}", "ERROR")
                return None
            
            detailed_log(f"STEP 3: User authenticated successfully: {auth_result.username}")
            
            # Step 3: Get or create ClearML user
            detailed_log("STEP 4: Getting or creating ClearML user")
            user = self._get_or_create_user(auth_result)
            
            if not user:
                detailed_log(f"Failed to get or create user for {auth_result.username}", "ERROR")
                return None
            
            detailed_log(f"User retrieved/created: ID={user.id}, Name={user.name}, Company={user.company}")
            
            # Step 4: Get company information
            detailed_log("STEP 5: Retrieving company information")
            company = Company.objects(id=user.company).only("id", "name").first()
            if not company:
                detailed_log("User company not found", "ERROR")
                return None
            
            detailed_log(f"Company found: ID={company.id}, Name={company.name}")
            
            # Step 5: Create authentication payload
            detailed_log("STEP 6: Creating authentication payload")
            identity = Identity(
                user=user.id,
                company=user.company,
                role='user',
                user_name=user.name,
                company_name=company.name
            )
            detailed_log(f"Identity created: {identity}")
            
            payload = Payload(
                auth_type=AuthType.bearer_token,
                identity=identity
            )
            detailed_log(f"Payload created successfully: {payload}")
            detailed_log("=== AUTHENTICATION COMPLETED SUCCESSFULLY ===")
            
            return payload
            
        except Exception as e:
            detailed_log(f"CRITICAL ERROR during authentication: {e}", "ERROR", include_trace=True)
            return None

    @log_workflow
    def get_sso_config(self) -> Dict[str, Any]:
        detailed_log("Getting SSO configuration")
        if not self.enabled:
            detailed_log("Casdoor disabled, returning empty config")
            return {}
            
        casdoor_endpoint = os.getenv('CASDOOR_ENDPOINT', '')
        casdoor_client_id = os.getenv('CASDOOR_CLIENT_ID', '')
        casdoor_org = os.getenv('CASDOOR_ORG_NAME', 'built-in')
        casdoor_app = os.getenv('CASDOOR_APP_NAME', 'app-built-in')
        login_url = f"{casdoor_endpoint}/login/oauth/authorize"
        
        config_data = {
            "casdoor": {
                "login_url": login_url,
                "client_id": casdoor_client_id,
                "organization": casdoor_org,
                "application": casdoor_app,
                "callback_url": "/auth/casdoor/callback"
            }
        }
        detailed_log(f"SSO config: {config_data}")
        return config_data

    @log_workflow
    def get_sso_providers(self) -> list:
        detailed_log("Getting SSO providers")
        if not self.enabled:
            detailed_log("Casdoor disabled, returning empty providers")
            return []
            
        providers = [{
            "name": "casdoor",
            "display_name": "Casdoor SSO",
            "login_url": self.get_sso_config().get("casdoor", {}).get("login_url", ""),
            "enabled": True,
            "icon": "casdoor",
            "description": "Sign in with your organization account"
        }]
        detailed_log(f"SSO providers: {providers}")
        return providers

    @log_workflow
    def test_connection(self) -> bool:
        detailed_log("Testing Casdoor connection")
        try:
            result = self.casdoor_auth.test_connection()
            detailed_log(f"Connection test result: {result}")
            return result
        except Exception as e:
            detailed_log(f"Connection test failed: {e}", "ERROR", include_trace=True)
            return False

    @log_workflow
    def _get_or_create_user(self, auth_result: AuthResult) -> Optional[User]:
        """Enhanced user creation/retrieval with detailed logging"""
        detailed_log("=== USER CREATION/RETRIEVAL PROCESS ===")
        detailed_log(f"Looking for user with ID: casdoor_{auth_result.user_id}")
        detailed_log(f"Username: {auth_result.username}")
        
        try:
            # Try to find existing user by Casdoor user ID
            user = User.objects(id=f"casdoor_{auth_result.user_id}").first()
            
            if user:
                detailed_log(f"Found existing user by Casdoor ID: {user.name}")
                self._update_user_info(user, auth_result)
                return user
            
            detailed_log("User not found by Casdoor ID, trying by username")
            # Try to find existing user by username
            user = User.objects(name=auth_result.username).first()
            if user:
                detailed_log(f"Found existing user by username: {user.name}, linking to Casdoor")
                user.id = f"casdoor_{auth_result.user_id}"
                self._update_user_info(user, auth_result)
                return user
            
            detailed_log("No existing user found")
            if self.auto_create_users:
                detailed_log("Auto-create enabled, creating new user")
                return self._create_new_user(auth_result)
            else:
                detailed_log("Auto-create disabled, returning None")
                return None
                
        except Exception as e:
            detailed_log(f"Error in _get_or_create_user: {e}", "ERROR", include_trace=True)
            return None

    @log_workflow
    def _create_new_user(self, auth_result: AuthResult) -> Optional[User]:
        """Enhanced user creation with detailed logging"""
        detailed_log("=== CREATING NEW USER ===")
        try:
            # Get or create default company
            detailed_log("Getting or creating company")
            company = self._get_or_create_company()
            if not company:
                detailed_log("Failed to get/create company", "ERROR")
                return None
            
            detailed_log(f"Using company: {company.id}")
            user_data = auth_result.user_data or {}
            detailed_log(f"User data from auth_result: {user_data}")
            
            # Create new user
            user_id = f"casdoor_{auth_result.user_id}"
            detailed_log(f"Creating user with ID: {user_id}")
            
            user = User(
                id=user_id,
                name=auth_result.username,
                company=company.id,
                given_name=user_data.get('display_name', auth_result.username),
                family_name=user_data.get('family_name', ''),
                avatar=user_data.get('avatar', ''),
                created=datetime.utcnow()
            )
            
            detailed_log(f"User object created, saving to database")
            user.save()
            detailed_log(f"User saved successfully: {user.name} ({user.id})")
            return user
            
        except Exception as e:
            detailed_log(f"Error creating new user: {e}", "ERROR", include_trace=True)
            return None

    @log_workflow
    def _update_user_info(self, user: User, auth_result: AuthResult):
        """Enhanced user update with detailed logging"""
        detailed_log(f"=== UPDATING USER INFO FOR: {user.name} ===")
        try:
            updated = False
            if user.name != auth_result.username:
                detailed_log(f"Updating username from {user.name} to {auth_result.username}")
                user.name = auth_result.username
                updated = True
            
            if updated:
                detailed_log("Saving updated user")
                user.save()
                detailed_log("User updated successfully")
            else:
                detailed_log("No updates needed")
                
        except Exception as e:
            detailed_log(f"Error updating user info: {e}", "ERROR", include_trace=True)

    @log_workflow
    def _get_or_create_company(self) -> Optional[Company]:
        """Enhanced company creation with detailed logging"""
        detailed_log(f"=== GETTING/CREATING COMPANY: {self.default_company} ===")
        try:
            company = Company.objects(id=self.default_company).first()
            if company:
                detailed_log(f"Found existing company: {company.name}")
                return company
            
            detailed_log("Company not found, creating new one")
            company = Company(
                id=self.default_company,
                name="Casdoor Users",
            )
            company.save()
            detailed_log(f"Created company: {company.name}")
            return company
            
        except Exception as e:
            detailed_log(f"Error getting/creating company: {e}", "ERROR", include_trace=True)
            return None

    @log_workflow
    def _get_token_expiry(self, token: str) -> Optional[datetime]:
        """Enhanced token expiry extraction with detailed logging"""
        detailed_log("Extracting token expiry")
        try:
            decoded = jwt.decode(token, options={"verify_signature": False})
            exp_timestamp = decoded.get('exp')
            
            if exp_timestamp:
                expiry = datetime.fromtimestamp(exp_timestamp)
                detailed_log(f"Token expires at: {expiry}")
                return expiry
            else:
                detailed_log("No expiry timestamp found in token")
                
        except Exception as e:
            detailed_log(f"Error extracting token expiry: {e}", "ERROR")
            
        return None

# Global instance
casdoor_auth = CasdoorAuth()