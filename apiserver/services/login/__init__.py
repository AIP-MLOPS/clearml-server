from apiserver.apimodels.login import (
    GetSupportedModesRequest,
    GetSupportedModesResponse,
    BasicMode,
    BasicGuestMode,
    ServerErrors,
)
from apiserver.config import info
from apiserver.service_repo import endpoint, APICall
from apiserver.service_repo.auth import revoke_auth_token
from apiserver.service_repo.auth.fixed_user import FixedUser

from apiserver.apimodels.login import AuthenticatedUser, CasdoorAuthenticateRequest, CasdoorAuthenticateResponse

from apiserver.service_repo.auth.casdoor_auth import casdoor_auth
from datetime import datetime
import traceback

from apiserver.service_repo.auth.payload import Token
from apiserver.apimodels.login import AuthenticatedUser, CasdoorAuthenticateRequest, CasdoorAuthenticateResponse


# Import Casdoor authentication
try:
    from apiserver.service_repo.auth.casdoor_auth import casdoor_auth
    CASDOOR_AVAILABLE = True
except ImportError:
    CASDOOR_AVAILABLE = False
    casdoor_auth = None


# @endpoint("login.supported_modes", response_data_model=GetSupportedModesResponse)
# def supported_modes(call: APICall, _, __: GetSupportedModesRequest):
#     guest_user = FixedUser.get_guest_user()
#     if guest_user:
#         guest = BasicGuestMode(
#             enabled=True,
#             name=guest_user.name,
#             username=guest_user.username,
#             password=guest_user.password,
#         )
#     else:
#         guest = BasicGuestMode()

#     return GetSupportedModesResponse(
#         basic=BasicMode(enabled=FixedUser.enabled(), guest=guest),
#         sso={},
#         sso_providers=[],
#         server_errors=ServerErrors(
#             missed_es_upgrade=info.missed_es_upgrade,
#             es_connection_error=info.es_connection_error,
#         ),
#         authenticated=call.auth is not None,
#     )

@endpoint("login.supported_modes", response_data_model=GetSupportedModesResponse)
def supported_modes(call: APICall, _, __: GetSupportedModesRequest):
    guest_user = FixedUser.get_guest_user()
    if guest_user:
        guest = BasicGuestMode(
            enabled=True,
            name=guest_user.name,
            username=guest_user.username,
            password=guest_user.password,
        )
    else:
        guest = BasicGuestMode()

    # Get SSO configuration
    sso_config = {}
    sso_providers = []
    
    # Add Casdoor SSO if available and enabled
    if CASDOOR_AVAILABLE and casdoor_auth and casdoor_auth.is_enabled():
        sso_config.update(casdoor_auth.get_sso_config())
        sso_providers.extend(casdoor_auth.get_sso_providers())

    return GetSupportedModesResponse(
        basic=BasicMode(enabled=FixedUser.enabled(), guest=guest),
        sso=sso_config,
        sso_providers=sso_providers,
        server_errors=ServerErrors(
            missed_es_upgrade=info.missed_es_upgrade,
            es_connection_error=info.es_connection_error,
        ),
        authenticated=call.auth is not None,
    )


@endpoint("login.logout", min_version="2.13")
def logout(call: APICall, _, __):
    revoke_auth_token(call.auth)
    call.result.set_auth_cookie(None)

# New endpoint for Casdoor token authentication
# @endpoint("login.casdoor_authenticate")
# @endpoint(
#     "login.casdoor_authenticate",
#     request_data_model=CasdoorAuthenticateRequest,
#     response_data_model=CasdoorAuthenticateResponse
# )
# def casdoor_authenticate(call: APICall, _, request):
#     """
#     Authenticate user with Casdoor JWT token
#     """
#     try:
#         # We use 'w' (write mode) to create a fresh log for each request
#         with open("/tmp/casdoor_precheck.log", "w") as f:
#             f.write(f"--- PRE-CHECK AT {datetime.utcnow().isoformat()} ---\n")
#             f.write(f"1. CASDOOR_AVAILABLE flag is: {CASDOOR_AVAILABLE}\n")
            
#             casdoor_auth_exists = casdoor_auth is not None
#             f.write(f"2. 'casdoor_auth' object is not None: {casdoor_auth_exists}\n")
            
#             if casdoor_auth_exists:
#                 is_enabled_result = casdoor_auth.is_enabled()
#                 f.write(f"3. casdoor_auth.is_enabled() returns: {is_enabled_result}\n")
#             else:
#                 f.write("3. casdoor_auth.is_enabled() was not checked because casdoor_auth is None.\n")
#     except Exception as e:
#         # Failsafe in case the logging itself causes an error
#         with open("/tmp/casdoor_precheck.log", "w") as f:
#             f.write(f"An error occurred during the logging pre-check itself: {e}")

#     if not CASDOOR_AVAILABLE or not casdoor_auth or not casdoor_auth.is_enabled():
#         call.result.error_code = 400
#         call.result.error_msg = "Casdoor authentication not available"
#         return CasdoorAuthenticateResponse(success=False, error="Casdoor auth not enabled")
    
#     # token = request.get("token")
#     token = request.token
#     # --- NEW LOGGING FOR TOKEN ---
#     try:
#         with open("/tmp/casdoor_precheck.log", "a") as f:
#             # Log a truncated token for security purposes
#             log_token = f"{token[:30]}...{token[-30:]}" if len(token) > 60 else token
#             f.write(f"--- TOKEN READ AT {datetime.utcnow().isoformat()} ---\n")
#             f.write(f"Token (truncated): {log_token}\n\n")
#     except Exception:
#         # Failsafe in case of logging errors
#         pass


#     if not token:
#         call.result.error_code = 400
#         call.result.error_msg = "Token not provided"
#         return CasdoorAuthenticateResponse(success=False, error="Token not provided")

    
#     # Authenticate user
#     payload = casdoor_auth.authenticate_user(token)

#     try:
#         with open("/tmp/casdoor_precheck.log", "a") as f:
#             f.write(f"--- PAYLOAD GENERATED AT {datetime.utcnow().isoformat()} ---\n")
#             if payload:
#                 # Assuming the payload object has a method to be converted to a dictionary
#                 f.write(f"Payload Content: {payload.to_dict()}\n\n")
#             else:
#                 f.write("Payload Content: None (Authentication Failed)\n\n")
#     except Exception:
#         # Failsafe in case of logging errors
#         pass
    
#     if not payload:
#         call.result.error_code = 401
#         call.result.error_msg = "Authentication failed"
#         return CasdoorAuthenticateResponse(success=False, error="Authentication failed")
    
#     # Set authentication
#     call.auth = payload
#     call.result.set_auth_cookie(payload)
    
#     return CasdoorAuthenticateResponse(
#         success=True,
#         user={
#             "id": payload.identity.user,
#             "name": payload.identity.user_name,
#             "company": payload.identity.company,
#         }
#     )


@endpoint(
    "login.casdoor_authenticate",
    request_data_model=CasdoorAuthenticateRequest,
    response_data_model=CasdoorAuthenticateResponse
)
def casdoor_authenticate(call: APICall, _, request: CasdoorAuthenticateRequest):
    """
    Authenticate user with Casdoor JWT token and exchange it for a ClearML session token.
    """
    if not CASDOOR_AVAILABLE or not casdoor_auth or not casdoor_auth.is_enabled():
        return CasdoorAuthenticateResponse(success=False, error="Casdoor auth not enabled")
    
    token = request.token
    if not token:
        return CasdoorAuthenticateResponse(success=False, error="Token not provided")

    # This call validates the Casdoor token and returns a ClearML Payload object
    payload = casdoor_auth.authenticate_user(token)
    
    if not payload:
        return CasdoorAuthenticateResponse(success=False, error="Authentication failed")
    
    # --- THE FINAL FIX: Create a standard ClearML session token ---
    # The payload.identity object contains the validated user details from Casdoor.
    clearml_token = Token.create_encoded_token(identity=payload.identity)
    
    # Set authentication for the session using the original payload
    call.auth = payload
    # Save the NEW, standard ClearML token to the cookie
    call.result.set_auth_cookie(clearml_token)
    
    # Manually create the user object for the response
    authenticated_user = AuthenticatedUser(
        id=payload.identity.user,
        name=payload.identity.user_name,
        company=payload.identity.company
    )
    
    # Create the final response object
    response_model = CasdoorAuthenticateResponse(
        success=True,
        user=authenticated_user
    )

    # Assign the response object to the call result
    call.result.data_model = response_model

# @endpoint(
#     "login.casdoor_authenticate",
#     request_data_model=CasdoorAuthenticateRequest,
#     response_data_model=CasdoorAuthenticateResponse
# )
# def casdoor_authenticate(call: APICall, _, request: CasdoorAuthenticateRequest):
#     """
#     Authenticate user with Casdoor JWT token
#     """
#     if not CASDOOR_AVAILABLE or not casdoor_auth or not casdoor_auth.is_enabled():
#         # This part is fine, it returns an error response object
#         return CasdoorAuthenticateResponse(success=False, error="Casdoor auth not enabled")
    
#     token = request.token
#     if not token:
#         return CasdoorAuthenticateResponse(success=False, error="Token not provided")

#     payload = casdoor_auth.authenticate_user(token)
    
#     if not payload:
#         return CasdoorAuthenticateResponse(success=False, error="Authentication failed")
    
#     # Set authentication for the session
#     call.auth = payload
#     call.result.set_auth_cookie(token)
    
#     # Manually create the user object
#     authenticated_user = AuthenticatedUser(
#         id=payload.identity.user,
#         name=payload.identity.user_name,
#         company=payload.identity.company
#     )
    
#     # Create the final response object
#     response_model = CasdoorAuthenticateResponse(
#         success=True,
#         user=authenticated_user
#     )

#     # --- FINAL FIX: Assign the response object to the call result instead of returning it ---
#     call.result.data_model = response_model

# @endpoint(
#     "login.casdoor_authenticate",
#     request_data_model=CasdoorAuthenticateRequest,
#     response_data_model=CasdoorAuthenticateResponse
# )
# def casdoor_authenticate(call: APICall, _, request: CasdoorAuthenticateRequest):
#     """
#     Authenticate user with Casdoor JWT token
#     """
#     if not CASDOOR_AVAILABLE or not casdoor_auth or not casdoor_auth.is_enabled():
#         return CasdoorAuthenticateResponse(success=False, error="Casdoor auth not enabled")
    
#     token = request.token
#     if not token:
#         return CasdoorAuthenticateResponse(success=False, error="Token not provided")

#     payload = casdoor_auth.authenticate_user(token)
    
#     if not payload:
#         return CasdoorAuthenticateResponse(success=False, error="Authentication failed")
    
#     # === MINIMAL CHANGE: Create ClearML auth token instead of using JWT directly ===
#     from apiserver.service_repo.auth import create_auth_token
    
#     # Create a proper ClearML auth token
#     clearml_auth_token = create_auth_token(payload.identity)
    
#     # Set authentication for the session using ClearML token
#     call.auth = payload
#     call.result.set_auth_cookie(clearml_auth_token)  # Use ClearML token, not JWT
#     # === END OF MINIMAL CHANGE ===
    
#     # Manually create the user object
#     authenticated_user = AuthenticatedUser(
#         id=payload.identity.user,
#         name=payload.identity.user_name,
#         company=payload.identity.company
#     )
    
#     # Create the final response object
#     response_model = CasdoorAuthenticateResponse(
#         success=True,
#         user=authenticated_user
#     )

#     # Assign the response object to the call result
#     call.result.data_model = response_model