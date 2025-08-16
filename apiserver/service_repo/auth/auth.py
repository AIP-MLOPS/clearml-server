import base64
from datetime import datetime
from time import time

import bcrypt
import jwt
from mongoengine import Q

from apiserver.apierrors import errors
from apiserver.config_repo import config
from apiserver.database.errors import translate_errors_context
from apiserver.database.model.auth import User, Entities, Credentials
from apiserver.database.model.company import Company
from apiserver.database.utils import get_options
from apiserver.redis_manager import redman
from .fixed_user import FixedUser
from .identity import Identity
from .payload import Payload, Token, Basic, AuthType

try:
    from .casdoor_auth import casdoor_auth
    CASDOOR_AVAILABLE = True
except ImportError:
    CASDOOR_AVAILABLE = False
    casdoor_handler = None

def extract_token_from_request(call):
    """
    Extract JWT token from request headers or cookies
    
    Args:
        call: The API call object containing request info
        
    Returns:
        str: JWT token if found, None otherwise
    """
    # First try Authorization header
    auth_header = getattr(call, 'headers', {}).get('Authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header[7:]  # Remove 'Bearer ' prefix
    
    # Try cookie
    cookies = getattr(call, 'cookies', {})
    
    # Check for Casdoor token cookie
    casdoor_token = cookies.get('clearml-token-k8s')
    if casdoor_token:
        return casdoor_token
    
    # Check for regular ClearML token cookie  
    clearml_token = cookies.get('clearml_token_basic')
    if clearml_token:
        return clearml_token
    
    return None


log = config.logger(__file__)
entity_keys = set(get_options(Entities))
verify_user_tokens = config.get("apiserver.auth.verify_user_tokens", True)
_revoked_tokens_key = "revoked_tokens"
redis = redman.connection("apiserver")


def get_auth_func(auth_type):
    if auth_type == AuthType.bearer_token:
        return authorize_token
    elif auth_type == AuthType.basic:
        return authorize_credentials
    raise errors.unauthorized.BadAuthType()


# def authorize_token(jwt_token, service, action, call):
#     """Validate token against service/endpoint and requests data (dicts).
#     Returns a parsed token object (auth payload)
#     """
#     call_info = {"ip": call.real_ip}

#     def log_error(msg):
#         info = ", ".join(f"{k}={v}" for k, v in call_info.items())
#         log.error(f"{msg} Call info: {info}")

#     # First, try Casdoor authentication if available and token looks like Casdoor token
#     if CASDOOR_AVAILABLE and casdoor_auth and casdoor_auth.is_enabled():
#         try:
#             log.info("Attempting Casdoor authentication")
#             casdoor_payload = casdoor_auth.authenticate_user(jwt_token)
#             if casdoor_payload:
#                 log.info(f"User authenticated via Casdoor: {casdoor_payload.identity.user_name}")
#                 return casdoor_payload
#         except Exception as e:
#             log.error(f"Casdoor authentication error: {e}")


#             # Fall through to try regular ClearML token authentication
#     # if CASDOOR_AVAILABLE and casdoor_auth and casdoor_auth.is_enabled():
#     #     if casdoor_handler.is_casdoor_token(jwt_token):
#     #         try:
#     #             casdoor_payload = casdoor_handler.authenticate_token(jwt_token)
#     #             if casdoor_payload:
#     #                 log.info(f"User authenticated via Casdoor: {casdoor_payload.identity.user_name}")
#     #                 return casdoor_payload
#     #         except Exception as e:
#     #             log.error(f"Casdoor authentication error: {e}")
#     #             # Fall through to try regular ClearML token authentication

#     try:
#         token = Token.from_encoded_token(jwt_token)
#         if is_token_revoked(token):
#             raise errors.unauthorized.InvalidToken("revoked token")
#         return token
#     except jwt.exceptions.InvalidKeyError as ex:
#         log_error("Failed parsing token.")
#         raise errors.unauthorized.InvalidToken(
#             "jwt invalid key error", reason=ex.args[0]
#         )
#     except jwt.InvalidTokenError as ex:
#         log_error("Failed parsing token.")
#         raise errors.unauthorized.InvalidToken("invalid jwt token", reason=ex.args[0])
#     except ValueError as ex:
#         log_error(f"Failed while processing token: {str(ex.args[0])}.")
#         raise errors.unauthorized.InvalidToken(
#             "failed processing token", reason=ex.args[0]
#         )
#     except Exception:
#         log_error("Failed processing token.")
#         raise

# Update your authorize_token function to use this:
def authorize_token(jwt_token, service, action, call):
    """Validate token against service/endpoint and requests data (dicts).
    Returns a parsed token object (auth payload)
    """
    log_file = "/tmp/auth_trace.log"
    
    # Helper to write to the log file
    def write_log(message):
        # Use 'a' (append) to add to the file
        with open(log_file, "a") as f:
            f.write(f"[{datetime.utcnow().isoformat()}] {message}\n")

    # Use 'w' (write) to start a fresh log for each API call
    with open(log_file, "w") as f:
        f.write(f"--- NEW AUTHORIZATION TRACE FOR REQUEST {call.id} ---\n")
        
    call_info = {"ip": call.real_ip}
    
    def log_error(msg):
        info = ", ".join(f"{k}={v}" for k, v in call_info.items())
        log.error(f"{msg} Call info: {info}")

    # If no token provided directly, try to extract from request
    if not jwt_token:
        jwt_token = extract_token_from_request(call)
        if not jwt_token:
            raise errors.unauthorized.MissingRequiredFields(field="authorization token")

    # First, try Casdoor authentication if available
    if CASDOOR_AVAILABLE and casdoor_auth and casdoor_auth.is_enabled():
        try:
            log.info("Attempting Casdoor authentication")
            casdoor_payload = casdoor_auth.authenticate_user(jwt_token)
            if casdoor_payload:
                log.info(f"User authenticated via Casdoor: {casdoor_payload.identity.user_name}")
                return casdoor_payload
        except Exception as e:
            log.error(f"Casdoor authentication error: {e}")
            # Fall through to try regular ClearML token authentication

    # Regular ClearML token authentication
    try:
        token = Token.from_encoded_token(jwt_token)
        if is_token_revoked(token):
            raise errors.unauthorized.InvalidToken("revoked token")
        return token
    except jwt.exceptions.InvalidKeyError as ex:
        log_error("Failed parsing token.")
        raise errors.unauthorized.InvalidToken(
            "jwt invalid key error", reason=ex.args[0]
        )
    except jwt.InvalidTokenError as ex:
        log_error("Failed parsing token.")
        raise errors.unauthorized.InvalidToken("invalid jwt token", reason=ex.args[0])
    except ValueError as ex:
        log_error(f"Failed while processing token: {str(ex.args[0])}.")
        raise errors.unauthorized.InvalidToken(
            "failed processing token", reason=ex.args[0]
        )
    except Exception:
        log_error("Failed processing token.")
        raise

def authorize_credentials(auth_data, service, action, call):
    """Validate credentials against service/action and request data (dicts).
    Returns a new basic object (auth payload)
    """
    try:
        access_key, _, secret_key = (
            base64.b64decode(auth_data.encode()).decode("latin-1").partition(":")
        )
    except Exception as e:
        log.exception("malformed credentials")
        raise errors.unauthorized.BadCredentials(str(e))

    query = Q(credentials__match=Credentials(key=access_key, secret=secret_key))

    fixed_user = None

    if FixedUser.enabled():
        fixed_user = FixedUser.get_by_username(access_key)
        if fixed_user:
            if FixedUser.pass_hashed():
                if not compare_secret_key_hash(secret_key, fixed_user.password):
                    raise errors.unauthorized.InvalidCredentials(
                        "bad username or password"
                    )
            else:
                if secret_key != fixed_user.password:
                    raise errors.unauthorized.InvalidCredentials(
                        "bad username or password"
                    )

            if fixed_user.is_guest and not FixedUser.is_guest_endpoint(service, action):
                raise errors.unauthorized.InvalidCredentials(
                    "endpoint not allowed for guest"
                )

            query = Q(id=fixed_user.user_id)

    with translate_errors_context("authorizing request"):
        user = User.objects(query).first()
        if not user:
            raise errors.unauthorized.InvalidCredentials(
                "failed to locate provided credentials"
            )

        if not fixed_user:
            # In case these are proper credentials, update last used time
            User.objects(id=user.id, credentials__key=access_key).update(
                **{
                    "set__credentials__$__last_used": datetime.utcnow(),
                    "set__credentials__$__last_used_from": call.get_worker(
                        default=call.real_ip
                    ),
                }
            )

    company = Company.objects(id=user.company).only("id", "name").first()

    if not company:
        raise errors.unauthorized.InvalidCredentials("invalid user company")

    identity = Identity(
        user=user.id,
        company=user.company,
        role=user.role,
        user_name=user.name,
        company_name=company.name,
    )

    basic = Basic(user_key=access_key, identity=identity)

    return basic


def authorize_impersonation(user, identity, service, action, call):
    """ Returns a new basic object (auth payload)"""
    if not user:
        raise ValueError("missing user")

    company = Company.objects(id=user.company).only("id", "name").first()
    if not company:
        raise errors.unauthorized.InvalidCredentials("invalid user company")

    return Payload(auth_type=None, identity=identity)


def compare_secret_key_hash(secret_key: str, hashed_secret: str) -> bool:
    """
    Compare hash for the passed secret key with the passed hash
    :return: True if equal. Otherwise False
    """
    return bcrypt.checkpw(
        secret_key.encode(), base64.b64decode(hashed_secret.encode("ascii"))
    )


def is_token_revoked(token: Token) -> bool:
    if not isinstance(token, Token) or not token.session_id:
        return False

    return redis.zscore(_revoked_tokens_key, token.session_id) is not None


def revoke_auth_token(token: Token):
    if not isinstance(token, Token) or not token.session_id:
        return

    timestamp_now = int(time())
    expiration_timestamp = token.exp
    if not expiration_timestamp:
        expiration_timestamp = timestamp_now + Token.default_expiration_sec

    redis.zadd(_revoked_tokens_key, {token.session_id: expiration_timestamp})
    redis.zremrangebyscore(_revoked_tokens_key, min=0, max=timestamp_now)

def is_casdoor_token(jwt_token):
    """
    Determine if a JWT token is from Casdoor based on its characteristics
    """
    try:
        # Decode without verification to check the structure
        decoded = jwt.decode(jwt_token, options={"verify_signature": False})
        
        # Check for Casdoor-specific claims
        casdoor_indicators = [
            decoded.get('iss') == 'https://iam.ai-lab.ir',  # Your Casdoor issuer
            'displayName' in decoded,  # Casdoor-specific claim
            'tokenType' in decoded,    # Casdoor-specific claim
            decoded.get('aud') and 'org-built-in' in str(decoded.get('aud')),  # Casdoor audience pattern
        ]
        
        # If any Casdoor indicator is present, treat as Casdoor token
        return any(casdoor_indicators)
        
    except Exception:
        return False
