from jsonmodels.fields import StringField, BoolField, EmbeddedField, ListField
from jsonmodels.models import Base

from apiserver.apimodels import DictField, callable_default


class GetSupportedModesRequest(Base):
    pass
    # state = StringField(help_text="ASCII base64 encoded application state")
    # callback_url_prefix = StringField()


class BasicGuestMode(Base):
    enabled = BoolField(default=False)
    name = StringField()
    username = StringField()
    password = StringField()


class BasicMode(Base):
    enabled = BoolField(default=False)
    guest = callable_default(EmbeddedField)(BasicGuestMode, default=BasicGuestMode)


class ServerErrors(Base):
    missed_es_upgrade = BoolField(default=False)
    es_connection_error = BoolField(default=False)


class GetSupportedModesResponse(Base):
    basic = EmbeddedField(BasicMode)
    server_errors = EmbeddedField(ServerErrors)
    sso = DictField([str, type(None)])
    sso_providers = ListField([dict])
    authenticated = BoolField(default=False)

class CasdoorAuthenticateRequest(Base):
    """Request model for Casdoor token authentication"""
    token = StringField(required=True, help_text="Casdoor JWT token")


class AuthenticatedUser(Base):
    """User information returned after successful authentication"""
    id = StringField(help_text="User ID")
    name = StringField(help_text="User name")
    company = StringField(help_text="User company ID")


class CasdoorAuthenticateResponse(Base):
    """Response model for Casdoor token authentication"""
    success = BoolField(default=False, help_text="Authentication success status")
    user = EmbeddedField(AuthenticatedUser, help_text="User information if successful")
    error = StringField(help_text="Error message if authentication failed")