import os
import jwt
import logging
from typing import Optional, Dict, Any
from casdoor import CasdoorSDK
from dataclasses import dataclass


@dataclass
class AuthResult:
    """Result of authentication attempt"""
    is_authenticated: bool
    user_id: Optional[str] = None
    username: Optional[str] = None
    error_message: Optional[str] = None
    user_data: Optional[Dict[str, Any]] = None


class CasdoorAuthenticator:
    """
    A class for authenticating users with Casdoor using JWT tokens.
    
    Environment variables required:
    - CASDOOR_ENDPOINT: Base URL of your Casdoor instance
    - CASDOOR_CLIENT_ID: Client ID from Casdoor application
    - CASDOOR_CLIENT_SECRET: Client secret from Casdoor application
    - CASDOOR_CERTIFICATE_PATH: Path to certificate file (optional if CASDOOR_CERTIFICATE is provided)
    - CASDOOR_CERTIFICATE: Certificate content as string (optional if CASDOOR_CERTIFICATE_PATH is provided)
    - CASDOOR_ORG_NAME: Organization name (default: 'built-in')
    - CASDOOR_APP_NAME: Application name (default: 'app-built-in')
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """
        Initialize the Casdoor authenticator with configuration from environment variables.
        
        Args:
            logger: Optional logger instance for debugging
        """
        self.logger = logger or logging.getLogger(__name__)
        self._casdoor_client = None
        self._load_config()
        self._initialize_client()
    
    def _load_config(self):
        """Load configuration from environment variables"""
        required_vars = [
            'CASDOOR_ENDPOINT',
            'CASDOOR_CLIENT_ID',
            'CASDOOR_CLIENT_SECRET'
        ]
        
        missing_vars = [var for var in required_vars if not os.getenv(var)]
        if missing_vars:
            raise ValueError(f"Missing required environment variables: {', '.join(missing_vars)}")
        
        self.endpoint = os.getenv('CASDOOR_ENDPOINT')
        self.client_id = os.getenv('CASDOOR_CLIENT_ID')
        self.client_secret = os.getenv('CASDOOR_CLIENT_SECRET')
        self.org_name = os.getenv('CASDOOR_ORG_NAME', 'built-in')
        self.application_name = os.getenv('CASDOOR_APP_NAME', 'app-built-in')
        
        # Load certificate
        self.certificate = self._load_certificate()
        
        self.logger.info("Configuration loaded successfully")
    
    # def _load_certificate(self) -> str:
    #     """Load certificate from file or environment variable"""
    #     cert_content = os.getenv('CASDOOR_CERTIFICATE')
    #     if cert_content:
    #         return cert_content
        
    #     cert_path = os.getenv('CASDOOR_CERTIFICATE_PATH')
    #     if cert_path and os.path.exists(cert_path):
    #         with open(cert_path, 'r') as cert_file:
    #             return cert_file.read()
        
    #     raise ValueError(
    #         "Certificate not found. Please provide either CASDOOR_CERTIFICATE "
    #         "or CASDOOR_CERTIFICATE_PATH environment variable"
    #     )
    # In apiserver/service_repo/auth/casdoor_authenticator.py

    def _load_certificate(self) -> str:
        """Load the certificate directly from a local file."""
        try:
            # Get the absolute path of the directory where this script is located
            script_dir = os.path.dirname(os.path.abspath(__file__))
            
            # Define the certificate filename
            cert_filename = "casdoor_certificate.pem"
            
            # Construct the full path to the certificate file
            cert_path = os.path.join(script_dir, cert_filename)
            
            self.logger.info(f"Attempting to load certificate from local path: {cert_path}")
            
            with open(cert_path, 'r') as cert_file:
                certificate_content = cert_file.read()
                self.logger.info("Successfully loaded certificate from local file.")
                return certificate_content
                
        except FileNotFoundError:
            self.logger.error(f"CRITICAL: Certificate file '{cert_filename}' not found in the same directory as the script.")
            raise ValueError(f"Certificate file not found at {cert_path}")
        except Exception as e:
            self.logger.error(f"CRITICAL: Failed to read local certificate file: {e}")
            raise
    
    def _initialize_client(self):
        """Initialize the Casdoor SDK client"""
        try:
            self._casdoor_client = CasdoorSDK(
                self.endpoint,
                self.client_id,
                self.client_secret,
                self.certificate,
                self.org_name,
                self.application_name
            )
            self.logger.info("CasdoorSDK initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize CasdoorSDK: {e}")
            raise
        
    
    def authenticate_user(self, token: str) -> AuthResult:
        """
        Authenticate a user using their JWT token.
        
        Args:
            token: The JWT token to authenticate
            
        Returns:
            AuthResult: Object containing authentication result and user information
        """
        try:
            # First, decode the token to extract user information
            decoded_token = jwt.decode(token, options={"verify_signature": False})
            user_id = decoded_token.get('sub')
            username = decoded_token.get('name', decoded_token.get('preferred_username'))
            
            if not user_id:
                return AuthResult(
                    is_authenticated=False,
                    error_message="Invalid token: missing user ID"
                )
            
            # Verify user exists in Casdoor
            user = self._casdoor_client.get_user_by_user_id(user_id)
            
            if user:
                self.logger.info(f"User authenticated successfully: {user.name}")
                return AuthResult(
                    is_authenticated=True,
                    user_id=user_id,
                    username=user.name,
                    user_data={
                        'id': user.id if hasattr(user, 'id') else user_id,
                        'name': user.name,
                        'email': getattr(user, 'email', None),
                        'display_name': getattr(user, 'displayName', user.name),
                        'organization': getattr(user, 'owner', self.org_name)
                    }
                )
            else:
                self.logger.warning(f"User not found in Casdoor: {user_id}")
                return AuthResult(
                    is_authenticated=False,
                    user_id=user_id,
                    username=username,
                    error_message="User not found in system"
                )
                
        except jwt.InvalidTokenError as e:
            self.logger.error(f"Invalid JWT token: {e}")
            return AuthResult(
                is_authenticated=False,
                error_message=f"Invalid token format: {str(e)}"
            )
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return AuthResult(
                is_authenticated=False,
                error_message=f"Authentication failed: {str(e)}"
            )
    
    def user_exists(self, token: str) -> bool:
        """
        Simple method to check if user exists (backward compatibility).
        
        Args:
            token: The JWT token to check
            
        Returns:
            bool: True if user exists and is authenticated, False otherwise
        """
        result = self.authenticate_user(token)
        return result.is_authenticated
    
    def test_connection(self) -> bool:
        """
        Test the connection to Casdoor.
        
        Returns:
            bool: True if connection is successful, False otherwise
        """
        try:
            apps = self._casdoor_client.get_applications()
            self.logger.info(f"Connection test successful. Found {len(apps)} applications")
            return True
        except Exception as e:
            self.logger.error(f"Connection test failed: {e}")
            return False
    
    def get_user_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed user information from token.
        
        Args:
            token: The JWT token
            
        Returns:
            Dict containing user information or None if not authenticated
        """
        result = self.authenticate_user(token)
        return result.user_data if result.is_authenticated else None


# Example usage and testing
if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO)
    
    # Example of how to use the class
    try:
        # Initialize authenticator (reads from environment variables)
        auth = CasdoorAuthenticator()
        
        # Test connection
        if auth.test_connection():
            print("✓ Connected to Casdoor successfully")
        else:
            print("✗ Failed to connect to Casdoor")
            exit(1)
        
        # Example token (you would get this from your frontend)
        with open("test_user.jwt", "r") as token_file:
            user_token = token_file.read().strip()
        
        # Authenticate user
        result = auth.authenticate_user(user_token)
        
        if result.is_authenticated:
            print(f"✓ User authenticated: {result.username}")
            print(f"User ID: {result.user_id}")
            print(f"User data: {result.user_data}")
        else:
            print(f"✗ Authentication failed: {result.error_message}")
        
        # Simple boolean check
        exists = auth.user_exists(user_token)
        print(f"User exists: {exists}")
        
    except Exception as e:
        print(f"Error: {e}")