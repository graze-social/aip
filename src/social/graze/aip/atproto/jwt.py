"""
JWT and DPoP utilities for AT Protocol authentication.

Provides helper functions for creating DPoP (Demonstrating Proof of Possession) JWTs
as specified in the OAuth 2.0 DPoP draft specification, reducing code duplication
across OAuth flows.
"""

import secrets
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Tuple
from jwcrypto import jwt, jwk
from ulid import ULID


def generate_dpop_key() -> Tuple[jwk.JWK, Dict[str, Any]]:
    """Generate a new DPoP key pair for token binding.
    
    Creates an ECDSA P-256 key pair suitable for DPoP JWT signing with a unique
    key identifier for tracking and validation.
    
    Returns:
        Tuple[jwk.JWK, Dict[str, Any]]: A tuple containing:
            - dpop_key: The complete JWK including private key for signing
            - public_key_dict: The public key portion as a dictionary for JWT headers
            
    Security considerations:
        - Uses ECDSA with P-256 curve as recommended by DPoP specification
        - Generates cryptographically secure random key identifier
    """
    dpop_key = jwk.JWK.generate(kty="EC", crv="P-256", kid=str(ULID()), alg="ES256")
    public_key_dict = dpop_key.export_public(as_dict=True)
    return dpop_key, public_key_dict


def create_dpop_header(public_key_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Create DPoP JWT header with embedded public key.
    
    Constructs the header section of a DPoP JWT according to the specification,
    including the public key for proof of possession verification.
    
    Args:
        public_key_dict: Public key dictionary from generate_dpop_key()
        
    Returns:
        Dict[str, Any]: DPoP JWT header ready for use with jwcrypto
    """
    return {
        "alg": "ES256",
        "jwk": public_key_dict,
        "typ": "dpop+jwt",
    }


def create_dpop_claims(
    http_method: str,
    http_uri: str,
    issued_at: Optional[datetime] = None,
    expires_in_seconds: int = 30,
    nonce: Optional[str] = None
) -> Dict[str, Any]:
    """Create DPoP JWT claims for request binding.
    
    Constructs the claims section of a DPoP JWT, binding the token to a specific
    HTTP request method and URI to prevent token misuse.
    
    Args:
        http_method: HTTP method (e.g., "POST", "GET") 
        http_uri: Target HTTP URI for the request
        issued_at: Token issuance time (defaults to current UTC time)
        expires_in_seconds: Token validity period in seconds (default: 30)
        nonce: Optional nonce value for replay protection
        
    Returns:
        Dict[str, Any]: DPoP JWT claims ready for use with jwcrypto
        
    Security considerations:
        - Short expiration time (30s default) reduces replay attack window
        - Request binding prevents token use with different endpoints
        - Nonce support enables server-side replay protection
    """
    if issued_at is None:
        issued_at = datetime.now(timezone.utc)
    
    claims = {
        "htm": http_method.upper(),
        "htu": http_uri,
        "iat": int(issued_at.timestamp()),
        "exp": int(issued_at.timestamp()) + expires_in_seconds,
    }
    
    if nonce is not None:
        claims["nonce"] = nonce
        
    return claims


def create_dpop_jwt(
    dpop_key: jwk.JWK,
    http_method: str,
    http_uri: str,
    public_key_dict: Optional[Dict[str, Any]] = None,
    issued_at: Optional[datetime] = None,
    expires_in_seconds: int = 30,
    nonce: Optional[str] = None
) -> str:
    """Create a complete DPoP JWT for request authentication.
    
    Generates a signed DPoP JWT that proves possession of a private key and binds
    the JWT to a specific HTTP request. This is the main function for creating
    DPoP tokens in OAuth flows.
    
    Args:
        dpop_key: Private key for signing the JWT
        http_method: HTTP method for request binding
        http_uri: Target URI for request binding  
        public_key_dict: Public key dictionary (extracted from dpop_key if None)
        issued_at: Token issuance time (defaults to current UTC time)
        expires_in_seconds: Token validity period in seconds (default: 30)
        nonce: Optional nonce for replay protection
        
    Returns:
        str: Serialized DPoP JWT ready for use as HTTP header value
        
    Usage:
        ```python
        dpop_key, public_key = generate_dpop_key()
        dpop_token = create_dpop_jwt(
            dpop_key, 
            "POST", 
            "https://auth.bsky.social/oauth/token"
        )
        headers["DPoP"] = dpop_token
        ```
        
    Flow integration:
        - PAR requests: Binds to pushed authorization request endpoint
        - Token requests: Binds to token endpoint with authorization code
        - Refresh requests: Binds to token endpoint with refresh token
    """
    if public_key_dict is None:
        public_key_dict = dpop_key.export_public(as_dict=True)
    
    # Create header and claims
    header = create_dpop_header(public_key_dict)
    claims = create_dpop_claims(
        http_method, http_uri, issued_at, expires_in_seconds, nonce
    )
    
    # Add unique JWT identifier to prevent replay attacks
    claims["jti"] = secrets.token_urlsafe(32)
    
    # Create and sign the JWT
    dpop_jwt = jwt.JWT(header=header, claims=claims)
    dpop_jwt.make_signed_token(dpop_key)
    
    return dpop_jwt.serialize()


def create_dpop_header_and_claims(
    http_method: str,
    http_uri: str,
    public_key_dict: Dict[str, Any],
    issued_at: Optional[datetime] = None,
    expires_in_seconds: int = 30,
    nonce: Optional[str] = None
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Create DPoP header and claims separately for middleware use.
    
    Creates the header and claims components of a DPoP JWT without signing,
    useful for middleware that needs to modify claims (like adding jti) before
    signing.
    
    Args:
        http_method: HTTP method for request binding
        http_uri: Target URI for request binding
        public_key_dict: Public key dictionary for header embedding
        issued_at: Token issuance time (defaults to current UTC time)
        expires_in_seconds: Token validity period in seconds (default: 30)
        nonce: Optional nonce for replay protection
        
    Returns:
        Tuple[Dict[str, Any], Dict[str, Any]]: A tuple containing:
            - header: DPoP JWT header with embedded public key
            - claims: DPoP JWT claims with request binding
            
    Usage:
        Primarily used by GenerateDpopMiddleware in chain.py for request
        processing where claims need modification before signing.
    """
    header = create_dpop_header(public_key_dict)
    claims = create_dpop_claims(
        http_method, http_uri, issued_at, expires_in_seconds, nonce
    )
    
    return header, claims