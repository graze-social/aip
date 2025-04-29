"""
AT Protocol Integration

This package provides integration with the AT Protocol, handling authentication flows
and communication with Personal Data Server (PDS) instances.

Key Components:
- app_password.py: Implementation of app password authentication 
- oauth.py: Implementation of OAuth flows including authorization code and refresh token
- chain.py: Middleware chain for API requests (DPoP, claims, metrics)
- pds.py: Interaction with PDS (Personal Data Server) instances

Key Features:
- OAuth 2.0 flow implementation with PKCE
- DPoP (Demonstrating Proof-of-Possession) for access tokens
- JWT-based client assertion for secure client authentication
- Proactive token refresh to maintain session validity

The authentication flow follows these steps:
1. Initialize OAuth flow with subject (handle or DID)
2. Generate PKCE challenge and redirect to authorization server
3. Complete OAuth flow with authorization code
4. Store tokens and set up refresh schedule
5. Refresh tokens before expiry to maintain session validity

All communication with AT Protocol services uses middleware chains for
consistent handling of authentication, metrics, and error reporting.
"""