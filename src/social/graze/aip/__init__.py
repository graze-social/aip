"""
AIP - AT Protocol Identity Provider

This module implements an AT Protocol Identity Provider service that handles user authentication
and identity resolution for the Bluesky/AT Protocol ecosystem. It serves as a bridge between
users and AT Protocol services, managing authentication flows, token management, and identity
resolution.

Key Components:
- app: Web application layer with request handlers and server configuration
- atproto: Integration with AT Protocol, handling authentication and PDS communication
- model: Database models for storing authentication data and user information
- resolve: Identity resolution utilities for AT Protocol DIDs and handles

Architecture Overview:
1. Authentication Flow:
   - User initiates OAuth flow through the service
   - Service verifies user identity with AT Protocol PDS
   - Secure tokens are issued and managed

2. Identity Resolution:
   - Resolves user handles to DIDs through DNS and HTTP mechanisms
   - Resolves DIDs to canonical data (handle, PDS location)

3. Token Management:
   - Background tasks refresh tokens before expiry
   - Redis-backed token caching
   - Task distribution using work queues

The service is designed with security, performance, and reliability in mind,
following OAuth 2.0 and AT Protocol specifications.
"""
