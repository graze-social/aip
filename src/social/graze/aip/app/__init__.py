"""
AIP Application Layer

This package implements the web application layer for the AIP service, handling HTTP requests
and responses using the aiohttp framework. It provides handlers for OAuth flows, app password 
authentication, and internal API endpoints.

Key Components:
- __main__.py: Entry point for running the application
- server.py: Web server configuration and middleware setup
- config.py: Configuration management using Pydantic settings
- handlers/: Request handlers for different endpoints
- tasks.py: Background tasks for token refresh and health monitoring
- cors.py: CORS handling for cross-origin requests
- util/: Utility functions for the application layer

The application uses several middleware layers:
- CORS middleware for handling cross-origin requests
- Statsd middleware for metrics collection
- Sentry middleware for error reporting

It provides the following main endpoints:
- OAuth authentication endpoints (/auth/atproto/*)
- Internal API endpoints (/internal/api/*)
- XRPC proxy endpoints (/xrpc/*)
"""