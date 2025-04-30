"""
Database Models

This package defines the database models for the AIP service using SQLAlchemy ORM.
These models represent the persistent data structures for authentication, user
information, and service health.

Key Models:
- base.py: Base SQLAlchemy model with common type definitions
- app_password.py: Models for app password authentication
- oauth.py: Models for OAuth sessions and token management
- handles.py: Models for user handles and DIDs
- health.py: Health monitoring model

The data models follow these relationships:
- Handle: Represents a user identity with DID, handle, and PDS location
- OAuthRequest: Temporary storage for OAuth request data
- OAuthSession: Active OAuth session with tokens and expiration info
- AppPassword: App-specific password credentials

Each model includes:
- Creation and expiration timestamps
- Secure storage of credentials (encrypted where appropriate)
- Relationships to other models where needed

The models use SQLAlchemy's async interface for non-blocking database operations
and include methods for common operations like upserts.
"""