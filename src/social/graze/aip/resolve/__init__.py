"""
Identity Resolution

This package provides utilities for resolving AT Protocol identifiers (DIDs, handles)
to their canonical forms, implementing both DNS-based and HTTP-based resolution methods.

Key Components:
- handle.py: Handle resolution implementation
- __main__.py: CLI interface for resolution

Resolution Types:
1. Handle Resolution
   - DNS-based resolution via TXT records (_atproto.{handle})
   - HTTP-based resolution via well-known endpoints (.well-known/atproto-did)

2. DID Resolution
   - did:plc method resolution via PLC directory
   - did:web method resolution via well-known endpoints

The resolution flow typically follows these steps:
1. Parse the input to determine if it's a handle or DID
2. For handles, attempt DNS resolution first, then HTTP
3. For DIDs, use the appropriate method based on the DID type
4. Return the resolved canonical data (DID, handle, PDS location)

This implementation follows the AT Protocol specification for identity
resolution, ensuring compatibility with the broader ecosystem.
"""