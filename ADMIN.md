# ADMIN.md

This document provides guidance for administering AIP (ATProtocol Identity Provider) in production environments.

## Recommendations

1. **Periodically build and deploy the project.** Project library and container layer updates will include important security updates.

2. **Use separate `OAUTH_SIGNING_KEYS` and `ATPROTO_OAUTH_SIGNING_KEYS` values.** This provides better security isolation between the base OAuth system and ATProtocol OAuth integrations.

3. **Rotate `ATPROTO_OAUTH_SIGNING_KEYS` keys periodically.** Regular key rotation is a security best practice that limits the impact of potential key compromise.

## ATProtocol OAuth Signing Key Rotation

The signing keys used to create and refresh ATProtocol OAuth credentials can be rotated as needed.

### Key Generation Process

1. **Generate a new private key** using the `goat` tool:
   ```bash
   goat key generate -t p256
   ```

2. **Prepare the key string** by taking the private key string that starts with "z45" and adding the prefix "did:key:" to the full value.

3. **Add the new key** to the front of the `ATPROTO_OAUTH_SIGNING_KEYS` environment variable using a semicolon (`;`) to separate multiple values.

### Example Configuration

```
ATPROTO_OAUTH_SIGNING_KEYS=did:key:z42tnV8MPtPPeJjH6h6P6De7iemk9qkuEFAnmBW9JRD9hd8d;did:key:z42thyf59TNmDL7C6ZhvemESTNC8aQ2nhxtt8migydgui8Lp
```

### Important Considerations

**WARNING:** Rotating ATProtocol OAuth signing keys doesn't immediately invalidate existing access tokens. Tokens signed with previous keys will continue to be valid until they expire naturally. Plan your key rotation strategy accordingly, considering:

- The expiration time of your access tokens
- The need to maintain service availability during rotation
- The requirement to support tokens signed with both old and new keys during the transition period

## Key Storage and Security

- Store signing keys securely using environment variables or a secrets management system
- Never commit signing keys to version control
- Limit access to signing keys to only the processes and personnel that require them
- Monitor key usage and access patterns for suspicious activity

## Monitoring and Maintenance

- Monitor AIP logs for authentication failures that might indicate key-related issues
- Set up alerts for unusual patterns in token generation or validation
- Regularly review and update dependencies to ensure security patches are applied
- Test key rotation procedures in a staging environment before applying to production