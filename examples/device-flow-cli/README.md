# Device Flow CLI Example

This CLI example demonstrates how to implement the **OAuth 2.0 Device Authorization Grant** (RFC 8628) flow with AIP. This flow is perfect for devices with limited input capabilities (like smart TVs, IoT devices, or CLI tools) that need to authenticate users.

## 🚀 Quick Start

### Prerequisites

1. **AIP server running** - Make sure AIP is running on `http://localhost:8080`
2. **Client management API enabled** - Set `ENABLE_CLIENT_API=true` in AIP (optional, for automatic registration)

### Setup

1. **Start AIP server:**
   ```bash
   # From the AIP root directory
   cd ../../..
   ENABLE_CLIENT_API=true cargo run --bin aip
   ```

2. **Register the OAuth client:**
   ```bash
   # From the device-flow-cli directory
   ./register-client.sh
   ```
   
   This will automatically register a public OAuth client with the device code grant type.

### Run the Example

```bash
# From the device-flow-cli directory
cargo run

# Or with custom parameters
cargo run -- --aip-url http://localhost:8080 --client-id device-flow-cli-example --scope "atproto"
```

### Expected Output

The CLI will guide you through the complete device flow:

```
🚀 Starting OAuth 2.0 Device Authorization Grant flow
📡 AIP Server: http://localhost:8080
🆔 Client ID: device-flow-cli-example

📱 Device Authorization Required
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
📋 User Code: ABCD-1234
🌐 Verification URL: http://localhost:8080/device
🔗 Quick Link: http://localhost:8080/device?user_code=ABCD-1234
⏰ Code expires in 600 seconds

🎯 Next Steps:
   1. Open http://localhost:8080/device in your browser
   2. Enter the user code: ABCD-1234
   3. Complete the authentication process
   4. Return here - the CLI will automatically detect completion

🔄 Starting token polling (interval: 5s, timeout: 600s)
📡 Polling attempt #1
⏳ Authorization still pending, waiting 5 seconds...
📡 Polling attempt #2
🎉 Access token obtained successfully!

✅ Authentication Successful!
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🎫 Access Token: FdTkXbhf...yMj6aQ
⏰ Expires in: 3600 seconds
🏷️ Token Type: bearer
📋 Granted Scope: atproto

🔍 Testing Access Token...
✅ Token is valid!
👤 User: did:plc:abcd1234...

🎉 Device flow complete! You can now use the access token to make authenticated API calls.
```

## 🔧 Configuration

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `--aip-url` | AIP server base URL | `http://localhost:8080` |
| `--client-id` | OAuth client ID | `device-flow-cli-example` |
| `--scope` | OAuth scope (optional) | None |

### Environment Variables

You can also use environment variables:

```bash
export AIP_BASE_URL="http://localhost:8080"
export CLIENT_ID="my-device-client"
export OAUTH_SCOPE="atproto"

cargo run
```

## 🔄 How It Works

The Device Authorization Grant follows these steps:

### 1. **Device Authorization Request**
```http
POST /oauth/device/authorization
Content-Type: application/x-www-form-urlencoded

client_id=device-flow-cli-example&scope=atproto
```

**Response:**
```json
{
  "device_code": "GmRhmhcxhwEzkoEqiMEg_DnyEysNkuNhszIySk9eS",
  "user_code": "ABCD-1234", 
  "verification_uri": "http://localhost:8080/device",
  "verification_uri_complete": "http://localhost:8080/device?user_code=ABCD-1234",
  "expires_in": 600,
  "interval": 5
}
```

### 2. **User Authorization**
- User opens `verification_uri` in browser
- Enters the `user_code` 
- Completes ATProtocol OAuth authentication
- Authorizes the device

### 3. **Token Polling**
The CLI polls the token endpoint until authorization is complete:

```http
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=GmRhmhcxhwEzkoEqiMEg_DnyEysNkuNhszIySk9eS&client_id=device-flow-cli-example
```

**Pending Response:**
```json
{
  "error": "authorization_pending"
}
```

**Success Response:**
```json
{
  "access_token": "FdTkXbhfrQT_WS2cRFf-tX2TBWHlvPfrL-4XmyMj6aQ",
  "token_type": "bearer",
  "expires_in": 3600,
  "scope": "atproto"
}
```

### 4. **Token Usage**
The CLI tests the access token by calling the session endpoint:

```http
GET /api/atprotocol/session
Authorization: Bearer FdTkXbhfrQT_WS2cRFf-tX2TBWHlvPfrL-4XmyMj6aQ
```

## 🎯 Key Features

- **📱 User-friendly flow** - Clear instructions and progress indicators
- **🔄 Automatic polling** - Handles token polling with proper intervals
- **⚠️ Error handling** - Comprehensive error handling for all failure modes
- **🎨 Rich output** - Colored output with emojis for better UX
- **🔍 Token validation** - Tests the obtained token to ensure it works
- **⚙️ Configurable** - Support for custom AIP URLs, client IDs, and scopes

## 🛠️ Error Handling

The CLI handles all standard OAuth 2.0 device flow errors:

- **`authorization_pending`** - User hasn't completed authorization yet
- **`slow_down`** - Polling too fast, increases interval automatically  
- **`expired_token`** - Device code has expired
- **`access_denied`** - User denied the authorization
- **Network errors** - Connection failures, timeouts, etc.

## 🔐 Security Considerations

- **Public client** - This example uses a public OAuth client (no client secret)
- **Short-lived codes** - Device codes expire in 10 minutes by default
- **Rate limiting** - Respects polling intervals and slow-down responses
- **No token storage** - Tokens are only displayed, not persisted

## 🏗️ Integration

To integrate this pattern into your own applications:

1. **Copy the core structs** - `DeviceAuthorizationRequest`, `TokenResponse`, etc.
2. **Implement the three steps** - authorization request, polling, token usage
3. **Handle errors gracefully** - Especially network and OAuth errors
4. **Store tokens securely** - Use secure storage for production applications

## 📚 References

- [RFC 8628: OAuth 2.0 Device Authorization Grant](https://tools.ietf.org/html/rfc8628)
- [AIP Documentation](../../../README.md)
- [OAuth 2.0 Security Best Practices](https://tools.ietf.org/html/draft-ietf-oauth-security-topics)

## 🐛 Troubleshooting

### Client Not Found
```
Device authorization request failed: 400 Bad Request - {"error":"invalid_client"}
```

**Solution:** Make sure your client is registered in AIP. Use the included registration script:

```bash
# From the device-flow-cli directory
./register-client.sh
```

Or manually register using the AIP client management API.

### Connection Refused
```
Failed to send device authorization request: Connection refused
```

**Solution:** Make sure AIP is running on the specified URL:

```bash
# Start AIP server
cargo run --bin aip
```

### Invalid Token
```
❌ Token test failed: Access token test failed: 500 Internal Server Error
```

**Solution:** This usually means the session is incomplete. Check AIP logs for more details.