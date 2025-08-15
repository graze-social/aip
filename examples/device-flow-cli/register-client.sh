#!/bin/bash
# Register OAuth client for device-flow-cli example

set -e

# Configuration
AIP_BASE_URL="${AIP_BASE_URL:-http://localhost:8080}"
CLIENT_NAME="Device Flow CLI Example"

echo "🚀 Registering OAuth client for device-flow-cli example"
echo "📡 AIP Server: $AIP_BASE_URL"
echo

# Check if AIP is running
echo "🔍 Checking if AIP server is running..."
if ! curl -s "$AIP_BASE_URL/.well-known/oauth-authorization-server" > /dev/null; then
    echo "❌ Error: AIP server is not running at $AIP_BASE_URL"
    echo "   Please start AIP first:"
    echo "   cd ../../.. && cargo run --bin aip"
    exit 1
fi
echo "✅ AIP server is running"
echo

# Register the client
echo "📝 Registering OAuth client..."
RESPONSE=$(curl -s -X POST "$AIP_BASE_URL/oauth/clients/register" \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "'"$CLIENT_NAME"'",
    "grant_types": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
    "response_types": ["device_code"],
    "token_endpoint_auth_method": "none",
    "application_type": "native",
    "software_id": "device-flow-cli-example",
    "software_version": "0.1.0",
    "scope": "atproto:atproto atproto:transition:generic"
  }' \
  -w "\nHTTP_STATUS:%{http_code}")

# Extract HTTP status
HTTP_STATUS=$(echo "$RESPONSE" | tail -n1 | cut -d: -f2)
BODY=$(echo "$RESPONSE" | sed '$ d')

if [ "$HTTP_STATUS" -eq 201 ] || [ "$HTTP_STATUS" -eq 200 ]; then
    echo "✅ Client registered successfully!"
    echo
    echo "📋 Client Details:"
    echo "$BODY" | jq '.'
    echo
    # Extract the generated client_id
    GENERATED_CLIENT_ID=$(echo "$BODY" | jq -r '.client_id')
    echo
    echo "🎯 You can now run the device flow example:"
    echo "   cargo run -- --client-id $GENERATED_CLIENT_ID"
elif [ "$HTTP_STATUS" -eq 409 ]; then
    echo "ℹ️  Client already exists (HTTP 409)"
    echo
    echo "🎯 You can run the device flow example:"
    echo "   cargo run"
    echo "   # Note: You'll need the previously registered client ID"
elif [ "$HTTP_STATUS" -eq 404 ]; then
    echo "❌ Client registration endpoint not found (HTTP 404)"
    echo "   This likely means client management API is disabled."
    echo "   Enable it by setting: ENABLE_CLIENT_API=true"
    echo "   Or manually register the client through AIP admin interface."
    exit 1
else
    echo "❌ Client registration failed (HTTP $HTTP_STATUS)"
    echo "Response:"
    echo "$BODY" | jq '.' 2>/dev/null || echo "$BODY"
    exit 1
fi
