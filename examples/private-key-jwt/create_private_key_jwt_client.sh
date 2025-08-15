#!/bin/bash

# Create Private Key JWT OAuth Client
# Simple script to register a client with private_key_jwt authentication
# Usage: bash create_private_key_jwt_client.sh [client_name]

set -e

# Configuration
AIP_BASE="${AIP_BASE_URL:-http://localhost:8080}"
CLIENT_NAME="${1:-My Private Key JWT Client}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/private_key_jwt_client"

echo "🔐 Creating Private Key JWT OAuth Client"
echo "Client Name: $CLIENT_NAME"
echo "AIP Server: $AIP_BASE"
echo

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Check dependencies
if ! command -v openssl >/dev/null 2>&1; then
    echo "❌ OpenSSL is required but not installed"
    exit 1
fi

if ! command -v jq >/dev/null 2>&1; then
    echo "❌ jq is required but not installed (brew install jq)"
    exit 1
fi

# Generate key pair
echo "🔑 Generating ES256 key pair..."
openssl ecparam -genkey -name prime256v1 -noout -out "$OUTPUT_DIR/private_key.pem"
openssl ec -in "$OUTPUT_DIR/private_key.pem" -pubout -out "$OUTPUT_DIR/public_key.pem"

# Create JWK Set using bash (more reliable hex parsing)
echo "🔧 Creating JWK Set..."

# Extract public key coordinates using reliable bash method
PUB_HEX=$(openssl ec -in "$OUTPUT_DIR/private_key.pem" -noout -text 2>/dev/null | grep -A 10 "pub:" | grep ":" | tr -d ' :' | tr -d '\n' | sed 's/pub//' | sed 's/ASN1OID.*//')

# Remove the '04' prefix and split into x,y coordinates  
COORDS=${PUB_HEX:2}
X_HEX=${COORDS:0:64}
Y_HEX=${COORDS:64:64}

# Convert to base64url
X_B64=$(printf "%s" "$X_HEX" | xxd -r -p | base64 | tr '+/' '-_' | tr -d '=')
Y_B64=$(printf "%s" "$Y_HEX" | xxd -r -p | base64 | tr '+/' '-_' | tr -d '=')

# Create JWK Set JSON
cat > "$OUTPUT_DIR/jwks.json" << EOF
{
  "keys": [
    {
      "kty": "EC",
      "crv": "P-256",
      "x": "$X_B64",
      "y": "$Y_B64",
      "use": "sig",
      "alg": "ES256",
      "kid": "key-1"
    }
  ]
}
EOF

echo '✅ JWK Set created'

# Register client
echo "📝 Registering OAuth client..."
RESPONSE=$(curl -s -X POST "$AIP_BASE/oauth/clients/register" \
  -H "Content-Type: application/json" \
  -d "{
    \"client_name\": \"$CLIENT_NAME\",
    \"token_endpoint_auth_method\": \"private_key_jwt\",
    \"grant_types\": [\"authorization_code\", \"refresh_token\", \"client_credentials\"],
    \"response_types\": [\"code\"],
    \"redirect_uris\": [\"http://localhost:8080/callback\"],
    \"scope\": \"atproto:atproto\",
    \"jwks\": $(cat "$OUTPUT_DIR/jwks.json")
  }")

if echo "$RESPONSE" | jq -e .client_id >/dev/null 2>&1; then
    CLIENT_ID=$(echo "$RESPONSE" | jq -r .client_id)
    echo "$RESPONSE" | jq . > "$OUTPUT_DIR/client_registration.json"
    
    echo "✅ Client registered successfully!"
    echo "   Client ID: $CLIENT_ID"
    echo
    echo "📁 Files created in $OUTPUT_DIR:"
    echo "   - private_key.pem (keep this secret!)"
    echo "   - public_key.pem"
    echo "   - jwks.json"
    echo "   - client_registration.json"
    echo
    echo "🔗 Use this client for private_key_jwt authentication"
    echo "   See test_private_key_jwt.sh for usage examples"
else
    echo "❌ Client registration failed:"
    echo "$RESPONSE" | jq .
    exit 1
fi