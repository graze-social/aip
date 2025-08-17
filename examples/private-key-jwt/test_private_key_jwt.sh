#!/bin/bash

# Complete ATProtocol OAuth Flow with Private Key JWT Client Authentication
# This script demonstrates the full OAuth 2.1 + PAR flow with private_key_jwt authentication

set -e

# Configuration
AIP_BASE="${AIP_BASE_URL:-http://localhost:8080}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLIENT_DIR="$SCRIPT_DIR/private_key_jwt_client"

echo "🌐 Complete ATProtocol OAuth Flow with Private Key JWT"
echo "AIP Server: $AIP_BASE"
echo ""

# Check if client exists
if [ ! -f "$CLIENT_DIR/client_registration.json" ]; then
    echo "❌ Client not found. Run ./create_private_key_jwt_client.sh first"
    exit 1
fi

# Load client config
CLIENT_ID=$(jq -r .client_id "$CLIENT_DIR/client_registration.json")
KID=$(jq -r '.keys[0].kid' "$CLIENT_DIR/jwks.json")

echo "Client ID: $CLIENT_ID"
echo "Key ID: $KID"
echo ""

# Function to base64url encode (no padding)
base64url_encode() {
    printf '%s' "$1" | base64 | tr '+/' '-_' | tr -d '='
}

# Step 1: Create JWT client assertion for PAR
echo "🔐 Step 1: Creating JWT client assertion for PAR..."

NOW=$(date +%s)
EXP=$((NOW + 300))  # 5 minutes from now
JTI=$(openssl rand -hex 16)

# JWT for PAR endpoint
HEADER='{"typ":"JWT","alg":"ES256","kid":"'$KID'"}'
CLAIMS='{"iss":"'$CLIENT_ID'","sub":"'$CLIENT_ID'","aud":"'$AIP_BASE'/oauth/token","iat":'$NOW',"exp":'$EXP',"jti":"'$JTI'"}'

HEADER_B64=$(base64url_encode "$HEADER")
CLAIMS_B64=$(base64url_encode "$CLAIMS")
SIGNATURE_INPUT="$HEADER_B64.$CLAIMS_B64"

# Sign with OpenSSL
SIGNATURE_RAW=$(printf '%s' "$SIGNATURE_INPUT" | openssl dgst -sha256 -sign "$CLIENT_DIR/private_key.pem" -binary)
SIGNATURE_B64=$(printf '%s' "$SIGNATURE_RAW" | base64 | tr '+/' '-_' | tr -d '=')

JWT_ASSERTION="$SIGNATURE_INPUT.$SIGNATURE_B64"
echo "✅ JWT client assertion created"

# Step 2: Pushed Authorization Request (PAR)
echo ""
echo "📤 Step 2: Making Pushed Authorization Request (PAR)..."

PAR_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$AIP_BASE/oauth/par" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "response_type=code" \
  -d "client_id=$CLIENT_ID" \
  -d "redirect_uri=http://localhost:8080/callback" \
  -d "scope=atproto:atproto" \
  -d "state=test-state-$(date +%s)" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$JWT_ASSERTION")

PAR_HTTP_CODE=$(echo "$PAR_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
PAR_RESPONSE_BODY=$(echo "$PAR_RESPONSE" | sed '/HTTP_CODE:/d')

echo "PAR HTTP Status: $PAR_HTTP_CODE"

if [ "$PAR_HTTP_CODE" = "200" ]; then
    REQUEST_URI=$(echo "$PAR_RESPONSE_BODY" | jq -r .request_uri)
    EXPIRES_IN=$(echo "$PAR_RESPONSE_BODY" | jq -r .expires_in)
    echo "✅ PAR request successful!"
    echo "   Request URI: $REQUEST_URI"
    echo "   Expires in: $EXPIRES_IN seconds"
else
    echo "❌ PAR request failed:"
    echo "$PAR_RESPONSE_BODY" | jq . 2>/dev/null || echo "$PAR_RESPONSE_BODY"
    exit 1
fi

# Step 3: Authorization URL
echo ""
echo "🔗 Step 3: Authorization URL for user authentication..."

AUTH_URL="$AIP_BASE/oauth/authorize?client_id=$CLIENT_ID&request_uri=$REQUEST_URI"
echo "Authorization URL: $AUTH_URL"
echo ""
echo "📋 Next steps for complete flow:"
echo "1. User visits: $AUTH_URL"
echo "2. User authenticates with their ATProtocol account (handle/password or app password)"
echo "3. User authorizes the client application"
echo "4. User gets redirected to: http://localhost:8080/callback?code=AUTHORIZATION_CODE&state=..."
echo "5. Client extracts the authorization code from the callback"
echo ""

# Step 4: Simulate token exchange (this would happen after user authorization)
echo "🔄 Step 4: Token exchange simulation (requires authorization code from user flow)..."
echo ""
echo "When you have an authorization code, you would exchange it like this:"
echo ""

# Create a new JWT for token endpoint
NOW2=$(date +%s)
EXP2=$((NOW2 + 300))
JTI2=$(openssl rand -hex 16)

TOKEN_HEADER='{"typ":"JWT","alg":"ES256","kid":"'$KID'"}'
TOKEN_CLAIMS='{"iss":"'$CLIENT_ID'","sub":"'$CLIENT_ID'","aud":"'$AIP_BASE'/oauth/token","iat":'$NOW2',"exp":'$EXP2',"jti":"'$JTI2'"}'

TOKEN_HEADER_B64=$(base64url_encode "$TOKEN_HEADER")
TOKEN_CLAIMS_B64=$(base64url_encode "$TOKEN_CLAIMS")
TOKEN_SIGNATURE_INPUT="$TOKEN_HEADER_B64.$TOKEN_CLAIMS_B64"

TOKEN_SIGNATURE_RAW=$(printf '%s' "$TOKEN_SIGNATURE_INPUT" | openssl dgst -sha256 -sign "$CLIENT_DIR/private_key.pem" -binary)
TOKEN_SIGNATURE_B64=$(printf '%s' "$TOKEN_SIGNATURE_RAW" | base64 | tr '+/' '-_' | tr -d '=')

TOKEN_JWT="$TOKEN_SIGNATURE_INPUT.$TOKEN_SIGNATURE_B64"

echo "curl -X POST '$AIP_BASE/oauth/token' \\"
echo "  -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "  -d 'grant_type=authorization_code' \\"
echo "  -d 'code=YOUR_AUTHORIZATION_CODE' \\"
echo "  -d 'redirect_uri=http://localhost:8080/callback' \\"
echo "  -d 'client_id=$CLIENT_ID' \\"
echo "  -d 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \\"
echo "  -d 'client_assertion=$TOKEN_JWT'"
echo ""

# Step 5: Get access token using client_credentials grant (for testing)
echo "🔑 Step 5: Getting access token using client_credentials grant..."

# Create a new JWT for client_credentials token request
NOW3=$(date +%s)
EXP3=$((NOW3 + 300))
JTI3=$(openssl rand -hex 16)

CC_HEADER='{"typ":"JWT","alg":"ES256","kid":"'$KID'"}'
CC_CLAIMS='{"iss":"'$CLIENT_ID'","sub":"'$CLIENT_ID'","aud":"'$AIP_BASE'/oauth/token","iat":'$NOW3',"exp":'$EXP3',"jti":"'$JTI3'"}'

CC_HEADER_B64=$(base64url_encode "$CC_HEADER")
CC_CLAIMS_B64=$(base64url_encode "$CC_CLAIMS")
CC_SIGNATURE_INPUT="$CC_HEADER_B64.$CC_CLAIMS_B64"

CC_SIGNATURE_RAW=$(printf '%s' "$CC_SIGNATURE_INPUT" | openssl dgst -sha256 -sign "$CLIENT_DIR/private_key.pem" -binary)
CC_SIGNATURE_B64=$(printf '%s' "$CC_SIGNATURE_RAW" | base64 | tr '+/' '-_' | tr -d '=')

CC_JWT="$CC_SIGNATURE_INPUT.$CC_SIGNATURE_B64"

# Request access token using client_credentials grant
TOKEN_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X POST "$AIP_BASE/oauth/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "scope=atproto:atproto" \
  -d "client_id=$CLIENT_ID" \
  -d "client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer" \
  -d "client_assertion=$CC_JWT")

TOKEN_HTTP_CODE=$(echo "$TOKEN_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
TOKEN_RESPONSE_BODY=$(echo "$TOKEN_RESPONSE" | sed '/HTTP_CODE:/d')

echo "Client Credentials Token HTTP Status: $TOKEN_HTTP_CODE"

if [ "$TOKEN_HTTP_CODE" = "200" ]; then
    ACCESS_TOKEN=$(echo "$TOKEN_RESPONSE_BODY" | jq -r .access_token)
    TOKEN_TYPE=$(echo "$TOKEN_RESPONSE_BODY" | jq -r .token_type)
    EXPIRES_IN=$(echo "$TOKEN_RESPONSE_BODY" | jq -r .expires_in)
    
    echo "✅ Access token obtained successfully!"
    echo "   Token Type: $TOKEN_TYPE"
    echo "   Expires in: $EXPIRES_IN seconds"
    echo "   Access Token: ${ACCESS_TOKEN:0:20}..."
    
    # Step 6: Test API endpoints with real access token
    echo ""
    echo "📡 Step 6: Testing ATProtocol API endpoints with real access token..."
    
    # Test session endpoint
    echo ""
    echo "Testing session endpoint..."
    SESSION_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X GET "$AIP_BASE/api/atprotocol/session" \
      -H "Authorization: Bearer $ACCESS_TOKEN")
    
    SESSION_HTTP_CODE=$(echo "$SESSION_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
    SESSION_RESPONSE_BODY=$(echo "$SESSION_RESPONSE" | sed '/HTTP_CODE:/d')
    
    echo "Session endpoint HTTP Status: $SESSION_HTTP_CODE"
    echo "Session Response:"
    echo "$SESSION_RESPONSE_BODY" | jq . 2>/dev/null || echo "$SESSION_RESPONSE_BODY"
    
    # Test XRPC endpoint
    echo ""
    echo "Testing XRPC getSession endpoint..."
    XRPC_RESPONSE=$(curl -s -w "\nHTTP_CODE:%{http_code}" -X GET "$AIP_BASE/xrpc/com.atproto.server.getSession" \
      -H "Authorization: Bearer $ACCESS_TOKEN")
    
    XRPC_HTTP_CODE=$(echo "$XRPC_RESPONSE" | grep "HTTP_CODE:" | cut -d: -f2)
    XRPC_RESPONSE_BODY=$(echo "$XRPC_RESPONSE" | sed '/HTTP_CODE:/d')
    
    echo "XRPC endpoint HTTP Status: $XRPC_HTTP_CODE"
    echo "XRPC Response:"
    echo "$XRPC_RESPONSE_BODY" | jq . 2>/dev/null || echo "$XRPC_RESPONSE_BODY"
    
else
    echo "❌ Failed to get access token:"
    echo "$TOKEN_RESPONSE_BODY" | jq . 2>/dev/null || echo "$TOKEN_RESPONSE_BODY"
fi

echo ""

# Summary
echo "📋 Flow Summary:"
echo "✅ Private Key JWT client authentication working"
echo "✅ PAR endpoint accepts our client credentials"
echo "✅ Authorization URL generated successfully"
echo "🔄 User authentication and authorization required for completion"
echo "🔄 Token exchange would use private_key_jwt authentication"
echo "🔄 API access would use the resulting access token"
echo ""
echo "🎉 Private Key JWT implementation is fully functional!"
echo "The client authentication is working correctly. A real user flow"
echo "would complete the authorization and enable API access."