import express from 'express';
import cors from 'cors';
import { join } from 'path';
import fetch from 'node-fetch';
import { generateDPoPProof, createMockDPoPKeyPair } from './dpop';
import type { AtpSessionResponse, XRPCProxyRequest, XRPCProxyResponse, ParsedDPoPKey } from './types';

const app = express();
const PORT = process.env.PORT || 3001;
const AIP_BASE_URL = process.env.AIP_BASE_URL || 'https://aipdev.tunn.dev';

// DPoP key pair storage (in production, this should be persisted)
let bffDPoPKeyPair: { publicKey: any; privateKey: ParsedDPoPKey } | null = null;

// Initialize DPoP key pair on startup
async function initializeDPoPKeyPair() {
  try {
    bffDPoPKeyPair = await createMockDPoPKeyPair();
    console.log('✅ DPoP key pair initialized');
    console.log('Public key JWK:', JSON.stringify(bffDPoPKeyPair.publicKey, null, 2));
    console.log('Private key has d component:', !!bffDPoPKeyPair.privateKey.d);
  } catch (error) {
    console.error('❌ Failed to initialize DPoP key pair:', error);
    process.exit(1);
  }
}

// Middleware
app.use(cors());
app.use(express.json());

// Serve static files (built React app)
const staticPath = __dirname.includes('/dist/') 
  ? join(__dirname, '../../dist')  // Production: dist/server/index.js -> ../../dist
  : join(__dirname, '../dist');    // Development: server/index.ts -> ../dist
app.use(express.static(staticPath));

/**
 * XRPC Proxy endpoint - handles DPoP-signed requests to PDS
 */
app.post('/api/xrpc-proxy', async (req, res) => {
  console.log('🔄 XRPC Proxy request received:', {
    method: req.method,
    url: req.url,
    body: req.body,
    headers: req.headers.authorization ? 'Bearer token present' : 'No auth header'
  });
  
  try {
    const { method = 'GET', endpoint, params, data }: XRPCProxyRequest = req.body;
    
    // Extract JWT token from Authorization header
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({
        success: false,
        error: 'Missing or invalid Authorization header'
      } as XRPCProxyResponse);
    }
    
    const jwtToken = authHeader.substring(7);
    
    // Get ATProtocol session from AIP
    console.log('Fetching ATProtocol session from AIP...');
    const sessionResponse = await fetch(`${AIP_BASE_URL}/api/atprotocol/session`, {
      headers: {
        'Authorization': `Bearer ${jwtToken}`,
        'Content-Type': 'application/json',
      },
    });
    
    if (!sessionResponse.ok) {
      const errorText = await sessionResponse.text();
      console.error('Failed to get session from AIP:', sessionResponse.status, errorText);
      return res.status(sessionResponse.status).json({
        success: false,
        error: `Failed to get ATProtocol session: ${sessionResponse.status} ${errorText}`
      } as XRPCProxyResponse);
    }
    
    const session: AtpSessionResponse = await sessionResponse.json() as AtpSessionResponse;
    console.log('Got ATProtocol session:', {
      did: session.did,
      handle: session.handle,
      token_type: session.token_type,
      scopes: session.scopes,
      pds_endpoint: session.pds_endpoint,
      dpop_jwk: session.dpop_jwk, // DPoP JWK from session (includes private key)
      expires_at: session.expires_at
    });
    
    // Use session's DPoP key for signing (from dpop_jwk field)
    if (!session.dpop_jwk || !session.dpop_jwk.d) {
      console.error('Session DPoP key missing or invalid');
      return res.status(500).json({
        success: false,
        error: 'Session DPoP key missing private component'
      } as XRPCProxyResponse);
    }
    
    // Convert session dpop_jwk to ParsedDPoPKey format
    const dpopKey: ParsedDPoPKey = {
      kty: session.dpop_jwk.kty,
      crv: session.dpop_jwk.crv,
      x: session.dpop_jwk.x,
      y: session.dpop_jwk.y,
      d: session.dpop_jwk.d
    };
    
    // Build full XRPC URL
    const baseUrl = session.pds_endpoint.replace(/\/+$/, ''); // Remove trailing slashes
    const xrpcPath = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
    let xrpcUrl = `${baseUrl}/xrpc${xrpcPath}`;
    
    // Add query parameters for GET requests
    // if (method.toUpperCase() === 'GET' && params) {
    //   const searchParams = new URLSearchParams(params);
    //   xrpcUrl += `?${searchParams.toString()}`;
    // }
    
    console.log('Making XRPC request to:', xrpcUrl);
    
    // Generate DPoP proof
    let dpopProof;
    try {
      console.log('Generating DPoP proof with key:', {
        kty: dpopKey.kty,
        crv: dpopKey.crv,
        hasX: !!dpopKey.x,
        hasY: !!dpopKey.y,
        hasD: !!dpopKey.d
      });
      
      dpopProof = await generateDPoPProof(
        method.toUpperCase(),
        xrpcUrl,
        dpopKey,
        session.access_token
      );
      
      console.log('DPoP proof generated successfully');
    } catch (error) {
      console.error('Failed to generate DPoP proof:', error);
      console.error('DPoP key details:', JSON.stringify(dpopKey, null, 2));
      return res.status(500).json({
        success: false,
        error: `Failed to generate DPoP proof: ${error}`
      } as XRPCProxyResponse);
    }

    console.log(dpopProof);
    
    // Prepare headers for PDS request
    const headers: Record<string, string> = {
      'Authorization': `DPoP ${session.access_token}`,
      'DPoP': dpopProof,
      'Content-Type': 'application/json',
    };
    
    // Add atproto-proxy header if specified in params
    if (params?.['atproto-proxy']) {
      headers['atproto-proxy'] = params['atproto-proxy'];
    }
    
    // Make request to PDS with retry logic for DPoP nonce
    let pdsResponse;
    let responseData;
    let retryWithNonce = false;
    let dpopNonce: string | undefined;
    
    // First attempt
    const requestOptions: any = {
      method: method.toUpperCase(),
      headers,
    };
    
    // Add body for POST requests
    if (method.toUpperCase() === 'POST' && data) {
      requestOptions.body = JSON.stringify(data);
    }
    
    console.log('Making PDS request with headers:', Object.keys(headers));
    
    pdsResponse = await fetch(xrpcUrl, requestOptions);
    
    // Check if we need to retry with DPoP nonce
    if (pdsResponse.status === 401) {
      // Try to get response data
      try {
        responseData = await pdsResponse.json();
      } catch (e) {
        responseData = { error: 'Failed to parse response' };
      }
      console.log(responseData);
      
      // Check if the error is about missing DPoP nonce
      const errorData = responseData as any;
      if (errorData?.error === 'use_dpop_nonce' || 
          errorData?.message?.includes('Authorization server requires nonce in DPoP proof')) {
        // Extract DPoP-Nonce header
        const nonceHeader = pdsResponse.headers.get('dpop-nonce') || pdsResponse.headers.get('DPoP-Nonce');
        dpopNonce = nonceHeader || undefined;
        if (dpopNonce) {
          console.log('Got DPoP nonce from 401 response, retrying with nonce');
          retryWithNonce = true;
        }
      }
    } else {
      // Parse response for non-401 statuses
      try {
        responseData = await pdsResponse.json();
      } catch (e) {
        responseData = { error: 'Failed to parse response' };
      }
    }
    
    // Retry with DPoP nonce if needed
    if (retryWithNonce && dpopNonce) {
      // Generate new DPoP proof with nonce
      let newDpopProof;
      try {
        newDpopProof = await generateDPoPProof(
          method.toUpperCase(),
          xrpcUrl,
          dpopKey,
          session.access_token,
          dpopNonce
        );
      } catch (error) {
        console.error('Failed to generate DPoP proof with nonce:', error);
        return res.status(500).json({
          success: false,
          error: `Failed to generate DPoP proof with nonce: ${error}`
        } as XRPCProxyResponse);
      }
      console.log(newDpopProof);
      
      // Update headers with new DPoP proof
      headers['DPoP'] = newDpopProof;
      
      // Make second request with nonce
      console.log('Retrying PDS request with DPoP nonce');
      pdsResponse = await fetch(xrpcUrl, requestOptions);
      try {
        responseData = await pdsResponse.json();
      } catch (e) {
        responseData = { error: 'Failed to parse response' };
      }
    }
    
    console.log('PDS response status:', pdsResponse.status, responseData);
    
    if (!pdsResponse.ok) {
      return res.status(pdsResponse.status).json({
        success: false,
        error: `XRPC call failed: ${pdsResponse.status} ${pdsResponse.statusText}`,
        data: responseData,
        status: pdsResponse.status
      } as XRPCProxyResponse);
    }
    
    // Return successful response
    res.json({
      success: true,
      data: responseData,
      status: pdsResponse.status
    } as XRPCProxyResponse);
    
  } catch (error) {
    console.error('XRPC proxy error:', error);
    res.status(500).json({
      success: false,
      error: `Internal server error: ${error}`
    } as XRPCProxyResponse);
  }
});

/**
 * Health check endpoint
 */
app.get('/api/health', (_req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

/**
 * Serve React app for all other routes
 */
app.get('*', (_req, res) => {
  const indexPath = __dirname.includes('/dist/') 
    ? join(__dirname, '../../dist/index.html')  // Production
    : join(__dirname, '../dist/index.html');    // Development
  res.sendFile(indexPath);
});

// Start server
app.listen(PORT, async () => {
  // Initialize DPoP key pair
  await initializeDPoPKeyPair();
  
  console.log(`🚀 BFF Server running on http://localhost:${PORT}`);
  console.log(`📡 AIP Server: ${AIP_BASE_URL}`);
  console.log(`🔧 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📁 Static files served from: ${staticPath}`);
  console.log(`\n🌐 Open your browser to http://localhost:${PORT}`);
  console.log(`📚 API endpoints available:`);
  console.log(`   POST /api/xrpc-proxy - DPoP-signed XRPC proxy`);
  console.log(`   GET /api/health - Health check`);
});

export default app;