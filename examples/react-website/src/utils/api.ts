import type {
  OAuthServerMetadata,
  OAuthResourceMetadata,
  ClientRegistrationRequest,
  ClientRegistrationResponse,
  PARRequest,
  PARResponse,
  TokenRequest,
  TokenResponse,
  AtpSessionResponse,
  XRPCResponse,
} from '../types/oauth';
import { CONFIG, createFormData } from './oauth';

// Discover OAuth server metadata
export async function discoverOAuthMetadata(): Promise<OAuthServerMetadata> {
  const response = await fetch(`${CONFIG.AIP_BASE_URL}/.well-known/oauth-authorization-server`);
  if (!response.ok) {
    throw new Error(`Failed to fetch OAuth metadata: ${response.status} ${response.statusText}`);
  }
  return response.json();
}

// Discover OAuth protected resource metadata
export async function discoverResourceMetadata(): Promise<OAuthResourceMetadata> {
  const response = await fetch(`${CONFIG.AIP_BASE_URL}/.well-known/oauth-protected-resource`);
  if (!response.ok) {
    throw new Error(`Failed to fetch resource metadata: ${response.status} ${response.statusText}`);
  }
  return response.json();
}

// Register OAuth client dynamically
export async function registerOAuthClient(
  registrationEndpoint: string,
  clientData: ClientRegistrationRequest
): Promise<ClientRegistrationResponse> {
  const response = await fetch(registrationEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(clientData),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Client registration failed: ${response.status} ${response.statusText} - ${errorText}`);
  }

  return response.json();
}

// Make PAR request
export async function makePARRequest(
  parEndpoint: string,
  parData: PARRequest
): Promise<PARResponse> {
  const response = await fetch(parEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: createFormData(parData as unknown as Record<string, string>),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`PAR request failed: ${response.status} ${response.statusText} - ${errorText}`);
  }

  return response.json();
}

// Exchange authorization code for tokens
export async function exchangeCodeForTokens(
  tokenEndpoint: string,
  tokenData: TokenRequest,
  clientSecret?: string
): Promise<TokenResponse> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/x-www-form-urlencoded',
  };

  // Add client authentication if we have a client secret
  if (clientSecret) {
    const credentials = btoa(`${tokenData.client_id}:${clientSecret}`);
    headers['Authorization'] = `Basic ${credentials}`;
  }

  const response = await fetch(tokenEndpoint, {
    method: 'POST',
    headers,
    body: createFormData(tokenData as unknown as Record<string, string>),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Token exchange failed: ${response.status} ${response.statusText} - ${errorText}`);
  }

  return response.json();
}

// Get ATProtocol session information
export async function getAtpSession(accessToken: string): Promise<AtpSessionResponse> {
  const response = await fetch(`${CONFIG.AIP_BASE_URL}/api/atprotocol/session`, {
    headers: {
      'Authorization': `Bearer ${accessToken}`,
    },
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Session request failed: ${response.status} ${response.statusText} - ${errorText}`);
  }

  return response.json();
}

// Make XRPC call via BFF proxy with DPoP signing
export async function makeXRPCCall(
  jwtAccessToken: string // Now we pass the JWT token instead of PDS details
): Promise<XRPCResponse> {
  console.log("jwt access token", jwtAccessToken);
  try {
    const response = await fetch('/api/xrpc-proxy', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${jwtAccessToken}`,
      },
      body: JSON.stringify({
        method: 'GET',
        endpoint: '/garden.lexicon.ngerakines.helloworld.Hello',
        params: {
          'atproto-proxy': 'did:web:ngerakines.tunn.dev#helloworld',
        },
      }),
    });

    const result = await response.json();

    if (!response.ok) {
      return {
        success: false,
        error: `BFF proxy failed: ${response.status} ${response.statusText}`,
        data: result,
      };
    }

    return result;
  } catch (error) {
    return {
      success: false,
      error: `XRPC call error: ${error instanceof Error ? error.message : 'Unknown error'}`,
    };
  }
}