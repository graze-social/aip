import type { OAuthState as OAuthFlowState, RegisteredClient } from '../types/oauth';

// Generate PKCE code verifier and challenge (sync version - deprecated, use generatePKCEAsync)
export function generatePKCE(): Promise<{ codeVerifier: string; codeChallenge: string }> {
  // Generate code verifier (43-128 characters, URL-safe)
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  const codeVerifier = base64URLEncode(array);

  // Generate code challenge (SHA256 hash of verifier, base64url encoded)
  return crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier))
    .then(hashBuffer => {
      const codeChallenge = base64URLEncode(new Uint8Array(hashBuffer));
      return { codeVerifier, codeChallenge };
    });
}

// Generate random state parameter
export function generateState(): string {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64URLEncode(array);
}

// Base64URL encode without padding
function base64URLEncode(array: Uint8Array): string {
  return btoa(String.fromCharCode(...array))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

// Configuration
export const CONFIG = {
  AIP_BASE_URL: import.meta.env.VITE_AIP_BASE_URL || 'http://localhost:8080',
  DEMO_BASE_URL: import.meta.env.VITE_DEMO_BASE_URL || 'http://localhost:3001',
};

// Helper to create form data for POST requests
export function createFormData(data: Record<string, string>): URLSearchParams {
  const formData = new URLSearchParams();
  Object.entries(data).forEach(([key, value]) => {
    formData.append(key, value);
  });
  return formData;
}

// Store OAuth state in session storage
export function storeOAuthState(state: string, oauthState: OAuthFlowState): void {
  sessionStorage.setItem(`oauth_state_${state}`, JSON.stringify(oauthState));
}

// Retrieve OAuth state from session storage
export function retrieveOAuthState(state: string): OAuthFlowState | null {
  const stored = sessionStorage.getItem(`oauth_state_${state}`);
  if (!stored) return null;
  
  try {
    return JSON.parse(stored);
  } catch {
    return null;
  }
}

// Remove OAuth state from session storage
export function removeOAuthState(state: string): void {
  sessionStorage.removeItem(`oauth_state_${state}`);
}

// Store registered client in session storage
export function storeRegisteredClient(client: RegisteredClient): void {
  sessionStorage.setItem('registered_client', JSON.stringify(client));
}

// Retrieve registered client from session storage
export function retrieveRegisteredClient(): RegisteredClient | null {
  const stored = sessionStorage.getItem('registered_client');
  if (!stored) return null;
  
  try {
    return JSON.parse(stored);
  } catch {
    return null;
  }
}

// Store access token in session storage
export function storeAccessToken(token: string): void {
  sessionStorage.setItem('access_token', token);
}

// Retrieve access token from session storage
export function retrieveAccessToken(): string | null {
  return sessionStorage.getItem('access_token');
}

// Remove access token from session storage
export function removeAccessToken(): void {
  sessionStorage.removeItem('access_token');
}

// Parse URL query parameters
export function parseURLParams(search: string): Record<string, string> {
  const params = new URLSearchParams(search);
  const result: Record<string, string> = {};
  params.forEach((value, key) => {
    result[key] = value;
  });
  return result;
}

// Generate async PKCE (returns a Promise)
export async function generatePKCEAsync(): Promise<{ codeVerifier: string; codeChallenge: string }> {
  // Generate code verifier (43-128 characters, URL-safe)
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  const codeVerifier = base64URLEncode(array);

  // Generate code challenge (SHA256 hash of verifier, base64url encoded)
  const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(codeVerifier));
  const codeChallenge = base64URLEncode(new Uint8Array(hashBuffer));
  
  return { codeVerifier, codeChallenge };
}

// Debug function to list all OAuth states in sessionStorage
export function debugListOAuthStates(): Record<string, any> {
  const states: Record<string, any> = {};
  for (let i = 0; i < sessionStorage.length; i++) {
    const key = sessionStorage.key(i);
    if (key && key.startsWith('oauth_state_')) {
      try {
        const value = sessionStorage.getItem(key);
        states[key] = value ? JSON.parse(value) : null;
      } catch {
        states[key] = 'Invalid JSON';
      }
    }
  }
  return states;
}