import { useState, useEffect, useCallback } from 'react';
import type {
  OAuthServerMetadata,
  RegisteredClient,
  AtpSessionResponse,
  XRPCResponse,
} from '../types/oauth';
import {
  discoverOAuthMetadata,
  registerOAuthClient,
  makePARRequest,
  exchangeCodeForTokens,
  getAtpSession,
  makeXRPCCall,
} from '../utils/api';
import {
  CONFIG,
  generatePKCEAsync,
  generateState,
  storeOAuthState,
  retrieveOAuthState,
  removeOAuthState,
  storeRegisteredClient,
  retrieveRegisteredClient,
  storeAccessToken,
  retrieveAccessToken,
  removeAccessToken,
  parseURLParams,
  debugListOAuthStates,
} from '../utils/oauth';

export interface OAuthHookState {
  // Client registration
  isRegistering: boolean;
  registrationError: string | null;
  registeredClient: RegisteredClient | null;
  
  // OAuth metadata
  serverMetadata: OAuthServerMetadata | null;
  
  // Authentication flow
  isAuthenticating: boolean;
  authError: string | null;
  accessToken: string | null;
  
  // ATProtocol session
  isLoadingSession: boolean;
  sessionError: string | null;
  atpSession: AtpSessionResponse | null;
  
  // XRPC call
  isLoadingXRPC: boolean;
  xrpcResult: XRPCResponse | null;
}

export function useOAuth() {
  const [state, setState] = useState<OAuthHookState>({
    isRegistering: false,
    registrationError: null,
    registeredClient: null,
    serverMetadata: null,
    isAuthenticating: false,
    authError: null,
    accessToken: null,
    isLoadingSession: false,
    sessionError: null,
    atpSession: null,
    isLoadingXRPC: false,
    xrpcResult: null,
  });

  // Initialize from storage on mount
  useEffect(() => {
    const storedClient = retrieveRegisteredClient();
    const storedToken = retrieveAccessToken();
    
    if (storedClient || storedToken) {
      setState(prev => ({
        ...prev,
        registeredClient: storedClient,
        accessToken: storedToken,
      }));
    }
  }, []);

  // Handle OAuth callback - use ref to avoid stale closure
  const handleCallbackRef = useCallback(async (code: string, receivedState: string) => {
    setState(prev => ({ ...prev, isAuthenticating: true, authError: null }));
    
    try {
      // Retrieve and validate stored OAuth state
      const oauthStateData = retrieveOAuthState(receivedState);
      if (!oauthStateData) {
        // Debug: log all available states
        console.error('OAuth state not found. Available states:', debugListOAuthStates());
        console.error('Looking for state:', receivedState);
        throw new Error('OAuth state not found or expired');
      }
      
      // Clean up stored state
      removeOAuthState(receivedState);
      
      // Get current metadata and client from state
      const currentClient = retrieveRegisteredClient();
      const currentMetadata = await discoverOAuthMetadata();
      
      if (!currentClient || !currentMetadata) {
        throw new Error('Client not registered or metadata not loaded');
      }
      
      // Exchange authorization code for tokens
      const tokenRequest = {
        grant_type: 'authorization_code',
        client_id: currentClient.client_id,
        code,
        redirect_uri: oauthStateData.redirect_uri,
        code_verifier: oauthStateData.code_verifier,
      };
      
      const tokenResponse = await exchangeCodeForTokens(
        currentMetadata.token_endpoint,
        tokenRequest,
        currentClient.client_secret
      );
      
      storeAccessToken(tokenResponse.access_token);
      setState(prev => ({
        ...prev,
        isAuthenticating: false,
        accessToken: tokenResponse.access_token,
      }));
      
      // Clean up URL
      window.history.replaceState({}, document.title, window.location.pathname);
    } catch (error) {
      setState(prev => ({
        ...prev,
        isAuthenticating: false,
        authError: error instanceof Error ? error.message : 'Token exchange failed',
      }));
    }
  }, []);

  // Handle OAuth callback
  useEffect(() => {
    const urlParams = parseURLParams(window.location.search);
    
    if (urlParams.code && urlParams.state) {
      handleCallbackRef(urlParams.code, urlParams.state);
    } else if (urlParams.error) {
      setState(prev => ({
        ...prev,
        authError: `OAuth error: ${urlParams.error} - ${urlParams.error_description || 'Unknown error'}`,
      }));
    }
  }, [handleCallbackRef]);

  // Register OAuth client
  const registerClient = useCallback(async () => {
    setState(prev => ({ ...prev, isRegistering: true, registrationError: null }));
    
    try {
      // Discover OAuth metadata
      const metadata = await discoverOAuthMetadata();
      setState(prev => ({ ...prev, serverMetadata: metadata }));
      
      // Use metadata registration endpoint or fallback
      const registrationEndpoint = metadata.registration_endpoint || 
        `${CONFIG.AIP_BASE_URL}/oauth/clients/register`;
      
      // Prepare client registration request
      const clientData = {
        client_name: 'AIP React Demo Client',
        client_uri: CONFIG.DEMO_BASE_URL,
        redirect_uris: [`${CONFIG.DEMO_BASE_URL}/callback`],
        response_types: ['code'],
        grant_types: ['authorization_code'],
        token_endpoint_auth_method: 'client_secret_post',
        scope: 'atproto:atproto atproto:transition:generic',
        contacts: ['admin@demo-client.example'],
        policy_uri: `${CONFIG.DEMO_BASE_URL}/policy`,
        tos_uri: `${CONFIG.DEMO_BASE_URL}/terms`,
        software_id: 'aip-react-demo-client',
        software_version: '1.0.0',
      };
      
      // Register client
      const registrationResponse = await registerOAuthClient(registrationEndpoint, clientData);
      
      const client: RegisteredClient = {
        client_id: registrationResponse.client_id,
        client_secret: registrationResponse.client_secret,
        registration_access_token: registrationResponse.registration_access_token,
        expires_at: registrationResponse.client_secret_expires_at,
      };
      
      storeRegisteredClient(client);
      setState(prev => ({
        ...prev,
        isRegistering: false,
        registeredClient: client,
      }));
    } catch (error) {
      setState(prev => ({
        ...prev,
        isRegistering: false,
        registrationError: error instanceof Error ? error.message : 'Registration failed',
      }));
    }
  }, []);

  // Start OAuth flow
  const startOAuthFlow = useCallback(async (subject?: string) => {
    if (!state.registeredClient || !state.serverMetadata) {
      setState(prev => ({ ...prev, authError: 'Client not registered or metadata not loaded' }));
      return;
    }
    
    setState(prev => ({ ...prev, isAuthenticating: true, authError: null }));
    
    try {
      // Generate PKCE parameters and state
      const { codeVerifier, codeChallenge } = await generatePKCEAsync();
      const oauthState = generateState();
      const redirectUri = `${CONFIG.DEMO_BASE_URL}/callback`;
      const scope = 'atproto:atproto atproto:transition:generic';
      
      // Store OAuth state for callback verification
      const stateData = {
        state: oauthState,
        code_verifier: codeVerifier,
        code_challenge: codeChallenge,
        redirect_uri: redirectUri,
        scope,
      };
      console.log('Storing OAuth state:', oauthState, stateData);
      storeOAuthState(oauthState, stateData);
      
      // Check if server supports PAR
      if (state.serverMetadata.pushed_authorization_request_endpoint) {
        // Use PAR flow
        const parRequest = {
          client_id: state.registeredClient.client_id,
          response_type: 'code',
          redirect_uri: redirectUri,
          scope,
          state: oauthState,
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
          ...(subject && { login_hint: subject }),
        };
        
        const parResponse = await makePARRequest(
          state.serverMetadata.pushed_authorization_request_endpoint,
          parRequest
        );
        
        // Redirect to authorization endpoint with request_uri
        const authUrl = `${state.serverMetadata.authorization_endpoint}?client_id=${encodeURIComponent(state.registeredClient.client_id)}&request_uri=${encodeURIComponent(parResponse.request_uri)}`;
        window.location.href = authUrl;
      } else {
        // Traditional OAuth flow
        const authParams = new URLSearchParams({
          response_type: 'code',
          client_id: state.registeredClient.client_id,
          redirect_uri: redirectUri,
          scope,
          state: oauthState,
          code_challenge: codeChallenge,
          code_challenge_method: 'S256',
          ...(subject && { login_hint: subject }),
        });
        
        const authUrl = `${state.serverMetadata.authorization_endpoint}?${authParams.toString()}`;
        window.location.href = authUrl;
      }
    } catch (error) {
      setState(prev => ({
        ...prev,
        isAuthenticating: false,
        authError: error instanceof Error ? error.message : 'OAuth flow failed',
      }));
    }
  }, [state.registeredClient, state.serverMetadata]);


  // Get ATProtocol session
  const getSession = useCallback(async () => {
    if (!state.accessToken) {
      setState(prev => ({ ...prev, sessionError: 'No access token available' }));
      return;
    }
    
    setState(prev => ({ ...prev, isLoadingSession: true, sessionError: null }));
   
    console.log("stuff", state);
    
    try {
      const session = await getAtpSession(state.accessToken);
      setState(prev => ({
        ...prev,
        isLoadingSession: false,
        atpSession: session,
      }));
    } catch (error) {
      setState(prev => ({
        ...prev,
        isLoadingSession: false,
        sessionError: error instanceof Error ? error.message : 'Session request failed',
      }));
    }
  }, [state.accessToken]);

  // Make XRPC call via BFF proxy
  const makeXRPC = useCallback(async () => {
    if (!state.accessToken) {
      setState(prev => ({ ...prev, xrpcResult: { success: false, error: 'No JWT access token available' } }));
      return;
    }
    
    setState(prev => ({ ...prev, isLoadingXRPC: true }));
    
    try {
      const result = await makeXRPCCall(state.accessToken);
      setState(prev => ({
        ...prev,
        isLoadingXRPC: false,
        xrpcResult: result,
      }));
    } catch (error) {
      setState(prev => ({
        ...prev,
        isLoadingXRPC: false,
        xrpcResult: {
          success: false,
          error: error instanceof Error ? error.message : 'XRPC call failed',
        },
      }));
    }
  }, [state.accessToken]);

  // Reset everything
  const reset = useCallback(() => {
    removeAccessToken();
    sessionStorage.removeItem('registered_client');
    setState({
      isRegistering: false,
      registrationError: null,
      registeredClient: null,
      serverMetadata: null,
      isAuthenticating: false,
      authError: null,
      accessToken: null,
      isLoadingSession: false,
      sessionError: null,
      atpSession: null,
      isLoadingXRPC: false,
      xrpcResult: null,
    });
  }, []);

  return {
    ...state,
    registerClient,
    startOAuthFlow,
    getSession,
    makeXRPC,
    reset,
  };
}