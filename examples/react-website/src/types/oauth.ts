// OAuth 2.0 and ATProtocol OAuth types

export interface OAuthServerMetadata {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  pushed_authorization_request_endpoint?: string;
  registration_endpoint?: string;
  response_types_supported: string[];
  grant_types_supported?: string[];
  code_challenge_methods_supported?: string[];
  scopes_supported?: string[];
}

export interface OAuthResourceMetadata {
  resource: string;
  authorization_servers: string[];
}

export interface ClientRegistrationRequest {
  client_name: string;
  client_uri?: string;
  redirect_uris: string[];
  response_types: string[];
  grant_types: string[];
  token_endpoint_auth_method: string;
  scope: string;
  contacts?: string[];
  logo_uri?: string;
  policy_uri?: string;
  tos_uri?: string;
  software_id?: string;
  software_version?: string;
}

export interface ClientRegistrationResponse {
  client_id: string;
  client_secret?: string;
  client_id_issued_at?: number;
  client_secret_expires_at?: number;
  registration_access_token?: string;
  registration_client_uri?: string;
  client_name?: string;
  client_uri?: string;
  redirect_uris: string[];
  response_types: string[];
  grant_types: string[];
  token_endpoint_auth_method: string;
  scope?: string;
}

export interface RegisteredClient {
  client_id: string;
  client_secret?: string;
  registration_access_token?: string;
  expires_at?: number;
}

export interface OAuthState {
  state: string;
  code_verifier: string;
  code_challenge: string;
  redirect_uri: string;
  scope: string;
}

export interface PARRequest {
  client_id: string;
  response_type: string;
  redirect_uri: string;
  scope: string;
  state: string;
  code_challenge: string;
  code_challenge_method: string;
  login_hint?: string;
}

export interface PARResponse {
  request_uri: string;
  expires_in: number;
}

export interface TokenRequest {
  grant_type: string;
  client_id: string;
  code: string;
  redirect_uri: string;
  code_verifier: string;
}

export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in?: number;
  refresh_token?: string;
  scope?: string;
}

export interface AtpSessionResponse {
  did: string;
  handle: string;
  access_token: string;
  token_type: string;
  scopes: string[];
  pds_endpoint: string;
  dpop_key: string;
  expires_at: number;
}

export interface XRPCResponse {
  success: boolean;
  data?: any;
  error?: string;
}