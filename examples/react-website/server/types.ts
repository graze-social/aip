// Server-side types for BFF

export interface AtpSessionResponse {
  did: string;
  handle: string;
  access_token: string;
  token_type: string;
  scopes: string[];
  pds_endpoint: string;
  dpop_key: string;
  dpop_jwk: {
    kid: string;
    alg: string;
    use: string;
    kty: string;
    crv: string;
    x: string;
    y: string;
    d: string;
  };
  expires_at: number;
}

export interface XRPCProxyRequest {
  method: string;
  endpoint: string;
  params?: Record<string, any>;
  data?: any;
}

export interface XRPCProxyResponse {
  success: boolean;
  data?: any;
  error?: string;
  status?: number;
}

export interface DPoPProof {
  header: {
    typ: string;
    alg: string;
    jwk: any;
  };
  payload: {
    jti: string;
    htm: string;
    htu: string;
    iat: number;
    exp?: number;
  };
}

export interface ParsedDPoPKey {
  kty: string;
  crv: string;
  x: string;
  y: string;
  d?: string;
}