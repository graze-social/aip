import React, { useState, useEffect } from 'react';
import { useOAuth } from '../hooks/useOAuth';
import { CONFIG } from '../utils/oauth';

const OAuthDemo: React.FC = () => {
  const [subject, setSubject] = useState('');
  const oauth = useOAuth();

  // Auto-register client on mount
  useEffect(() => {
    if (!oauth.registeredClient && !oauth.isRegistering && !oauth.registrationError) {
      oauth.registerClient();
    }
  }, [oauth.registeredClient, oauth.isRegistering, oauth.registrationError, oauth.registerClient]);

  // Auto-load session when we get an access token
  useEffect(() => {
    if (oauth.accessToken && !oauth.atpSession && !oauth.isLoadingSession && !oauth.sessionError) {
      oauth.getSession();
    }
  }, [oauth.accessToken, oauth.atpSession, oauth.isLoadingSession, oauth.sessionError, oauth.getSession]);

  const handleStartOAuth = () => {
    const trimmedSubject = subject.trim();
    oauth.startOAuthFlow(trimmedSubject || undefined);
  };

  const renderClientRegistration = () => (
    <div className="oauth-section">
      <h3>🔧 Client Registration</h3>
      {oauth.isRegistering && (
        <div className="info-box">
          <p className="loading">Registering OAuth client with AIP server...</p>
        </div>
      )}
      
      {oauth.registrationError && (
        <div className="error-box">
          <h4>Registration Error</h4>
          <p>{oauth.registrationError}</p>
          <button className="btn btn-secondary" onClick={oauth.registerClient}>
            Retry Registration
          </button>
        </div>
      )}
      
      {oauth.registeredClient && (
        <div className="success-box">
          <h4>✅ Client Registered Successfully</h4>
          <dl>
            <dt>Client ID:</dt>
            <dd>{oauth.registeredClient.client_id}</dd>
            <dt>Client Secret:</dt>
            <dd>{oauth.registeredClient.client_secret ? '(provided)' : '(not provided)'}</dd>
          </dl>
        </div>
      )}
    </div>
  );

  const renderOAuthFlow = () => (
    <div className="oauth-section">
      <h3>🔐 ATProtocol Authentication</h3>
      <p>Enter your ATProtocol handle or DID to start the OAuth login process:</p>
      
      {oauth.authError && (
        <div className="error-box">
          <h4>Authentication Error</h4>
          <p>{oauth.authError}</p>
        </div>
      )}
      
      {!oauth.accessToken ? (
        <div>
          <div className="form-group">
            <label htmlFor="subject" className="form-label">
              ATProtocol Handle or DID
            </label>
            <input
              type="text"
              id="subject"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              className="form-input"
              placeholder="alice.bsky.social or did:plc:... (optional)"
              disabled={oauth.isAuthenticating || !oauth.registeredClient}
            />
            <div className="form-hint">
              Enter your ATProtocol handle (e.g., alice.bsky.social) or DID (e.g., did:plc:abc123...) 
              or leave empty to be prompted by AIP
            </div>
          </div>
          
          <button
            onClick={handleStartOAuth}
            disabled={oauth.isAuthenticating || !oauth.registeredClient}
            className="btn"
          >
            {oauth.isAuthenticating ? 'Starting OAuth...' : 'Start OAuth Login'}
          </button>
        </div>
      ) : (
        <div className="success-box">
          <h4>✅ Authentication Successful</h4>
          <p>JWT Access Token received and stored.</p>
        </div>
      )}
    </div>
  );

  const renderSession = () => (
    <div className="oauth-section">
      <h3>📊 ATProtocol Session</h3>
      
      {oauth.sessionError && (
        <div className="error-box">
          <h4>Session Error</h4>
          <p>{oauth.sessionError}</p>
          <button className="btn btn-secondary" onClick={oauth.getSession}>
            Retry Session
          </button>
        </div>
      )}
      
      {oauth.isLoadingSession && (
        <div className="info-box">
          <p className="loading">Loading ATProtocol session...</p>
        </div>
      )}
      
      {oauth.atpSession && (
        <div className="success-box">
          <h4>✅ ATProtocol Session Retrieved</h4>
          <dl>
            <dt>DID:</dt>
            <dd>{oauth.atpSession.did}</dd>
            <dt>Handle:</dt>
            <dd>{oauth.atpSession.handle}</dd>
            <dt>PDS Endpoint:</dt>
            <dd>{oauth.atpSession.pds_endpoint}</dd>
            <dt>Token Type:</dt>
            <dd>{oauth.atpSession.token_type}</dd>
            <dt>Scopes:</dt>
            <dd>{oauth.atpSession.scopes.join(', ')}</dd>
            <dt>Expires At:</dt>
            <dd>{new Date(oauth.atpSession.expires_at * 1000).toLocaleString()}</dd>
          </dl>
        </div>
      )}
      
      {oauth.accessToken && (
        <button
          onClick={oauth.getSession}
          disabled={oauth.isLoadingSession}
          className="btn btn-secondary"
        >
          {oauth.isLoadingSession ? 'Loading...' : 'Refresh Session'}
        </button>
      )}
    </div>
  );

  const renderXRPC = () => (
    <div className="oauth-section">
      <h3>🌐 XRPC Call</h3>
      <p>Make an XRPC call to the external service with atproto-proxy header:</p>
      
      {oauth.isLoadingXRPC && (
        <div className="info-box">
          <p className="loading">Making XRPC call...</p>
        </div>
      )}
      
      {oauth.xrpcResult && (
        <div className={oauth.xrpcResult.success ? 'success-box' : 'error-box'}>
          <h4>{oauth.xrpcResult.success ? '✅ XRPC Call Successful' : '❌ XRPC Call Failed'}</h4>
          {oauth.xrpcResult.error && <p><strong>Error:</strong> {oauth.xrpcResult.error}</p>}
          {oauth.xrpcResult.data && (
            <div>
              <p><strong>Response:</strong></p>
              <div className="code-block">
                {JSON.stringify(oauth.xrpcResult.data, null, 2)}
              </div>
            </div>
          )}
        </div>
      )}
      
      <button
        onClick={oauth.makeXRPC}
        disabled={!oauth.accessToken || oauth.isLoadingXRPC}
        className="btn"
      >
        {oauth.isLoadingXRPC ? 'Making Call...' : 'Make XRPC Call'}
      </button>
    </div>
  );

  const renderConfiguration = () => (
    <div className="oauth-section">
      <h3>⚙️ Configuration</h3>
      <dl>
        <dt>AIP Server:</dt>
        <dd>{CONFIG.AIP_BASE_URL}</dd>
        <dt>Demo Client:</dt>
        <dd>{CONFIG.DEMO_BASE_URL}</dd>
      </dl>
    </div>
  );

  const renderControls = () => (
    <div className="oauth-section">
      <h3>🔄 Controls</h3>
      <button onClick={oauth.reset} className="btn btn-secondary">
        Reset Everything
      </button>
    </div>
  );

  return (
    <div>
      <div className="info-box">
        <h3>How it works:</h3>
        <ol>
          <li><strong>Client Registration:</strong> Automatically register with AIP using OAuth 2.0 Dynamic Client Registration</li>
          <li><strong>OAuth Flow:</strong> Enter your ATProtocol handle/DID and start OAuth 2.1 + PAR authentication</li>
          <li><strong>Token Exchange:</strong> Exchange authorization code for JWT access token</li>
          <li><strong>Session Retrieval:</strong> Use JWT to get ATProtocol session information</li>
          <li><strong>XRPC Call:</strong> Make authenticated call to external service with atproto-proxy header</li>
        </ol>
      </div>

      {renderClientRegistration()}
      {renderOAuthFlow()}
      {renderSession()}
      {renderXRPC()}
      {renderConfiguration()}
      {renderControls()}
    </div>
  );
};

export default OAuthDemo;