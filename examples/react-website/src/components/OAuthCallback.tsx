import React, { useEffect } from 'react';

interface OAuthCallbackProps {
  onCallback: (code: string, state: string) => void;
  onError: (error: string, description?: string) => void;
}

const OAuthCallback: React.FC<OAuthCallbackProps> = ({ onCallback, onError }) => {
  useEffect(() => {
    const urlParams = new URLSearchParams(window.location.search);
    const code = urlParams.get('code');
    const state = urlParams.get('state');
    const error = urlParams.get('error');
    const errorDescription = urlParams.get('error_description');

    if (error) {
      onError(error, errorDescription || undefined);
    } else if (code && state) {
      onCallback(code, state);
    }
  }, [onCallback, onError]);

  return (
    <div className="oauth-section">
      <h3>🔄 Processing OAuth Callback</h3>
      <div className="info-box">
        <p className="loading">Processing authentication response...</p>
      </div>
    </div>
  );
};

export default OAuthCallback;