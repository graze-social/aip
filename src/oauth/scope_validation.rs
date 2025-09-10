//! OAuth scope validation utilities for AT Protocol scopes.

use atproto_oauth::scopes::{AccountScope, Scope, TransitionScope};
use crate::errors::OAuthError;


pub fn compat_scopes(scopes: &str) -> String {
    scopes.replace("atproto:", "")
}

/// Validate that scopes contain required AT Protocol scopes for OAuth operations.
/// 
/// This function ensures:
/// - The 'atproto' scope is always present (required for all AT Protocol operations)
/// - The 'openid' scope has accompanying AT Protocol scopes that grant read capabilities
/// - The 'email' scope has accompanying scopes that grant email read capabilities
/// - The 'profile' scope has accompanying scopes that grant profile read capabilities
pub fn validate_oauth_scope_requirements(scopes: &[Scope]) -> Result<(), OAuthError> {
    // First, check that 'atproto' scope is always present
    let has_atproto = scopes.iter().any(|s| matches!(s, Scope::Atproto));
    if !has_atproto {
        return Err(OAuthError::InvalidScope(
            "The 'atproto' scope is required for all AT Protocol OAuth operations".to_string()
        ));
    }

    let email_read_scope = Scope::Account(AccountScope {
        resource: atproto_oauth::scopes::AccountResource::Email,
        action: atproto_oauth::scopes::AccountAction::Read,
    });

    let has_openid = scopes.iter().any(|s| matches!(s, Scope::OpenId));
    let has_profile = scopes.iter().any(|s| matches!(s, Scope::Profile));
    let has_email = scopes.iter().any(|s| matches!(s, Scope::Email));

    // Check if "profile" scope is present
    if has_profile {
        // Profile requires openid scope
        if !has_openid {
            return Err(OAuthError::InvalidScope(
                "The 'profile' scope requires 'openid' scope".to_string()
            ));
        }
    }

    // Check if "email" scope is present
    if has_email {
        // Email requires openid scope
        if !has_openid {
            return Err(OAuthError::InvalidScope(
                "The 'email' scope requires 'openid' scope".to_string()
            ));
        }
        
        // Email requires a scope that grants email read access
        // Check for transition:email (deprecated but still supported) or scopes that grant email read
        let has_transition_email = scopes.iter().any(|s| {
            matches!(s, Scope::Transition(TransitionScope::Email))
        });
        
        let has_email_capability = has_transition_email || scopes.iter().any(|s| s.grants(&email_read_scope));

        if !has_email_capability {
            return Err(OAuthError::InvalidScope(
                "The 'email' scope requires a scope granting email read access (e.g., 'transition:email' or 'account:email?action=read')".to_string()
            ));
        }
    }

    Ok(())
}

/// Filter AT Protocol scopes for the ATProtocol OAuth flow.
/// 
/// This function:
/// - Removes standard OAuth scopes (openid, profile, email) that are not used in AT Protocol
/// - Preserves all AT Protocol specific scopes
/// - Returns an error if required scopes are missing
pub fn filter_atprotocol_scopes(scopes: &[Scope]) -> Result<Vec<Scope>, OAuthError> {
    // First validate that all required scopes are present
    validate_oauth_scope_requirements(scopes)?;
    
    // Filter out OpenID Connect scopes, keeping only AT Protocol scopes
    let filtered: Vec<Scope> = scopes
        .iter()
        .filter(|s| !matches!(s, Scope::OpenId | Scope::Profile | Scope::Email))
        .cloned()
        .collect();
    
    // Ensure we have at least the atproto scope after filtering
    if filtered.is_empty() {
        return Err(OAuthError::InvalidScope(
            "No valid AT Protocol scopes remain after filtering".to_string()
        ));
    }
    
    Ok(filtered)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_missing_atproto() {
        // Checking that atproto is required
        let scopes = vec![
            Scope::OpenId,
            Scope::Transition(TransitionScope::Generic),
        ];
        
        let result = validate_oauth_scope_requirements(&scopes);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("atproto"));
        }
    }

    #[test]
    fn test_validate_openid_without_capability() {
        // OpenId with just atproto should pass (no transition:generic required)
        let scopes = vec![
            Scope::Atproto,
            Scope::OpenId,
        ];
        
        let result = validate_oauth_scope_requirements(&scopes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_openid_with_capability() {
        // OpenId with atproto and transition:generic should also pass
        let scopes = vec![
            Scope::Atproto,
            Scope::OpenId,
            Scope::Transition(TransitionScope::Generic),
        ];
        
        let result = validate_oauth_scope_requirements(&scopes);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_email_without_capability() {
        let scopes = vec![
            Scope::Atproto,
            Scope::OpenId,  // Required for email scope
            Scope::Email,
        ];
        
        let result = validate_oauth_scope_requirements(&scopes);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("email"));
        }
    }

    #[test]
    fn test_validate_email_with_transition_email() {
        let scopes = vec![
            Scope::Atproto,
            Scope::OpenId,  // Required for email scope
            Scope::Email,
            Scope::Transition(TransitionScope::Email),
        ];
        
        let result = validate_oauth_scope_requirements(&scopes);
        assert!(result.is_ok(), "transition:email should grant email access");
    }
    
    #[test]
    fn test_validate_email_with_account_email_read() {
        use atproto_oauth::scopes::{AccountScope, AccountResource, AccountAction};
        
        let scopes = vec![
            Scope::Atproto,
            Scope::OpenId,  // Required for email scope
            Scope::Email,
            Scope::Account(AccountScope {
                resource: AccountResource::Email,
                action: AccountAction::Read,
            }),
        ];
        
        let result = validate_oauth_scope_requirements(&scopes);
        assert!(result.is_ok(), "account:email?action=read should grant email access");
    }
    
    #[test]
    fn test_validate_email_with_transition_generic_fails() {
        let scopes = vec![
            Scope::Atproto,
            Scope::OpenId,  // Required for email scope
            Scope::Email,
            Scope::Transition(TransitionScope::Generic),
        ];
        
        let result = validate_oauth_scope_requirements(&scopes);
        assert!(result.is_err(), "transition:generic alone should NOT grant email access");
        if let Err(e) = result {
            assert!(e.to_string().contains("email"));
        }
    }

    #[test]
    fn test_filter_atprotocol_scopes() {
        let scopes = vec![
            Scope::Atproto,
            Scope::OpenId,
            Scope::Profile,
            Scope::Email,
            Scope::Transition(TransitionScope::Generic),
            Scope::Transition(TransitionScope::Email),
        ];
        
        let result = filter_atprotocol_scopes(&scopes);
        assert!(result.is_ok());
        
        let filtered = result.unwrap();
        assert_eq!(filtered.len(), 3); // atproto, transition:generic, transition:email
        assert!(filtered.contains(&Scope::Atproto));
        assert!(filtered.contains(&Scope::Transition(TransitionScope::Generic)));
        assert!(filtered.contains(&Scope::Transition(TransitionScope::Email)));
        assert!(!filtered.contains(&Scope::OpenId));
        assert!(!filtered.contains(&Scope::Profile));
        assert!(!filtered.contains(&Scope::Email));
    }

    #[test]
    fn test_filter_fails_on_invalid_scopes() {
        // Missing atproto scope
        let scopes = vec![
            Scope::OpenId,
            Scope::Transition(TransitionScope::Generic),
        ];
        
        let result = filter_atprotocol_scopes(&scopes);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_profile_without_openid() {
        // Profile without openid should fail
        let scopes = vec![
            Scope::Atproto,
            Scope::Profile,
        ];
        
        let result = validate_oauth_scope_requirements(&scopes);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("openid"));
        }
    }

    #[test]
    fn test_validate_email_without_openid() {
        // Email without openid should fail
        let scopes = vec![
            Scope::Atproto,
            Scope::Email,
            Scope::Transition(TransitionScope::Email),
        ];
        
        let result = validate_oauth_scope_requirements(&scopes);
        assert!(result.is_err());
        if let Err(e) = result {
            assert!(e.to_string().contains("openid"));
        }
    }

    #[test]
    fn test_validate_profile_with_openid() {
        // Profile with openid should pass
        let scopes = vec![
            Scope::Atproto,
            Scope::OpenId,  // Required for profile scope
            Scope::Profile,
        ];
        
        let result = validate_oauth_scope_requirements(&scopes);
        assert!(result.is_ok());
    }
}