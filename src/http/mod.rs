//! Axum HTTP server handlers and middleware for OAuth 2.1 and ATProtocol endpoints.

pub mod context;
mod handler_app_password;
mod handler_atprotocol_client_metadata;
mod handler_atprotocol_oauth_authorize;
mod handler_atprotocol_oauth_callback;
mod handler_atprotocol_session;

mod handler_index;
mod handler_oauth;
mod handler_oauth_clients;
mod handler_par;
mod handler_userinfo;
mod handler_well_known;
mod handler_xrpc_clients;
mod middleware_auth;
pub mod server;
mod utils_oauth;

pub use context::{AppEngine, AppState};
pub use server::build_router;
