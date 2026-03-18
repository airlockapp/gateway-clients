//! Airlock Gateway Client SDK for Rust.
//!
//! Provides a typed HTTP client for the Airlock Gateway API, covering
//! all enforcer-side endpoints: artifact submission, exchange polling,
//! pairing management, presence tracking, and gateway discovery.

pub mod auth_client;
pub mod canonical_json;
pub mod client;
pub mod crypto;
pub mod errors;
pub mod models;
pub mod nonce_journal;

pub use auth_client::{AirlockAuthClient, AirlockAuthOptions};
pub use client::AirlockGatewayClient;
pub use crypto::EncryptedPayload;
pub use errors::GatewayError;
pub use models::*;
