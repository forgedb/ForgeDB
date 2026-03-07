//! PASETO v4.public authentication for ForgeDB.
//!
//! This crate is the identity layer — it generates Ed25519 keypairs, signs
//! tokens, and verifies them. No JWTs, no algorithm confusion, no `alg: none`
//! nonsense. We use PASETO v4.public (asymmetric) so cluster followers and
//! client SDKs can verify tokens with just the public key, keeping the secret
//! key's blast radius as small as possible.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────┐     ┌──────────┐     ┌──────────────┐
//! │  keys.rs │────▶│ token.rs │────▶│ middleware.rs │
//! │ (keygen) │     │ (sign/   │     │ (Bearer hdr  │
//! │          │     │  verify) │     │  extraction)  │
//! └──────────┘     └──────────┘     └──────────────┘
//! ```
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use forge_auth::{keys, issue_token, validate_token, TokenClaims};
//!
//! // Generate and save keys during `forgedb init`:
//! let kp = keys::generate_keypair().unwrap();
//! // keys::save_keys(data_dir, &kp.secret, &kp.public).unwrap();
//!
//! // Issue a token:
//! let claims = TokenClaims::new("user-42", 3600, Some("admin".into()));
//! let token = issue_token(&claims, &kp.secret).unwrap();
//!
//! // Verify it later (on any node that has the public key):
//! let verified = validate_token(&token, &kp.public).unwrap();
//! assert_eq!(verified.sub, "user-42");
//! ```

pub mod keys;
pub mod middleware;
pub mod token;

pub use middleware::validate_bearer_token;
pub use token::{TokenClaims, issue_token, validate_token};
