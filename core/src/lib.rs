//! Epidermis protocol core.

pub mod crypto;
pub mod model;
pub mod verify;

pub use crypto::{KeyPair, PublicKey, Signature};
pub use model::{Action, Challenge, Claim, Credential, CredentialBody, Presentation};
pub use verify::{
    InMemoryReplayStore, InMemoryTrustRegistry, Policy, Verification, Verifier, VerifyError,
};
