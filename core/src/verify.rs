use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use crate::crypto::{hash, PublicKey};
use crate::model::{claims_valid, presentation_bytes, Action, Challenge, Claim, Presentation};

/// Registry entries express which claims an issuer may assert.
#[derive(Clone, Debug)]
pub struct Issuer {
    pub public_key: PublicKey,
    pub allowed_claim_kinds: HashSet<String>,
    pub active: bool,
}

pub trait TrustRegistry {
    fn issuer(&self, id: &str) -> Option<&Issuer>;
    fn is_revoked(&self, credential_id: &[u8; 32]) -> bool;
}

#[derive(Default)]
pub struct InMemoryTrustRegistry {
    issuers: HashMap<String, Issuer>,
    revoked: HashSet<[u8; 32]>,
}
impl InMemoryTrustRegistry {
    pub fn add_issuer(
        &mut self,
        id: String,
        key: PublicKey,
        allowed_claim_kinds: impl IntoIterator<Item = String>,
    ) {
        self.issuers.insert(
            id,
            Issuer {
                public_key: key,
                allowed_claim_kinds: allowed_claim_kinds.into_iter().collect(),
                active: true,
            },
        );
    }
    pub fn deactivate_issuer(&mut self, id: &str) {
        if let Some(issuer) = self.issuers.get_mut(id) {
            issuer.active = false;
        }
    }
    pub fn revoke(&mut self, id: [u8; 32]) {
        self.revoked.insert(id);
    }
}
impl TrustRegistry for InMemoryTrustRegistry {
    fn issuer(&self, id: &str) -> Option<&Issuer> {
        self.issuers.get(id)
    }
    fn is_revoked(&self, id: &[u8; 32]) -> bool {
        self.revoked.contains(id)
    }
}

/// Must atomically consume an issued challenge once, after all checks pass.
pub trait ReplayStore {
    fn consume(&self, challenge_key: [u8; 32], now: u64) -> bool;
}

#[derive(Default)]
pub struct InMemoryReplayStore(Mutex<HashMap<[u8; 32], (u64, bool)>>);
impl InMemoryReplayStore {
    /// The relying party registers its own challenge before sending it to a wallet.
    pub fn register(&self, challenge: &Challenge) -> bool {
        use std::collections::hash_map::Entry;
        let mut entries = self.0.lock().expect("replay store mutex poisoned");
        match entries.entry(hash(&challenge.signing_bytes())) {
            Entry::Vacant(slot) => {
                slot.insert((challenge.expires_at, false));
                true
            }
            Entry::Occupied(_) => false,
        }
    }
}
impl ReplayStore for InMemoryReplayStore {
    fn consume(&self, key: [u8; 32], now: u64) -> bool {
        let mut entries = self.0.lock().expect("replay store mutex poisoned");
        match entries.get_mut(&key) {
            Some((expires_at, consumed)) if now < *expires_at && !*consumed => {
                *consumed = true;
                true
            }
            _ => false,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Policy {
    /// Each approving holder must carry every required claim.
    pub required_claims: Vec<Claim>,
    pub min_distinct_approvers: usize,
}
impl Policy {
    pub fn validate(&self) -> bool {
        self.min_distinct_approvers > 0 && self.min_distinct_approvers <= 16
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    InvalidPolicy,
    InvalidAction,
    InvalidChallenge,
    AudienceMismatch,
    ActionMismatch,
    ChallengeExpired,
    InsufficientApprovals,
    DuplicateApprover,
    InvalidCredential,
    UntrustedIssuer,
    UnauthorizedClaim,
    CredentialExpired,
    RevokedCredential,
    InvalidPresentation,
    Replay,
}

#[derive(Clone, Debug)]
pub struct Verification {
    pub action_digest: [u8; 32],
    pub approver_fingerprints: Vec<[u8; 32]>,
}

pub struct Verifier<'a, R: TrustRegistry, S: ReplayStore> {
    pub registry: &'a R,
    pub replay_store: &'a S,
    pub audience: &'a str,
}

impl<R: TrustRegistry, S: ReplayStore> Verifier<'_, R, S> {
    pub fn verify(
        &self,
        action: &Action,
        challenge: &Challenge,
        presentations: &[Presentation],
        policy: &Policy,
        now: u64,
    ) -> Result<Verification, VerifyError> {
        if !policy.validate() {
            return Err(VerifyError::InvalidPolicy);
        }
        if !action.is_valid() {
            return Err(VerifyError::InvalidAction);
        }
        if challenge.audience.is_empty()
            || challenge.audience.len() > 256
            || challenge.issued_at >= challenge.expires_at
            || challenge.expires_at - challenge.issued_at > 300
            || challenge.nonce == [0; 32]
        {
            return Err(VerifyError::InvalidChallenge);
        }
        if challenge.audience != self.audience {
            return Err(VerifyError::AudienceMismatch);
        }
        if challenge.action_digest != action.digest() {
            return Err(VerifyError::ActionMismatch);
        }
        if now < challenge.issued_at || now >= challenge.expires_at {
            return Err(VerifyError::ChallengeExpired);
        }
        if presentations.len() < policy.min_distinct_approvers {
            return Err(VerifyError::InsufficientApprovals);
        }

        let mut seen_keys = HashSet::new();
        let mut seen_people = HashSet::new();
        let mut approvers = Vec::with_capacity(presentations.len());
        for presentation in presentations {
            let credential = &presentation.credential;
            let body = &credential.body;
            if body.id == [0; 32]
                || body.issuer.is_empty()
                || body.subject_id == [0; 32]
                || body.not_before >= body.expires_at
                || !claims_valid(&body.claims)
            {
                return Err(VerifyError::InvalidCredential);
            }
            if now < body.not_before || now >= body.expires_at {
                return Err(VerifyError::CredentialExpired);
            }
            let issuer = self
                .registry
                .issuer(&body.issuer)
                .filter(|i| i.active)
                .ok_or(VerifyError::UntrustedIssuer)?;
            if body
                .claims
                .iter()
                .any(|c| !issuer.allowed_claim_kinds.contains(&c.kind))
            {
                return Err(VerifyError::UnauthorizedClaim);
            }
            if !issuer
                .public_key
                .verify(&body.signing_bytes(), &credential.signature)
            {
                return Err(VerifyError::InvalidCredential);
            }
            if self.registry.is_revoked(&body.id) {
                return Err(VerifyError::RevokedCredential);
            }
            if !policy
                .required_claims
                .iter()
                .all(|required| body.claims.contains(required))
            {
                return Err(VerifyError::UnauthorizedClaim);
            }
            if !body.subject_key.verify(
                &presentation_bytes(&body.id, challenge),
                &presentation.signature,
            ) {
                return Err(VerifyError::InvalidPresentation);
            }
            let fingerprint = body.subject_key.fingerprint();
            if !seen_keys.insert(fingerprint)
                || !seen_people.insert((body.issuer.clone(), body.subject_id))
            {
                return Err(VerifyError::DuplicateApprover);
            }
            approvers.push(fingerprint);
        }
        if seen_people.len() < policy.min_distinct_approvers {
            return Err(VerifyError::InsufficientApprovals);
        }
        if !self
            .replay_store
            .consume(hash(&challenge.signing_bytes()), now)
        {
            return Err(VerifyError::Replay);
        }
        Ok(Verification {
            action_digest: action.digest(),
            approver_fingerprints: approvers,
        })
    }
}
