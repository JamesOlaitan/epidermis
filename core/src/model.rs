use crate::crypto::{hash, Encoder, KeyPair, PublicKey, Signature};
use rand_core::{OsRng, RngCore};

/// A single issuer assertion. Claim values are small, independent facts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim {
    pub kind: String,
    pub value: String,
}

#[derive(Clone, Debug)]
pub struct CredentialBody {
    pub id: [u8; 32],
    pub issuer: String,
    /// Opaque, issuer-scoped person reference. The issuer must deduplicate enrollment.
    pub subject_id: [u8; 32],
    pub subject_key: PublicKey,
    pub claims: Vec<Claim>,
    pub not_before: u64,
    pub expires_at: u64,
}

impl CredentialBody {
    pub fn new(
        issuer: String,
        subject_id: [u8; 32],
        subject_key: PublicKey,
        claims: Vec<Claim>,
        not_before: u64,
        expires_at: u64,
    ) -> Result<Self, &'static str> {
        if issuer.is_empty()
            || subject_id == [0; 32]
            || claims.is_empty()
            || not_before >= expires_at
            || !valid_claims(&claims)
        {
            return Err("invalid credential body");
        }
        let mut id = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut id)
            .map_err(|_| "OS randomness unavailable")?;
        Ok(Self {
            id,
            issuer,
            subject_id,
            subject_key,
            claims,
            not_before,
            expires_at,
        })
    }

    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(b"epidermis:credential:v1");
        e.bytes(&self.id);
        e.text(&self.issuer);
        e.bytes(&self.subject_id);
        e.bytes(&self.subject_key.0);
        e.number(self.claims.len() as u64);
        for claim in &self.claims {
            e.text(&claim.kind);
            e.text(&claim.value);
        }
        e.number(self.not_before);
        e.number(self.expires_at);
        e.finish()
    }
}

fn valid_claims(claims: &[Claim]) -> bool {
    claims.iter().all(|c| {
        !c.kind.is_empty() && !c.value.is_empty() && c.kind.len() <= 128 && c.value.len() <= 512
    }) && claims.windows(2).all(|w| w[0].kind < w[1].kind)
}

#[derive(Clone, Debug)]
pub struct Credential {
    pub body: CredentialBody,
    pub signature: Signature,
}
impl Credential {
    pub fn issue(body: CredentialBody, issuer_key: &KeyPair) -> Result<Self, &'static str> {
        let signature = issuer_key.sign(&body.signing_bytes())?;
        Ok(Self { body, signature })
    }
}

/// The fields shown for approval are exactly the fields signed. Order is canonical.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Action {
    pub kind: String,
    pub fields: Vec<(String, String)>,
}
impl Action {
    pub fn new(kind: String, fields: Vec<(String, String)>) -> Result<Self, &'static str> {
        if kind.is_empty()
            || kind.len() > 128
            || fields.is_empty()
            || fields.len() > 32
            || fields
                .iter()
                .any(|(k, v)| k.is_empty() || v.is_empty() || k.len() > 128 || v.len() > 1024)
            || !fields.windows(2).all(|w| w[0].0 < w[1].0)
        {
            return Err("invalid action");
        }
        Ok(Self { kind, fields })
    }
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(b"epidermis:action:v1");
        e.text(&self.kind);
        e.number(self.fields.len() as u64);
        for (k, v) in &self.fields {
            e.text(k);
            e.text(v);
        }
        e.finish()
    }
    pub fn digest(&self) -> [u8; 32] {
        hash(&self.signing_bytes())
    }
    pub fn is_valid(&self) -> bool {
        Self::new(self.kind.clone(), self.fields.clone()).is_ok()
    }
}

#[derive(Clone, Debug)]
pub struct Challenge {
    pub audience: String,
    pub nonce: [u8; 32],
    pub issued_at: u64,
    pub expires_at: u64,
    pub action_digest: [u8; 32],
}
impl Challenge {
    pub fn new(
        audience: String,
        action: &Action,
        issued_at: u64,
        expires_at: u64,
    ) -> Result<Self, &'static str> {
        if audience.is_empty()
            || audience.len() > 256
            || !action.is_valid()
            || issued_at >= expires_at
            || expires_at - issued_at > 300
        {
            return Err("invalid challenge");
        }
        let mut nonce = [0u8; 32];
        OsRng
            .try_fill_bytes(&mut nonce)
            .map_err(|_| "OS randomness unavailable")?;
        Ok(Self {
            audience,
            nonce,
            issued_at,
            expires_at,
            action_digest: action.digest(),
        })
    }
    pub fn signing_bytes(&self) -> Vec<u8> {
        let mut e = Encoder::new(b"epidermis:challenge:v1");
        e.text(&self.audience);
        e.bytes(&self.nonce);
        e.number(self.issued_at);
        e.number(self.expires_at);
        e.bytes(&self.action_digest);
        e.finish()
    }
}

#[derive(Clone, Debug)]
pub struct Presentation {
    pub credential: Credential,
    pub signature: Signature,
}
impl Presentation {
    pub fn sign(
        credential: Credential,
        challenge: &Challenge,
        holder_key: &KeyPair,
    ) -> Result<Self, &'static str> {
        if credential.body.subject_key != holder_key.public_key() {
            return Err("holder key does not match credential");
        }
        let signature = holder_key.sign(&presentation_bytes(&credential.body.id, challenge))?;
        Ok(Self {
            credential,
            signature,
        })
    }
}

pub(crate) fn presentation_bytes(id: &[u8; 32], challenge: &Challenge) -> Vec<u8> {
    let mut e = Encoder::new(b"epidermis:presentation:v1");
    e.bytes(id);
    e.bytes(&challenge.signing_bytes());
    e.finish()
}

pub(crate) fn claims_valid(claims: &[Claim]) -> bool {
    !claims.is_empty() && valid_claims(claims)
}
