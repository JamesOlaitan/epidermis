//! SLH-DSA-SHA2-128s signatures with protocol-level domain separation.
use fips205::slh_dsa_sha2_128s as slh;
use fips205::traits::{SerDes, Signer, Verifier};
use sha2::{Digest, Sha256};

pub const ALGORITHM: &str = "SLH-DSA-SHA2-128s";
pub const PUBLIC_KEY_LEN: usize = slh::PK_LEN;
pub const SIGNATURE_LEN: usize = slh::SIG_LEN;
const CONTEXT: &[u8] = b"epidermis-v1";

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PublicKey(pub Vec<u8>);

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature(pub Vec<u8>);

pub struct KeyPair {
    public: PublicKey,
    secret: slh::PrivateKey,
}

impl KeyPair {
    pub fn generate() -> Result<Self, &'static str> {
        let (public, secret) = slh::try_keygen()?;
        Ok(Self {
            public: PublicKey(public.into_bytes().to_vec()),
            secret,
        })
    }

    pub fn public_key(&self) -> PublicKey {
        self.public.clone()
    }

    pub fn sign(&self, message: &[u8]) -> Result<Signature, &'static str> {
        self.secret
            .try_sign(message, CONTEXT, true)
            .map(|bytes| Signature(bytes.to_vec()))
    }
}

impl PublicKey {
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        let Ok(key_bytes) = <&[u8; PUBLIC_KEY_LEN]>::try_from(self.0.as_slice()) else {
            return false;
        };
        let Ok(sig_bytes) = <&[u8; SIGNATURE_LEN]>::try_from(signature.0.as_slice()) else {
            return false;
        };
        let Ok(key) = slh::PublicKey::try_from_bytes(key_bytes) else {
            return false;
        };
        key.verify(message, sig_bytes, CONTEXT)
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        Sha256::digest(&self.0).into()
    }
}

pub(crate) fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

// Fixed field order and length-prefixing make signed bytes unambiguous across implementations.
pub(crate) struct Encoder(Vec<u8>);
impl Encoder {
    pub fn new(domain: &[u8]) -> Self {
        let mut s = Self(Vec::new());
        s.bytes(domain);
        s
    }
    pub fn bytes(&mut self, value: &[u8]) {
        self.0
            .extend_from_slice(&(value.len() as u64).to_be_bytes());
        self.0.extend_from_slice(value);
    }
    pub fn text(&mut self, value: &str) {
        self.bytes(value.as_bytes());
    }
    pub fn number(&mut self, value: u64) {
        self.0.extend_from_slice(&value.to_be_bytes());
    }
    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}
