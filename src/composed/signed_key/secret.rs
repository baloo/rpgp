use std::collections::BTreeMap;
use std::io;

use chrono::{DateTime, Utc};
use rand::{CryptoRng, Rng};

use crate::composed::key::{PublicKey, PublicSubkey};
use crate::composed::signed_key::{SignedKeyDetails, SignedPublicSubKey};
use crate::crypto::hash::HashAlgorithm;
use crate::crypto::public_key::PublicKeyAlgorithm;
use crate::errors::Result;
use crate::packet::{self, write_packet, SignatureType};
use crate::ser::Serialize;
use crate::types::{KeyId, KeyTrait, Mpi, PublicKeyTrait, SecretKeyRepr, SecretKeyTrait};
use crate::{armor, SignedPublicKey};

/// Represents a secret signed PGP key.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignedSecretKey {
    pub primary_key: packet::SecretKey,
    pub details: SignedKeyDetails,
    pub public_subkeys: Vec<SignedPublicSubKey>,
    pub secret_subkeys: Vec<SignedSecretSubKey>,
}

key_parser!(
    SignedSecretKey,
    SignedSecretKeyParser,
    Tag::SecretKey,
    packet::SecretKey,
    // secret keys, can contain both public and secret subkeys
    (
        PublicSubkey,
        packet::PublicSubkey,
        SignedPublicSubKey,
        public_subkeys
    ),
    (
        SecretSubkey,
        packet::SecretSubkey,
        SignedSecretSubKey,
        secret_subkeys
    )
);

impl SignedSecretKey {
    pub fn new(
        primary_key: packet::SecretKey,
        details: SignedKeyDetails,
        mut public_subkeys: Vec<SignedPublicSubKey>,
        mut secret_subkeys: Vec<SignedSecretSubKey>,
    ) -> Self {
        public_subkeys.retain(|key| {
            if key.signatures.is_empty() {
                warn!("ignoring unsigned {:?}", key.key);
                false
            } else {
                true
            }
        });

        secret_subkeys.retain(|key| {
            if key.signatures.is_empty() {
                warn!("ignoring unsigned {:?}", key.key);
                false
            } else {
                true
            }
        });

        SignedSecretKey {
            primary_key,
            details,
            public_subkeys,
            secret_subkeys,
        }
    }

    /// Get the secret key expiration as a date.
    pub fn expires_at(&self) -> Option<DateTime<Utc>> {
        let expiration = self.details.key_expiration_time()?;
        Some(*self.primary_key.created_at() + expiration)
    }

    fn verify_public_subkeys(&self) -> Result<()> {
        for subkey in &self.public_subkeys {
            subkey.verify(&self.primary_key)?;
        }

        Ok(())
    }

    fn verify_secret_subkeys(&self) -> Result<()> {
        for subkey in &self.secret_subkeys {
            subkey.verify(&self.primary_key)?;
        }

        Ok(())
    }

    pub fn verify(&self) -> Result<()> {
        self.details.verify(&self.primary_key)?;
        self.verify_public_subkeys()?;
        self.verify_secret_subkeys()?;

        Ok(())
    }

    pub fn to_armored_writer(
        &self,
        writer: &mut impl io::Write,
        headers: Option<&BTreeMap<String, String>>,
    ) -> Result<()> {
        armor::write(self, armor::BlockType::PrivateKey, writer, headers)
    }

    pub fn to_armored_bytes(&self, headers: Option<&BTreeMap<String, String>>) -> Result<Vec<u8>> {
        let mut buf = Vec::new();

        self.to_armored_writer(&mut buf, headers)?;

        Ok(buf)
    }

    pub fn to_armored_string(&self, headers: Option<&BTreeMap<String, String>>) -> Result<String> {
        Ok(::std::str::from_utf8(&self.to_armored_bytes(headers)?)?.to_string())
    }
}

impl KeyTrait for SignedSecretKey {
    /// Returns the fingerprint of the associated primary key.
    fn fingerprint(&self) -> Vec<u8> {
        self.primary_key.fingerprint()
    }

    /// Returns the Key ID of the associated primary key.
    fn key_id(&self) -> KeyId {
        self.primary_key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.primary_key.algorithm()
    }
}

impl Serialize for SignedSecretKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        write_packet(writer, &self.primary_key)?;
        self.details.to_writer(writer)?;
        for ps in &self.public_subkeys {
            ps.to_writer(writer)?;
        }

        for ps in &self.secret_subkeys {
            ps.to_writer(writer)?;
        }

        Ok(())
    }
}

impl SecretKeyTrait for SignedSecretKey {
    type PublicKey = PublicKey;

    fn unlock<F, G>(&self, pw: F, work: G) -> Result<()>
    where
        F: FnOnce() -> String,
        G: FnOnce(&SecretKeyRepr) -> Result<()>,
    {
        self.primary_key.unlock(pw, work)
    }

    fn create_signature<F>(&self, key_pw: F, hash: HashAlgorithm, data: &[u8]) -> Result<Vec<Mpi>>
    where
        F: FnOnce() -> String,
    {
        self.primary_key.create_signature(key_pw, hash, data)
    }

    fn public_key(&self) -> Self::PublicKey {
        let mut subkeys: Vec<PublicSubkey> = self
            .public_subkeys
            .iter()
            .map(SignedPublicSubKey::as_unsigned)
            .collect();
        let sec_subkeys = self.secret_subkeys.iter().map(SecretKeyTrait::public_key);

        subkeys.extend(sec_subkeys);

        PublicKey::new(
            self.primary_key.public_key(),
            self.details.as_unsigned(),
            subkeys,
        )
    }
}

impl PublicKeyTrait for SignedSecretKey {
    fn verify_signature(&self, hash: HashAlgorithm, data: &[u8], sig: &[Mpi]) -> Result<()> {
        self.primary_key.verify_signature(hash, data, sig)
    }

    fn encrypt<R: Rng + CryptoRng>(&self, rng: &mut R, plain: &[u8]) -> Result<Vec<Mpi>> {
        self.primary_key.encrypt(rng, plain)
    }

    fn to_writer_old(&self, writer: &mut impl io::Write) -> Result<()> {
        self.primary_key.to_writer_old(writer)
    }
}

/// Represents a composed secret PGP SubKey.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct SignedSecretSubKey {
    pub key: packet::SecretSubkey,
    pub signatures: Vec<packet::Signature>,
}

impl SignedSecretSubKey {
    pub fn new(key: packet::SecretSubkey, mut signatures: Vec<packet::Signature>) -> Self {
        signatures.retain(|sig| {
            if sig.typ() != SignatureType::SubkeyBinding
                && sig.typ() != SignatureType::SubkeyRevocation
            {
                warn!(
                    "ignoring unexpected signature {:?} after Subkey packet",
                    sig.typ()
                );
                false
            } else {
                true
            }
        });

        SignedSecretSubKey { key, signatures }
    }

    pub fn verify(&self, key: &impl PublicKeyTrait) -> Result<()> {
        ensure!(!self.signatures.is_empty(), "missing subkey bindings");

        for sig in &self.signatures {
            sig.verify_key_binding(key, &self.key)?;
        }

        Ok(())
    }
}

impl KeyTrait for SignedSecretSubKey {
    /// Returns the fingerprint of the key.
    fn fingerprint(&self) -> Vec<u8> {
        self.key.fingerprint()
    }

    /// Returns the Key ID of the key.
    fn key_id(&self) -> KeyId {
        self.key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.key.algorithm()
    }
}

impl Serialize for SignedSecretSubKey {
    fn to_writer<W: io::Write>(&self, writer: &mut W) -> Result<()> {
        write_packet(writer, &self.key)?;
        for sig in &self.signatures {
            write_packet(writer, sig)?;
        }

        Ok(())
    }
}

impl SecretKeyTrait for SignedSecretSubKey {
    type PublicKey = PublicSubkey;

    fn unlock<F, G>(&self, pw: F, work: G) -> Result<()>
    where
        F: FnOnce() -> String,
        G: FnOnce(&SecretKeyRepr) -> Result<()>,
    {
        self.key.unlock(pw, work)
    }

    fn create_signature<F>(&self, key_pw: F, hash: HashAlgorithm, data: &[u8]) -> Result<Vec<Mpi>>
    where
        F: FnOnce() -> String,
    {
        self.key.create_signature(key_pw, hash, data)
    }

    fn public_key(&self) -> Self::PublicKey {
        let keyflags = self
            .signatures
            .first()
            .expect("invalid signed subkey")
            .key_flags();

        PublicSubkey::new(self.key.public_key(), keyflags)
    }
}

impl PublicKeyTrait for SignedSecretSubKey {
    fn verify_signature(&self, hash: HashAlgorithm, data: &[u8], sig: &[Mpi]) -> Result<()> {
        self.key.verify_signature(hash, data, sig)
    }

    fn encrypt<R: Rng + CryptoRng>(&self, rng: &mut R, plain: &[u8]) -> Result<Vec<Mpi>> {
        self.key.encrypt(rng, plain)
    }

    fn to_writer_old(&self, writer: &mut impl io::Write) -> Result<()> {
        self.key.to_writer_old(writer)
    }
}

impl From<SignedSecretKey> for SignedPublicKey {
    fn from(value: SignedSecretKey) -> Self {
        let primary = value.primary_key.public_key();
        let details = value.details;

        let mut subkeys = value.public_subkeys;

        value
            .secret_subkeys
            .into_iter()
            .for_each(|key| subkeys.push(key.into()));

        SignedPublicKey::new(primary, details, subkeys)
    }
}

impl From<SignedSecretSubKey> for SignedPublicSubKey {
    fn from(value: SignedSecretSubKey) -> Self {
        SignedPublicSubKey::new(value.key.public_key(), value.signatures)
    }
}
