//! This attempts to demonstrate the use of a private key held in an HSM or
//! more generally a remote API (TPM / Cloud HSM / ...).

use std::{fmt, marker::PhantomData};

use chrono::{DateTime, Utc};
use cipher::ArrayLength;
use ecdsa::{
    hazmat::DigestPrimitive,
    signature::{hazmat::PrehashSigner, Keypair},
    PrimeCurve, SignatureSize,
};
use elliptic_curve::CurveArithmetic;
use pgp::{
    bail,
    composed::key,
    crypto::{hash::HashAlgorithm, public_key::PublicKeyAlgorithm},
    errors::Result,
    packet::{KeyFlags, PublicKey, UserId},
    types::{
        EcdsaPublicParams, EskType, KeyId, KeyVersion, Mpi, PkeskBytes, PublicKeyTrait,
        PublicParams, SecretKeyTrait, SignatureBytes, Version,
    },
    ArmorOptions, Message,
};
use rand::{CryptoRng, Rng};

trait PgpPublicKey {
    const PgpAlgorithm: PublicKeyAlgorithm;

    fn pgp_parameters(&self) -> PublicParams;
}

impl<C> PgpPublicKey for ecdsa::VerifyingKey<C>
where
    Self: PgpEcdsaPublicKey,
    C: PrimeCurve + CurveArithmetic,
{
    const PgpAlgorithm: PublicKeyAlgorithm = PublicKeyAlgorithm::ECDSA;
    fn pgp_parameters(&self) -> PublicParams {
        let key = self.ecdsa_public_key();
        PublicParams::ECDSA(key)
    }
}

trait PgpEcdsaPublicKey {
    fn ecdsa_public_key(&self) -> EcdsaPublicParams;
}

impl PgpEcdsaPublicKey for p256::ecdsa::VerifyingKey {
    fn ecdsa_public_key(&self) -> EcdsaPublicParams {
        let key = self.into();
        let p = Mpi::from_raw(self.to_sec1_bytes().to_vec());
        EcdsaPublicParams::P256 { key, p }
    }
}

trait PgpHash {
    const HashAlgorithm: HashAlgorithm;
}

impl PgpHash for sha2::Sha256 {
    const HashAlgorithm: HashAlgorithm = HashAlgorithm::SHA2_256;
}

struct EcdsaSigner<'a, T, C> {
    inner: &'a T,
    public_key: PublicKey,
    _signature: PhantomData<C>,
}

impl<'a, C, T> EcdsaSigner<'a, T, C>
where
    T: Keypair,
    T::VerifyingKey: PgpPublicKey,
{
    pub fn new(inner: &'a T, created_at: DateTime<Utc>) -> Result<Self> {
        let public_key = PublicKey::new(
            Version::New,
            KeyVersion::V4,
            <T as Keypair>::VerifyingKey::PgpAlgorithm,
            created_at,
            None,
            inner.verifying_key().pgp_parameters(),
        )?;

        Ok(Self {
            inner,
            public_key,
            _signature: PhantomData,
        })
    }
}

impl<'a, C, T> Keypair for EcdsaSigner<'a, T, C>
where
    T: Keypair,
{
    type VerifyingKey = T::VerifyingKey;

    fn verifying_key(&self) -> Self::VerifyingKey {
        self.inner.verifying_key()
    }
}

impl<'a, C, T> EcdsaSigner<'a, T, C>
where
    C: PrimeCurve + DigestPrimitive,
    SignatureSize<C>: ArrayLength<u8>,
    T: PrehashSigner<ecdsa::Signature<C>>,
    C::Digest: PgpHash,
{
    fn sign_prehash(&self, hash: HashAlgorithm, prehash: &[u8]) -> Result<Vec<Vec<u8>>> {
        if C::Digest::HashAlgorithm != hash {
            bail!(
                "Signer only support {expected:?}, found {found:?}",
                expected = C::Digest::HashAlgorithm,
                found = hash
            );
        }
        let signature = self.inner.sign_prehash(prehash)?;
        let (r, s) = signature.split_bytes();
        Ok(vec![r.to_vec(), s.to_vec()])
    }
}

impl<'a, C, T> fmt::Debug for EcdsaSigner<'a, T, C> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EcdsaSigner").finish()
    }
}

impl<'a, C, T> SecretKeyTrait for EcdsaSigner<'a, T, C>
where
    C: PrimeCurve + DigestPrimitive,
    SignatureSize<C>: ArrayLength<u8>,
    T: PrehashSigner<ecdsa::Signature<C>>,
    C::Digest: PgpHash,
{
    type PublicKey = PublicKey;
    type Unlocked = Self;

    fn unlock<F, G, Tr>(&self, _pw: F, work: G) -> pgp::errors::Result<Tr>
    where
        F: FnOnce() -> String,
        G: FnOnce(&Self::Unlocked) -> pgp::errors::Result<Tr>,
    {
        work(self)
    }

    fn create_signature<F>(
        &self,
        _key_pw: F,
        hash: HashAlgorithm,
        prehashed_data: &[u8],
    ) -> pgp::errors::Result<SignatureBytes>
    where
        F: FnOnce() -> String,
    {
        let sig = self.sign_prehash(hash, prehashed_data)?;

        // MPI format:
        // strip leading zeros, to match parse results from MPIs
        let mpis = sig
            .iter()
            .map(|v| Mpi::from_slice(&v[..]))
            .collect::<Vec<_>>();

        Ok(SignatureBytes::Mpis(mpis))
    }

    fn public_key(&self) -> Self::PublicKey {
        self.public_key.clone()
    }

    fn hash_alg(&self) -> HashAlgorithm {
        C::Digest::HashAlgorithm
    }
}

impl<'a, C, T> PublicKeyTrait for EcdsaSigner<'a, T, C> {
    fn verify_signature(
        &self,
        hash: pgp::crypto::hash::HashAlgorithm,
        data: &[u8],
        sig: &SignatureBytes,
    ) -> pgp::errors::Result<()> {
        self.public_key.verify_signature(hash, data, sig)
    }

    fn encrypt<R: CryptoRng + Rng>(
        &self,
        rng: R,
        plain: &[u8],
        esk_type: EskType,
    ) -> pgp::errors::Result<PkeskBytes> {
        bail!("Encryption is unsupported")
    }

    fn serialize_for_hashing(&self, writer: &mut impl std::io::Write) -> pgp::errors::Result<()> {
        self.public_key.serialize_for_hashing(writer)
    }

    fn version(&self) -> KeyVersion {
        self.public_key.version()
    }

    fn fingerprint(&self) -> pgp::types::Fingerprint {
        self.public_key.fingerprint()
    }

    fn key_id(&self) -> KeyId {
        self.public_key.key_id()
    }

    fn algorithm(&self) -> PublicKeyAlgorithm {
        self.public_key.algorithm()
    }

    fn created_at(&self) -> &chrono::DateTime<chrono::Utc> {
        self.public_key.created_at()
    }

    fn expiration(&self) -> Option<u16> {
        self.public_key.expiration()
    }

    fn public_params(&self) -> &PublicParams {
        self.public_key.public_params()
    }

    fn is_encryption_key(&self) -> bool {
        false
    }
}

fn main() {
    let mut rng = rand::thread_rng();
    let signer = p256::ecdsa::SigningKey::random(&mut rng);

    let key = EcdsaSigner::new(&signer, Default::default()).expect("Create public key");

    let mut flags = KeyFlags(0);
    flags.set_sign(true);
    let public = key::PublicKey::new(
        key.public_key(),
        key::KeyDetails::new(
            UserId::from_str(Version::New, "demo"),
            vec![],
            vec![],
            flags,
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
        ),
        vec![],
    );
    let signed_public = public
        .sign(&mut rng, &key, || String::new())
        .expect("Sign public key");

    println!(
        "public_key: {}",
        signed_public
            .to_armored_string(ArmorOptions::default())
            .expect("Serialize public key")
    );

    const HELLO: &[u8] = b"helloworld";

    let message = Message::new_literal_bytes("test", HELLO);
    let signature = message
        .clone()
        .sign(&mut rng, &key, || String::new(), key.hash_alg())
        .expect("sign payload");

    println!(
        "signature of 'helloworld': {signature}",
        signature = signature
            .to_armored_string(ArmorOptions::default())
            .expect("Serialize public key")
    );

    println!("verified? {}", signature.verify(&key).is_ok());
}
