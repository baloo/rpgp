use chrono::{DateTime, NaiveDateTime, Utc};
use enum_primitive::FromPrimitive;
use nom::{be_u16, be_u32, be_u8, rest, IResult};
use std::str;
use util::mpi;

use packet::types::{
    self, CompressionAlgorithm, HashAlgorithm, PublicKeyAlgorithm, RevocationCode, Signature,
    SignatureType, SignatureVersion, Subpacket, SubpacketType, SymmetricKeyAlgorithm,
};
use util::{clone_into_array, packet_length};

enum_from_primitive!{
#[derive(Debug, PartialEq, Eq, Clone)]
/// Available key flags
pub enum KeyFlag {
    /// This key may be used to certify other keys.
    CertifyKeys = 0x01,
    /// This key may be used to sign data.
    SignData = 0x02,
    /// This key may be used to encrypt communications.
    EncryptCommunication = 0x04,
    /// This key may be used to encrypt storage.
    EncryptStorage = 0x08,
    /// The private component of this key may have been split by a secret-sharing mechanism.
    SplitPrivateKey = 0x10,
    /// This key may be used for authentication.
    Authentication = 0x20,
    /// The private component of this key may be in the possession of more than one person.
    SharedPrivateKey = 0x80,
}
}

/// Convert an epoch timestamp to a `DateTime`
fn dt_from_timestamp(ts: u32) -> DateTime<Utc> {
    DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(ts as i64, 0), Utc)
}

/// Parse a signature creation time subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.4
named!(
    signature_creation_time<Subpacket>,
    map!(
        // 4-octet time field
        be_u32,
        |date| Subpacket::SignatureCreationTime(dt_from_timestamp(date))
    )
);

/// Parse an issuer subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.5
fn issuer<'a>(body: &'a [u8]) -> IResult<&'a [u8], Subpacket> {
    // TODO: proper error handling
    assert_eq!(body.len(), 8);

    Ok((&b""[..], Subpacket::Issuer(clone_into_array(body))))
}

/// Parse a key expiration time subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.6
named!(
    key_expiration<Subpacket>,
    map!(
        // 4-octet time field
        be_u32,
        |date| Subpacket::KeyExpirationTime(dt_from_timestamp(date))
    )
);

/// Parse a preferred symmetric algorithms subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.7
fn pref_sym_alg<'a>(body: &'a [u8]) -> IResult<&'a [u8], Subpacket> {
    let algs = body
        .iter()
        // TODO: proper error handling
        .map(|b| SymmetricKeyAlgorithm::from_u8(*b).unwrap())
        .collect();

    Ok((&b""[..], Subpacket::PreferredSymmetricAlgorithms(algs)))
}

/// Parse a preferred hash algorithms subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.8
fn pref_hash_alg<'a>(body: &'a [u8]) -> IResult<&'a [u8], Subpacket> {
    let algs = body
        .iter()
        // TODO: proper error handling
        .map(|b| HashAlgorithm::from_u8(*b).unwrap())
        .collect();

    Ok((&b""[..], Subpacket::PreferredHashAlgorithms(algs)))
}

/// Parse a preferred compression algorithms subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.9
fn pref_com_alg<'a>(body: &'a [u8]) -> IResult<&'a [u8], Subpacket> {
    let algs = body
        .iter()
        // TODO: proper error handling
        .map(|b| CompressionAlgorithm::from_u8(*b).unwrap())
        .collect();

    Ok((&b""[..], Subpacket::PreferredCompressionAlgorithms(algs)))
}

/// Parse a signature expiration time subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.10
named!(
    signature_expiration_time<Subpacket>,
    map!(
        // 4-octet time field
        be_u32,
        |date| Subpacket::SignatureExpirationTime(dt_from_timestamp(date))
    )
);

/// Parse a revocable subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.12
fn revocable<'a>(body: &'a [u8]) -> IResult<&'a [u8], Subpacket> {
    // TODO: proper error handling
    assert_eq!(body.len(), 1);

    Ok((&b""[..], Subpacket::Revocable(body[0] == 1)))
}

/// Parse a revocation key subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.15
named!(
    revocation_key<Subpacket>,
    do_parse!(
        class: be_u8
            >> alg: map_opt!(be_u8, PublicKeyAlgorithm::from_u8)
            >> fp: take!(20)
            >> (Subpacket::RevocationKey(class, alg, clone_into_array(fp)))
    )
);

/// Parse a notation data subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.16
named!(
    notation_data<Subpacket>,
    do_parse!(
        // Flags
        tag!(&[0x80, 0, 0, 0][..])
            >> name_len: be_u16
            >> value_len: be_u16
            >> name: map_res!(take!(name_len), str::from_utf8)
            >> value: map_res!(take!(value_len), str::from_utf8)
            >> (Subpacket::Notation(name.to_string(), value.to_string()))
    )
);

/// Parse a key server preferences subpacket
/// https://tools.ietf.org/html/rfc4880.html#section-5.2.3.17
fn key_server_prefs(body: &[u8]) -> IResult<&[u8], Subpacket> {
    Ok((&b""[..], Subpacket::KeyServerPreferences(body.to_vec())))
}

/// Parse a preferred key server subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.18
named!(
    preferred_key_server<Subpacket>,
    do_parse!(
        body: map_res!(rest, str::from_utf8)
            >> ({ Subpacket::PreferredKeyServer(body.to_string()) })
    )
);

/// Parse a primary user id subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.19
named!(
    primary_userid<Subpacket>,
    map!(be_u8, |a| Subpacket::IsPrimary(a == 1))
);

/// Parse a key flags subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.21
fn key_flags(body: &[u8]) -> IResult<&[u8], Subpacket> {
    Ok((&b""[..], Subpacket::KeyFlags(body.to_vec())))
}

/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.22
named!(
    signers_userid<Subpacket>,
    do_parse!(body: map_res!(rest, str::from_utf8) >> (Subpacket::SignersUserID(body.to_string())))
);
/// Parse a features subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.24
fn features(body: &[u8]) -> IResult<&[u8], Subpacket> {
    Ok((&b""[..], Subpacket::Features(body.to_vec())))
}

/// Parse a revocation reason subpacket
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.23
named!(
    rev_reason<Subpacket>,
    do_parse!(
        code: map_opt!(be_u8, RevocationCode::from_u8)
            >> reason: rest
            >> (Subpacket::RevocationReason(code, reason.to_vec()))
    )
);

/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3.26
named!(
    embedded_sig<Subpacket>,
    map!(parser, |sig| Subpacket::EmbeddedSignature(sig))
);

fn subpacket<'a>(typ: SubpacketType, body: &'a [u8]) -> IResult<&'a [u8], Subpacket> {
    use self::SubpacketType::*;
    println!("parsing subpacket: {:?} {:?}", typ, body);

    match typ {
        SignatureCreationTime => signature_creation_time(body),
        SignatureExpirationTime => signature_expiration_time(body),
        ExportableCertification => unimplemented!("{:?}", typ),
        TrustSignature => unimplemented!("{:?}", typ),
        RegularExpression => unimplemented!("{:?}", typ),
        Revocable => revocable(body),
        KeyExpirationTime => key_expiration(body),
        PreferredSymmetricAlgorithms => pref_sym_alg(body),
        RevocationKey => revocation_key(body),
        Issuer => issuer(body),
        NotationData => notation_data(body),
        PreferredHashAlgorithms => pref_hash_alg(body),
        PreferredCompressionAlgorithms => pref_com_alg(body),
        KeyServerPreferences => key_server_prefs(body),
        PreferredKeyServer => preferred_key_server(body),
        PrimaryUserID => primary_userid(body),
        PolicyURI => unimplemented!("{:?}", typ),
        KeyFlags => key_flags(body),
        SignersUserID => signers_userid(body),
        RevocationReason => rev_reason(body),
        Features => features(body),
        SignatureTarget => unimplemented!("{:?}", typ),
        EmbeddedSignature => embedded_sig(body),
    }
}

named!(subpackets(&[u8]) -> Vec<Subpacket>,
    many0!(complete!(do_parse!(
        // the subpacket length (1, 2, or 5 octets)
        len: packet_length
    // the subpacket type (1 octet)
    >> typ: map_opt!(be_u8, SubpacketType::from_u8)
    >>   p: flat_map!(take!(len - 1), |b| subpacket(typ, b))
    >> (p)
))));

/// Parse a v2 signature packet
/// > OBSOLETE FORMAT, ONLY HERE FOR COMPATABILITY
/// Ref: https://tools.ietf.org/html/rfc1991#section-6.2
named!(
    v2_parser<Signature>,
    do_parse!(
        // One-octet length of following hashed material. MUST be 5.
        tag!(&[5])
    // One-octet signature type.
    >> typ: map_opt!(be_u8, SignatureType::from_u8)
    // TODO:
    // (d2) signature time stamp (4 bytes);
    // (e) key ID for key used for singing (8 bytes);
    // (f) public-key-cryptosystem (PKC) type (1 byte);
    // (g) message digest algorithm type (1 byte);
    // (h) first two bytes of the MD output, used as a checksum
    //     (2 bytes);
    // (i) a byte string of encrypted data holding the RSA-signed digest.
    >> (
        Signature::new(
            SignatureVersion::V2, typ,
            PublicKeyAlgorithm::RSA,
            HashAlgorithm::SHA1,
            vec![],
            vec![],
        ))
    )
);

/// Parse a v3 signature packet
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.2
named!(
    v3_parser<Signature>,
    do_parse!(
        // One-octet length of following hashed material. MUST be 5.
        tag!(&[5])
    // One-octet signature type.
    >> typ: map_opt!(be_u8, SignatureType::from_u8)
            >> (Signature::new(
                SignatureVersion::V3,
                typ,
                PublicKeyAlgorithm::RSA,
                HashAlgorithm::SHA1,
                vec![],
                vec![],
            )) // TODO
               // -
               //   -
               //   - Four-octet creation time.
               //   - Eight-octet Key ID of signer.
               //  - One-octet public-key algorithm.
               //      - One-octet hash algorithm.
               //      - Two-octet field holding left 16 bits of signed hash value.
               //      - One or more multiprecision integers comprising the signature.
               //        This portion is algorithm specific, as described below.)
    )
);

/// Parse a v4 signature packet
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2.3
named!(
    v4_parser<Signature>,
    do_parse!(
        // One-octet signature type.
        typ: map_opt!(be_u8, SignatureType::from_u8)
    // One-octet public-key algorithm.
    >>  pub_alg: map_opt!(be_u8, PublicKeyAlgorithm::from_u8)
    // One-octet hash algorithm.
    >> hash_alg: map_opt!(be_u8, HashAlgorithm::from_u8)
    // Two-octet scalar octet count for following hashed subpacket data.
    >> hsub_len: be_u16
    // Hashed subpacket data set (zero or more subpackets).
    >>     hsub: flat_map!(take!(hsub_len), subpackets)
    // Two-octet scalar octet count for the following unhashed subpacket data.
    >> usub_len: be_u16
    // Unhashed subpacket data set (zero or more subpackets).
    >>     usub: flat_map!(take!(usub_len), subpackets)
    // Two-octet field holding the left 16 bits of the signed hash value.
    >>  ls_hash: take!(2)
    // One or more multiprecision integers comprising the signature.
    >>      sig: switch!(value!(&pub_alg),
                         &PublicKeyAlgorithm::RSA     => call!(mpi) |
                         &PublicKeyAlgorithm::RSASign => call!(mpi) 
                        // TODO: figure out
                        // &PublicKeyAlgorithm::DSA => conacat(mpi | mpi)
                        // TODO: verify what about the other algorithms
    ) >> ({
            let mut sig = Signature::new(
                SignatureVersion::V4,
                typ,
                pub_alg,
                hash_alg,
                ls_hash.to_vec(),
                sig.to_vec(),
            );

            for p in hsub {
                use self::Subpacket::*;
                match p {
                    SignatureCreationTime(d) => sig.created = Some(d),
                    Issuer(a) => sig.issuer = Some(a),
                    PreferredSymmetricAlgorithms(list) => sig.preferred_symmetric_algs = list,
                    PreferredHashAlgorithms(list) => sig.preferred_hash_algs = list,
                    PreferredCompressionAlgorithms(list) => sig.preferred_compression_algs = list,
                    KeyServerPreferences(f) => sig.key_server_prefs = f,
                    KeyFlags(f) => sig.key_flags = f,
                    Features(f) => sig.features = f,
                    RevocationReason(code, body) => {
                        sig.revocation_reason_code = Some(code);
                        sig.revocation_reason_string =
                            Some(str::from_utf8(body.as_slice()).unwrap().to_string());
                    }
                    IsPrimary(b) => sig.is_primary = b,
                    KeyExpirationTime(d) => sig.key_expiration_time = Some(d),
                    Revocable(b) => sig.is_revocable = b,
                    EmbeddedSignature(mut sig) => sig.embedded_signature = Some(Box::new(sig)),
                    PreferredKeyServer(server) => sig.preferred_key_server = Some(server),
                    SignatureExpirationTime(d) => sig.signature_expiration_time = Some(d),
                    Notation(name, value) => {
                        sig.notations.insert(name, value);
                    }
                    RevocationKey(class, alg, fp) => {
                        sig.revocation_key = Some(types::RevocationKey {
                            class: class,
                            algorithm: alg,
                            fingerprint: fp,
                        });
                    }
                    SignersUserID(u) => sig.signers_userid = Some(u),
                }
            }

            sig.unhashed_subpackets = usub;
            sig
        })
    )
);

/// Parse a signature packet (Tag 2)
/// Ref: https://tools.ietf.org/html/rfc4880.html#section-5.2
named!(pub parser<Signature>, do_parse!(
    // Version
       ver: map_opt!(be_u8, SignatureVersion::from_u8)
    >> sig: switch!(value!(&ver),
                &SignatureVersion::V2 => call!(v2_parser) |
                &SignatureVersion::V3 => call!(v3_parser) |
                &SignatureVersion::V4 => call!(v4_parser)
            )
    >> (sig)
));

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subpacket_pref_sym_alg() {
        let input = vec![9, 8, 7, 3, 2];
        let (_, res) = pref_sym_alg(input.as_slice()).unwrap();
        assert_eq!(
            res,
            Subpacket::PreferredSymmetricAlgorithms(
                input
                    .iter()
                    .map(|i| SymmetricKeyAlgorithm::from_u8(*i).unwrap())
                    .collect()
            )
        );
    }
}