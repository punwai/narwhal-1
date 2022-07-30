// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
use base64ct::{Base64, Encoding};
use digest::Digest;
use rand::Rng;
use std::{
    fmt::{self, Display},
    str::FromStr,
};

use crate::{pubkey_bytes::PublicKeyBytes, serde_helpers::keypair_decode_base64};
use serde::{
    de::{self},
    Deserialize, Serialize,
};
use serde_with::serde_as;

use signature::{Signature, Signer, Verifier};

use crate::traits::{
    AggregateAuthenticator, Authenticator, EncodeDecodeBase64, KeyPair, SigningKey, ToFromBytes,
    VerifyingKey,
};
use sha3::Sha3_256;

///
/// Define Structs
///

const PRIVATE_KEY_LENGTH: usize = 20;
const PUBLIC_KEY_LENGTH: usize = 20;

#[readonly::make]
#[derive(Default, Debug, Clone)]
pub struct ZeroPublicKey([u8; PUBLIC_KEY_LENGTH]);

pub type ZeroPublicKeyBytes = PublicKeyBytes<ZeroPublicKey, { PUBLIC_KEY_LENGTH }>;

#[derive(Default, Debug)]
pub struct ZeroPrivateKey([u8; PRIVATE_KEY_LENGTH]);

// There is a strong requirement for this specific impl. in Fab benchmarks
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")] // necessary so as not to deser under a != type
pub struct ZeroKeyPair {
    name: ZeroPublicKey,
    secret: ZeroPrivateKey,
}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroSignature {}

#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroAggregateSignature {}

///
/// Implement SigningKey
///

impl AsRef<[u8]> for ZeroPublicKey {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl ToFromBytes for ZeroPublicKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        let bytes_fixed: [u8; PUBLIC_KEY_LENGTH] =
            bytes.try_into().map_err(|_| signature::Error::new())?;
        Ok(Self(bytes_fixed))
    }
}

impl std::hash::Hash for ZeroPublicKey {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl PartialEq for ZeroPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for ZeroPublicKey {}

impl PartialOrd for ZeroPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.as_ref().partial_cmp(other.as_ref())
    }
}
impl Ord for ZeroPublicKey {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_ref().cmp(other.as_ref())
    }
}

impl Display for ZeroPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode_string(self.as_ref()))
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl Serialize for ZeroPublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl<'de> Deserialize<'de> for ZeroPublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl Verifier<ZeroSignature> for ZeroPublicKey {
    fn verify(&self, _msg: &[u8], _signature: &ZeroSignature) -> Result<(), signature::Error> {
        Ok(())
    }
}

impl<'a> From<&'a ZeroPrivateKey> for ZeroPublicKey {
    fn from(secret: &'a ZeroPrivateKey) -> Self {
        let mut hasher = Sha3_256::new();
        hasher.update(secret.0);
        let result = hasher.finalize();
        let bytes: [u8; PUBLIC_KEY_LENGTH] = result[..PUBLIC_KEY_LENGTH]
            .try_into()
            .map_err(|_| signature::Error::new())
            .unwrap();
        ZeroPublicKey(bytes)
    }
}

impl VerifyingKey for ZeroPublicKey {
    type PrivKey = ZeroPrivateKey;
    type Sig = ZeroSignature;

    const LENGTH: usize = PUBLIC_KEY_LENGTH;

    fn verify_batch(
        _msg: &[u8],
        _pks: &[Self],
        _sigs: &[Self::Sig],
    ) -> Result<(), signature::Error> {
        Ok(())
    }
}

///
/// Implement Authenticator
///

impl AsRef<[u8]> for ZeroSignature {
    fn as_ref(&self) -> &[u8] {
        &[]
    }
}

impl std::hash::Hash for ZeroSignature {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.as_ref().hash(state);
    }
}

impl PartialEq for ZeroSignature {
    fn eq(&self, other: &Self) -> bool {
        self == other
    }
}

impl Eq for ZeroSignature {}

impl Signature for ZeroSignature {
    fn from_bytes(_bytes: &[u8]) -> Result<Self, signature::Error> {
        Ok(ZeroSignature {})
    }
}

impl Default for ZeroSignature {
    fn default() -> Self {
        ZeroSignature {}
    }
}

impl Display for ZeroSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode_string(self.as_ref()))
    }
}

impl Authenticator for ZeroSignature {
    type PubKey = ZeroPublicKey;
    type PrivKey = ZeroPrivateKey;
    const LENGTH: usize = 0;
}

///
/// Implement SigningKey
///

impl AsRef<[u8]> for ZeroPrivateKey {
    fn as_ref(&self) -> &[u8] {
        &[]
    }
}

impl ToFromBytes for ZeroPrivateKey {
    fn from_bytes(bytes: &[u8]) -> Result<Self, signature::Error> {
        let bytes: [u8; PRIVATE_KEY_LENGTH] =
            bytes.try_into().map_err(|_| signature::Error::new())?;
        Ok(ZeroPrivateKey(bytes))
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl Serialize for ZeroPrivateKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.encode_base64())
    }
}

// There is a strong requirement for this specific impl. in Fab benchmarks
impl<'de> Deserialize<'de> for ZeroPrivateKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        let value = Self::decode_base64(&s).map_err(|e| de::Error::custom(e.to_string()))?;
        Ok(value)
    }
}

impl SigningKey for ZeroPrivateKey {
    type PubKey = ZeroPublicKey;
    type Sig = ZeroSignature;
    const LENGTH: usize = PRIVATE_KEY_LENGTH;
}

impl Signer<ZeroSignature> for ZeroPrivateKey {
    fn try_sign(&self, _msg: &[u8]) -> Result<ZeroSignature, signature::Error> {
        Ok(ZeroSignature {})
    }
}

///
/// Implement KeyPair
///

impl From<ZeroPrivateKey> for ZeroKeyPair {
    fn from(secret: ZeroPrivateKey) -> Self {
        let pk: ZeroPublicKey = (&secret).into();
        ZeroKeyPair {
            name: pk,
            secret: secret,
        }
    }
}

impl EncodeDecodeBase64 for ZeroKeyPair {
    fn decode_base64(value: &str) -> Result<Self, eyre::Report> {
        keypair_decode_base64(value)
    }

    fn encode_base64(&self) -> String {
        let mut bytes: Vec<u8> = Vec::new();
        bytes.extend_from_slice(self.secret.as_ref());
        bytes.extend_from_slice(self.name.as_ref());
        base64ct::Base64::encode_string(&bytes[..])
    }
}

impl KeyPair for ZeroKeyPair {
    type PubKey = ZeroPublicKey;
    type PrivKey = ZeroPrivateKey;
    type Sig = ZeroSignature;

    #[cfg(feature = "copy_key")]
    fn copy(&self) -> Self {
        ZeroKeyPair {
            name: ZeroPublicKey(self.name.0),
            secret: ZeroPrivateKey(self.secret.0),
        }
    }

    fn public(&'_ self) -> &'_ Self::PubKey {
        &self.name
    }

    fn private(self) -> Self::PrivKey {
        self.secret
    }

    fn generate<R: rand::CryptoRng + rand::RngCore>(_rng: &mut R) -> Self {
        let sk_bytes: [u8; PUBLIC_KEY_LENGTH] = rand::thread_rng().gen();
        let sk = ZeroPrivateKey(sk_bytes);
        sk.into()
    }
}

impl Signer<ZeroSignature> for ZeroKeyPair {
    fn try_sign(&self, _msg: &[u8]) -> Result<ZeroSignature, signature::Error> {
        Ok(ZeroSignature {})
    }
}

impl FromStr for ZeroKeyPair {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let kp = Self::decode_base64(s).map_err(|e| anyhow::anyhow!("{}", e.to_string()))?;
        Ok(kp)
    }
}

///
/// Implement AggregateAuthenticator
///

// Don't try to use this externally
impl AsRef<[u8]> for ZeroAggregateSignature {
    fn as_ref(&self) -> &[u8] {
        &[]
    }
}

impl Display for ZeroAggregateSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        write!(f, "{}", Base64::encode_string(self.as_ref()))
    }
}

// see [#34](https://github.com/MystenLabs/narwhal/issues/34)
impl Default for ZeroAggregateSignature {
    fn default() -> Self {
        ZeroAggregateSignature {}
    }
}

impl AggregateAuthenticator for ZeroAggregateSignature {
    type PrivKey = ZeroPrivateKey;
    type PubKey = ZeroPublicKey;
    type Sig = ZeroSignature;

    /// Parse a key from its byte representation
    fn aggregate(_signatures: Vec<Self::Sig>) -> Result<Self, signature::Error> {
        Ok(ZeroAggregateSignature {})
    }

    fn add_signature(&mut self, _signature: Self::Sig) -> Result<(), signature::Error> {
        Ok(())
    }

    fn add_aggregate(&mut self, _signature: Self) -> Result<(), signature::Error> {
        Ok(())
    }

    fn verify(
        &self,
        _pks: &[<Self::Sig as Authenticator>::PubKey],
        _message: &[u8],
    ) -> Result<(), signature::Error> {
        Ok(())
    }

    fn batch_verify(
        _signatures: &[Self],
        _pks: &[&[Self::PubKey]],
        _messages: &[&[u8]],
    ) -> Result<(), signature::Error> {
        Ok(())
    }
}

///
/// Implement VerifyingKeyBytes
///

impl TryFrom<ZeroPublicKeyBytes> for ZeroPublicKey {
    type Error = signature::Error;

    fn try_from(bytes: ZeroPublicKeyBytes) -> Result<ZeroPublicKey, Self::Error> {
        ZeroPublicKey::from_bytes(bytes.as_ref())
    }
}

impl From<&ZeroPublicKey> for ZeroPublicKeyBytes {
    fn from(pk: &ZeroPublicKey) -> ZeroPublicKeyBytes {
        ZeroPublicKeyBytes::from_bytes(pk.as_ref()).unwrap()
    }
}
