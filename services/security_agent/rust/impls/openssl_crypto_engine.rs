/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// This file uses std:: and can override the no_std config

use crate::common::ErrorCode;
use crate::log_e;
use crate::traits::crypto_engine::{AesGcmParam, AesGcmResult, CryptoEngine, KeyPair, RandomChecker};
use crate::vec;
use crate::Vec;

use openssl::bn::BigNumContext;
use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::hash::{hash, MessageDigest};
use openssl::md::Md;
use openssl::nid::Nid;
use openssl::pkey::Id;
use openssl::pkey::PKey;
use openssl::pkey::Private;
use openssl::pkey_ctx::PkeyCtx;
use openssl::rand::rand_bytes;
use openssl::sign::{Signer, Verifier};
use openssl::symm::{Cipher, Crypter, Mode};

pub struct OpenSSLCryptoEngine;

impl OpenSSLCryptoEngine {
    pub fn new() -> Self {
        Self
    }
}

impl CryptoEngine for OpenSSLCryptoEngine {
    fn generate_ed25519_key_pair(&self) -> Result<KeyPair, ErrorCode> {
        let pkey = PKey::generate_ed25519().map_err(|e| {
            log_e!("Failed to generate Ed25519 key pair: {}", e);
            ErrorCode::GeneralError
        })?;

        let pri_key = pkey.raw_private_key().map_err(|e| {
            log_e!("Failed to serialize private key: {}", e);
            ErrorCode::GeneralError
        })?;

        let pub_key = pkey.raw_public_key().map_err(|e| {
            log_e!("Failed to serialize public key: {}", e);
            ErrorCode::GeneralError
        })?;

        Ok(KeyPair::new(pub_key, pri_key))
    }

    fn ed25519_sign(&self, pri_key: &[u8], data: &[u8]) -> Result<Vec<u8>, ErrorCode> {
        let pkey = PKey::private_key_from_raw_bytes(pri_key, Id::ED25519).map_err(|e| {
            log_e!("Failed to parse private key: {}", e);
            ErrorCode::GeneralError
        })?;

        let mut signer = Signer::new_without_digest(&pkey).map_err(|e| {
            log_e!("Failed to create signer: {}", e);
            ErrorCode::GeneralError
        })?;

        signer.sign_oneshot_to_vec(data).map_err(|e| {
            log_e!("Failed to sign data: {}", e);
            ErrorCode::GeneralError
        })
    }

    fn ed25519_verify(&self, pub_key: &[u8], data: &[u8], sign: &[u8]) -> Result<(), ErrorCode> {
        if pub_key.is_empty() {
            log_e!("Public key is empty");
            return Err(ErrorCode::GeneralError);
        }

        let pkey = PKey::public_key_from_raw_bytes(pub_key, Id::ED25519).map_err(|e| {
            log_e!("Failed to parse public key: {}", e);
            ErrorCode::GeneralError
        })?;

        let mut verifier = Verifier::new_without_digest(&pkey).map_err(|e| {
            log_e!("Failed to create verifier: {}", e);
            ErrorCode::GeneralError
        })?;

        verifier
            .verify_oneshot(sign, data)
            .map_err(|e| {
                log_e!("Failed to verify signature: {}", e);
                ErrorCode::GeneralError
            })
            .and_then(|result| {
                if result {
                    Ok(())
                } else {
                    log_e!("Signature verification failed");
                    Err(ErrorCode::GeneralError)
                }
            })
    }

    fn hmac_sha256(&self, hmac_key: &[u8], data: &[u8]) -> Result<Vec<u8>, ErrorCode> {
        let pkey = PKey::hmac(hmac_key).map_err(|e| {
            log_e!("Failed to create HMAC key: {}", e);
            ErrorCode::GeneralError
        })?;

        let mut signer = Signer::new(MessageDigest::sha256(), &pkey).map_err(|e| {
            log_e!("Failed to create HMAC signer: {}", e);
            ErrorCode::GeneralError
        })?;

        signer.update(data).map_err(|e| {
            log_e!("Failed to update HMAC: {}", e);
            ErrorCode::GeneralError
        })?;

        signer.sign_to_vec().map_err(|e| {
            log_e!("Failed to finalize HMAC: {}", e);
            ErrorCode::GeneralError
        })
    }

    fn sha256(&self, data: &[u8]) -> Result<crate::Vec<u8>, ErrorCode> {
        let hasher = hash(MessageDigest::sha256(), data).map_err(|e| {
            log_e!("Failed to hash data: {}", e);
            ErrorCode::GeneralError
        })?;

        Ok(hasher.to_vec())
    }

    fn secure_random(&self, out_buffer: &mut [u8]) -> Result<(), ErrorCode> {
        rand_bytes(out_buffer).map_err(|e| {
            log_e!("Failed to generate secure random bytes: {}", e);
            ErrorCode::GeneralError
        })
    }

    fn secure_random_with_check(&self, out_buffer: &mut [u8], checker: RandomChecker) -> Result<(), ErrorCode> {
        const MAX_RETRY_TIME: u32 = 10;
        for _i in 0..MAX_RETRY_TIME {
            self.secure_random(out_buffer)?;
            if checker(out_buffer) {
                return Ok(());
            }
        }

        log_e!("Failed to generate secure random bytes with check");
        Err(ErrorCode::GeneralError)
    }

    fn aes_gcm_encrypt(&self, plaintext: &[u8], aes_gcm_param: &AesGcmParam) -> Result<AesGcmResult, ErrorCode> {
        if aes_gcm_param.key.len() != 32 {
            log_e!("AES-GCM key must be 256 bits (32 bytes)");
            return Err(ErrorCode::BadParam);
        }

        let cipher = Cipher::aes_256_gcm();
        let mut crypter =
            Crypter::new(cipher, Mode::Encrypt, &aes_gcm_param.key, Some(&aes_gcm_param.iv)).map_err(|e| {
                log_e!("Failed to create encrypt crypter: {}", e);
                ErrorCode::GeneralError
            })?;

        crypter.aad_update(&aes_gcm_param.aad).map_err(|e| {
            log_e!("Failed to add AAD: {}", e);
            ErrorCode::GeneralError
        })?;

        let mut ciphertext = vec![0; plaintext.len() + cipher.block_size()];
        let count = crypter.update(plaintext, &mut ciphertext).map_err(|e| {
            log_e!("Failed to encrypt data: {}", e);
            ErrorCode::GeneralError
        })?;

        let rest = crypter.finalize(&mut ciphertext[count..]).map_err(|e| {
            log_e!("Failed to finalize encryption: {}", e);
            ErrorCode::GeneralError
        })?;

        ciphertext.truncate(count + rest);

        let mut tag = [0u8; 16];
        crypter.get_tag(&mut tag).map_err(|e| {
            log_e!("Failed to get authentication tag: {}", e);
            ErrorCode::GeneralError
        })?;

        Ok(AesGcmResult::new(ciphertext, tag))
    }

    fn aes_gcm_decrypt(&self, aes_gcm_param: &AesGcmParam, result: &AesGcmResult) -> Result<Vec<u8>, ErrorCode> {
        if aes_gcm_param.key.len() != 32 {
            log_e!("AES-GCM key must be 256 bits (32 bytes)");
            return Err(ErrorCode::BadParam);
        }

        let tag = &result.authentication_tag;

        let cipher = Cipher::aes_256_gcm();
        let mut crypter =
            Crypter::new(cipher, Mode::Decrypt, &aes_gcm_param.key, Some(&aes_gcm_param.iv)).map_err(|e| {
                log_e!("Failed to create decrypt crypter: {}", e);
                ErrorCode::GeneralError
            })?;

        crypter.aad_update(&aes_gcm_param.aad).map_err(|e| {
            log_e!("Failed to add AAD: {}", e);
            ErrorCode::GeneralError
        })?;

        crypter.set_tag(tag).map_err(|e| {
            log_e!("Failed to set authentication tag: {}", e);
            ErrorCode::GeneralError
        })?;

        let ciphertext = &result.ciphertext;
        let mut plaintext = vec![0; ciphertext.len() + cipher.block_size()];
        let count = crypter.update(ciphertext, &mut plaintext).map_err(|e| {
            log_e!("Failed to decrypt data: {}", e);
            ErrorCode::GeneralError
        })?;

        let rest = crypter.finalize(&mut plaintext[count..]).map_err(|e| {
            log_e!("Failed to finalize decryption: {}", e);
            ErrorCode::GeneralError
        })?;

        plaintext.truncate(count + rest);

        Ok(plaintext)
    }

    fn hkdf(&self, salt: &[u8], key: &[u8]) -> Result<crate::Vec<u8>, ErrorCode> {
        let mut ctx = PkeyCtx::new_id(Id::HKDF).map_err(|e| {
            log_e!("Failed to create HKDF context: {}", e);
            ErrorCode::GeneralError
        })?;

        ctx.derive_init().map_err(|e| {
            log_e!("Failed to initialize HKDF derivation: {}", e);
            ErrorCode::GeneralError
        })?;

        ctx.set_hkdf_md(Md::sha256()).map_err(|e| {
            log_e!("Failed to set HKDF hash algorithm to SHA256: {}", e);
            ErrorCode::GeneralError
        })?;

        ctx.set_hkdf_key(key).map_err(|e| {
            log_e!("Failed to set HKDF input key material length: {} error: {}", key.len(), e);
            ErrorCode::GeneralError
        })?;

        ctx.set_hkdf_salt(salt).map_err(|e| {
            log_e!("Failed to set HKDF salt length: {} error: {}", salt.len(), e);
            ErrorCode::GeneralError
        })?;

        let mut out = vec![0u8; 32];
        ctx.derive(Some(out.as_mut_slice())).map_err(|e| {
            log_e!("Failed to derive key using HKDF: {}", e);
            ErrorCode::GeneralError
        })?;

        Ok(out)
    }

    fn p256_ecdh(&self, key_pair: &KeyPair, pub_key: &[u8]) -> Result<crate::Vec<u8>, ErrorCode> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(|e| {
            log_e!("Failed to create EC group for P-256: {}", e);
            ErrorCode::GeneralError
        })?;

        let priv_bn = openssl::bn::BigNum::from_slice(&key_pair.pri_key).map_err(|e| {
            log_e!("Failed to parse private key from bytes: {}", e);
            ErrorCode::GeneralError
        })?;

        let mut public_point = EcPoint::new(&group).map_err(|e| {
            log_e!("Failed to create EC point: {}", e);
            ErrorCode::GeneralError
        })?;

        let mut ctx = BigNumContext::new().map_err(|e| {
            log_e!("Failed to create BigNum context: {}", e);
            ErrorCode::GeneralError
        })?;

        public_point.mul_generator(&group, &priv_bn, &mut ctx).map_err(|e| {
            log_e!("Failed to generate public key from private key: {}", e);
            ErrorCode::GeneralError
        })?;

        let ec_key = EcKey::from_private_components(&group, &priv_bn, &public_point).map_err(|e| {
            log_e!("Failed to create EC key from private components: {}", e);
            ErrorCode::GeneralError
        })?;

        let private_pkey = PKey::from_ec_key(ec_key).map_err(|e| {
            log_e!("Failed to create PKey from EC key: {}", e);
            ErrorCode::GeneralError
        })?;

        let peer_point = EcPoint::from_bytes(&group, pub_key, &mut ctx).map_err(|e| {
            log_e!("Failed to parse peer public key from bytes: {}", e);
            ErrorCode::GeneralError
        })?;

        let peer_ec_key = EcKey::from_public_key(&group, &peer_point).map_err(|e| {
            log_e!("Failed to create EC key from peer public key: {}", e);
            ErrorCode::GeneralError
        })?;

        let peer_pkey = PKey::from_ec_key(peer_ec_key).map_err(|e| {
            log_e!("Failed to create PKey from peer EC key: {}", e);
            ErrorCode::GeneralError
        })?;

        let mut deriver = Deriver::new(&private_pkey).map_err(|e| {
            log_e!("Failed to create key deriver: {}", e);
            ErrorCode::GeneralError
        })?;

        deriver.set_peer(&peer_pkey).map_err(|e| {
            log_e!("Failed to set peer public key for ECDH: {}", e);
            ErrorCode::GeneralError
        })?;

        let shared_secret = deriver.derive_to_vec().map_err(|e| {
            log_e!("Failed to derive shared secret via ECDH: {}", e);
            ErrorCode::GeneralError
        })?;

        Ok(shared_secret)
    }

    fn x25519_ecdh(&self, key_pair: &KeyPair, pub_key: &[u8]) -> Result<crate::Vec<u8>, ErrorCode> {
        let private_pkey = PKey::private_key_from_raw_bytes(&key_pair.pri_key, Id::X25519).map_err(|e| {
            log_e!("Failed to create private PKey from raw bytes: {}", e);
            ErrorCode::GeneralError
        })?;

        let peer_pkey = PKey::public_key_from_raw_bytes(pub_key, Id::X25519).map_err(|e| {
            log_e!("Failed to create peer public PKey from raw bytes: {}", e);
            ErrorCode::GeneralError
        })?;

        let mut deriver = Deriver::new(&private_pkey).map_err(|e| {
            log_e!("Failed to create key deriver for X25519: {}", e);
            ErrorCode::GeneralError
        })?;

        deriver.set_peer(&peer_pkey).map_err(|e| {
            log_e!("Failed to set peer public key for X25519 ECDH: {}", e);
            ErrorCode::GeneralError
        })?;

        let shared_secret = deriver.derive_to_vec().map_err(|e| {
            log_e!("Failed to derive shared secret via X25519 ECDH: {}", e);
            ErrorCode::GeneralError
        })?;
        Ok(shared_secret)
    }

    fn generate_x25519_key_pair(&self) -> Result<KeyPair, ErrorCode> {
        let pkey = PKey::generate_x25519().map_err(|e| {
            log_e!("Failed to generate X25519 key pair: {}", e);
            ErrorCode::GeneralError
        })?;

        let pri_key = pkey.raw_private_key().map_err(|e| {
            log_e!("Failed to serialize private key: {}", e);
            ErrorCode::GeneralError
        })?;

        let pub_key = pkey.raw_public_key().map_err(|e| {
            log_e!("Failed to serialize public key: {}", e);
            ErrorCode::GeneralError
        })?;

        if pub_key.len() != 32 || pri_key.len() != 32 {
            log_e!("Invalid key length: pub={}, pri={}", pub_key.len(), pri_key.len());
            return Err(ErrorCode::GeneralError);
        }

        Ok(KeyPair::new(pub_key, pri_key))
    }
}
