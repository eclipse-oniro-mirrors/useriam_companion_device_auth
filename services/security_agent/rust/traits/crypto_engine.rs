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

use crate::common::ErrorCode;
use crate::log_e;
use crate::singleton_registry;
use crate::Box;
use crate::{AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPair {
    pub pub_key: crate::Vec<u8>,
    pub pri_key: crate::Vec<u8>,
}

impl KeyPair {
    pub fn new(pub_key: crate::Vec<u8>, pri_key: crate::Vec<u8>) -> Self {
        Self { pub_key, pri_key }
    }

    pub fn check_valid(&self) -> bool {
        if self.pub_key.is_empty() {
            log_e!("Public key is empty");
            return false;
        }

        if self.pri_key.is_empty() {
            log_e!("Private key is empty");
            return false;
        }
        true
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.pri_key.fill(0);
        self.pri_key.clear();
        self.pub_key.fill(0);
        self.pub_key.clear();
    }
}

pub struct AesGcmParam {
    pub key: crate::Vec<u8>,
    pub iv: [u8; AES_GCM_IV_SIZE],
    pub aad: crate::Vec<u8>,
}

impl Drop for AesGcmParam {
    fn drop(&mut self) {
        self.key.fill(0);
        self.key.clear();
        self.iv.fill(0);
        self.aad.fill(0);
        self.aad.clear();
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AesGcmResult {
    pub ciphertext: crate::Vec<u8>,
    pub authentication_tag: [u8; AES_GCM_TAG_SIZE],
}

impl AesGcmResult {
    pub fn new(ciphertext: crate::Vec<u8>, authentication_tag: [u8; AES_GCM_TAG_SIZE]) -> Self {
        Self { ciphertext, authentication_tag }
    }
}

impl Drop for AesGcmResult {
    fn drop(&mut self) {
        self.ciphertext.fill(0);
        self.ciphertext.clear();
        self.authentication_tag.fill(0);
    }
}

pub type RandomChecker = Box<dyn Fn(&[u8]) -> bool>;

pub trait CryptoEngine {
    fn generate_ed25519_key_pair(&self) -> Result<KeyPair, ErrorCode>;
    fn ed25519_sign(&self, pri_key: &[u8], data: &[u8]) -> Result<crate::Vec<u8>, ErrorCode>;
    fn ed25519_verify(&self, pub_key: &[u8], data: &[u8], sign: &[u8]) -> Result<(), ErrorCode>;
    fn hmac_sha256(&self, hmac_key: &[u8], data: &[u8]) -> Result<crate::Vec<u8>, ErrorCode>;
    fn sha256(&self, data: &[u8]) -> Result<crate::Vec<u8>, ErrorCode>;
    fn secure_random(&self, out_buffer: &mut [u8]) -> Result<(), ErrorCode>;
    fn secure_random_with_check(&self, _out_buffer: &mut [u8], _checker: RandomChecker) -> Result<(), ErrorCode>;
    fn aes_gcm_encrypt(&self, plaintext: &[u8], aes_gcm_param: &AesGcmParam) -> Result<AesGcmResult, ErrorCode>;
    fn aes_gcm_decrypt(&self, aes_gcm_param: &AesGcmParam, result: &AesGcmResult) -> Result<crate::Vec<u8>, ErrorCode>;
    fn hkdf(&self, salt: &[u8], key: &[u8]) -> Result<crate::Vec<u8>, ErrorCode>;
    fn p256_ecdh(&self, key_pair: &KeyPair, pub_key: &[u8]) -> Result<crate::Vec<u8>, ErrorCode>;
    fn x25519_ecdh(&self, key_pair: &KeyPair, pub_key: &[u8]) -> Result<crate::Vec<u8>, ErrorCode>;
    fn generate_x25519_key_pair(&self) -> Result<KeyPair, ErrorCode>;
}

pub struct DummyCryptoEngine;

impl CryptoEngine for DummyCryptoEngine {
    fn generate_ed25519_key_pair(&self) -> Result<KeyPair, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn ed25519_sign(&self, _pri_key: &[u8], _data: &[u8]) -> Result<crate::Vec<u8>, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn ed25519_verify(&self, _pub_key: &[u8], _data: &[u8], _sign: &[u8]) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn hmac_sha256(&self, _hmac_key: &[u8], _data: &[u8]) -> Result<crate::Vec<u8>, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn sha256(&self, _data: &[u8]) -> Result<crate::Vec<u8>, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn secure_random(&self, _buffer: &mut [u8]) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn secure_random_with_check(&self, _out_buffer: &mut [u8], _checker: RandomChecker) -> Result<(), ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn aes_gcm_encrypt(&self, _plaintext: &[u8], _aes_gcm_param: &AesGcmParam) -> Result<AesGcmResult, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn aes_gcm_decrypt(
        &self,
        _aes_gcm_param: &AesGcmParam,
        _result: &AesGcmResult,
    ) -> Result<crate::Vec<u8>, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn hkdf(&self, _salt: &[u8], _key: &[u8]) -> Result<crate::Vec<u8>, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn p256_ecdh(&self, _key_pair: &KeyPair, _pub_key: &[u8]) -> Result<crate::Vec<u8>, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn x25519_ecdh(&self, _key_pair: &KeyPair, _pub_key: &[u8]) -> Result<crate::Vec<u8>, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn generate_x25519_key_pair(&self) -> Result<KeyPair, ErrorCode> {
        log_e!("not implemented");
        Err(ErrorCode::GeneralError)
    }
}

singleton_registry!(CryptoEngineRegistry, CryptoEngine, DummyCryptoEngine);

#[cfg(any(test, feature = "test-utils"))]
pub use crate::test_utils::mock::MockCryptoEngine;
