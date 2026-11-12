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

use crate::common::constants::{
    AeadAlgoType, KaAlgoType, KdfAlgoType, MacAlgoType, ErrorCode, AES_GCM_AAD, AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE,
};
use crate::common::types::Udid;
use crate::traits::crypto_engine::AesGcmParam;
use crate::traits::crypto_engine::AesGcmResult;
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::crypto_engine::KeyPair;
use crate::traits::log_trace::RustFileId;
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::{log_e, p, Box, Vec};
#[cfg(not(any(test, feature = "test-utils")))]
use alloc::borrow::ToOwned;
#[cfg(any(test, feature = "test-utils"))]
use std::borrow::ToOwned;
pub(crate) const FILE_ID: u16 = RustFileId::MessageCrypto as u16;
type EncryptedMessage = (Vec<u8>, [u8; AES_GCM_TAG_SIZE], [u8; AES_GCM_IV_SIZE]);

fn init_aes_gcm_param(key: &[u8], iv: [u8; AES_GCM_IV_SIZE]) -> Result<Box<AesGcmParam>, ErrorCode> {
    let aad = AES_GCM_AAD.as_bytes().to_vec();
    let aes_param = Box::new(AesGcmParam { key: key.to_vec(), iv, aad });
    Ok(aes_param)
}

pub fn generate_key_pair(ka_algorithm: u16) -> Result<KeyPair, ErrorCode> {
    match KaAlgoType::try_from(ka_algorithm).map_err(|e| p!(e))? {
        KaAlgoType::X25519 => CryptoEngineRegistry::get().generate_x25519_key_pair(),
        KaAlgoType::None => Err(ErrorCode::BadParam),
    }
}

pub fn key_agreement(ka_algorithm: u16, key_pair: &KeyPair, peer_pub_key: &[u8]) -> Result<Vec<u8>, ErrorCode> {
    match KaAlgoType::try_from(ka_algorithm).map_err(|e| p!(e))? {
        KaAlgoType::X25519 => CryptoEngineRegistry::get().x25519_ecdh(key_pair, peer_pub_key),
        KaAlgoType::None => Err(ErrorCode::BadParam),
    }
}

fn encrypt_sec_message_aes256_gcm(message: &[u8], key: &[u8]) -> Result<EncryptedMessage, ErrorCode> {
    let mut tag = [0u8; AES_GCM_TAG_SIZE];
    let mut iv = [0u8; AES_GCM_IV_SIZE];
    CryptoEngineRegistry::get().secure_random(&mut iv).map_err(|_| {
        log_e!("secure_random fail");
        ErrorCode::GeneralError
    })?;
    let aes_gcm_param = init_aes_gcm_param(key, iv)?;
    let aes_gcm_result = CryptoEngineRegistry::get().aes_gcm_encrypt(message, &aes_gcm_param).map_err(|e| p!(e))?;

    tag.copy_from_slice(&aes_gcm_result.authentication_tag);
    Ok((aes_gcm_result.ciphertext.clone(), tag, iv))
}

fn decrypt_sec_message_aes256_gcm(sec_message: &[u8], key: &[u8], tag: &[u8], iv: &[u8]) -> Result<Vec<u8>, ErrorCode> {
    let mut tag_array = [0u8; AES_GCM_TAG_SIZE];
    if tag.len() != AES_GCM_TAG_SIZE {
        log_e!("tag len does not match, {}", tag.len());
        return Err(ErrorCode::GeneralError);
    }
    tag_array.copy_from_slice(tag);
    let mut iv_array = [0u8; AES_GCM_IV_SIZE];
    if iv.len() != AES_GCM_IV_SIZE {
        log_e!("iv len does not match, {}", iv.len());
        return Err(ErrorCode::GeneralError);
    }
    iv_array.copy_from_slice(iv);
    let aes_gcm_param = init_aes_gcm_param(key, iv_array)?;
    let aes_gcm_result = AesGcmResult::new(sec_message.to_vec(), tag_array);

    CryptoEngineRegistry::get().aes_gcm_decrypt(&aes_gcm_param, &aes_gcm_result).map_err(|e| p!(e))
}

pub fn derive_session_key(kdf_algorithm: u16, salt: &[u8], sk: &[u8]) -> Result<Vec<u8>, ErrorCode> {
    match KdfAlgoType::try_from(kdf_algorithm).map_err(|e| p!(e))? {
        KdfAlgoType::HkdfSha256 => CryptoEngineRegistry::get().hkdf(salt, sk),
        KdfAlgoType::Invalid => Err(ErrorCode::BadParam),
    }
}

pub fn encrypt_sec_message(
    aead_algorithm: u16,
    message: &[u8],
    key: &[u8],
) -> Result<EncryptedMessage, ErrorCode> {
    match AeadAlgoType::try_from(aead_algorithm).map_err(|e| p!(e))? {
        AeadAlgoType::Aes256Gcm => encrypt_sec_message_aes256_gcm(message, key),
        AeadAlgoType::Invalid => Err(ErrorCode::BadParam),
    }
}

pub fn decrypt_sec_message(
    aead_algorithm: u16,
    sec_message: &[u8],
    key: &[u8],
    tag: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, ErrorCode> {
    match AeadAlgoType::try_from(aead_algorithm).map_err(|e| p!(e))? {
        AeadAlgoType::Aes256Gcm => decrypt_sec_message_aes256_gcm(sec_message, key, tag, iv),
        AeadAlgoType::Invalid => Err(ErrorCode::BadParam),
    }
}

pub fn compute_mac(mac_algorithm: u16, hmac_key: &[u8], data: &[u8]) -> Result<Vec<u8>, ErrorCode> {
    match MacAlgoType::try_from(mac_algorithm).map_err(|e| p!(e))? {
        MacAlgoType::HmacSha256 => CryptoEngineRegistry::get().hmac_sha256(hmac_key, data),
        MacAlgoType::Invalid => Err(ErrorCode::BadParam),
    }
}

pub fn get_distribute_key(local_device_id: &str, peer_device_id: &str) -> Result<Vec<u8>, ErrorCode> {
    let local_udid: Udid = local_device_id.to_owned().try_into().map_err(|e| {
        log_e!("Failed to convert device_id to Udid: {:?}", e);
        ErrorCode::GeneralError
    })?;
    let peer_udid: Udid = peer_device_id.to_owned().try_into().map_err(|e| {
        log_e!("Failed to convert device_id to Udid: {:?}", e);
        ErrorCode::GeneralError
    })?;
    MiscManagerRegistry::get_mut().get_distribute_key(local_udid, peer_udid)
}
