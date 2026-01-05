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

use crate::common::constants::*;
use crate::common::types::*;
use crate::traits::crypto_engine::AesGcmParam;
use crate::traits::crypto_engine::AesGcmResult;
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::String;
use crate::{log_e, log_i, p, Box, Vec};

fn init_aes_gcm_param(key: Vec<u8>, iv: [u8; AES_GCM_IV_SIZE]) -> Result<AesGcmParam, ErrorCode> {
    let aad = AES_GCM_AAD.as_bytes().to_vec();
    let aes_param = AesGcmParam { key, iv, aad };
    Ok(aes_param)
}

pub fn encrypt_sec_message(
    message: &[u8],
    key: &[u8],
) -> Result<(Vec<u8>, [u8; AES_GCM_TAG_SIZE], [u8; AES_GCM_IV_SIZE]), ErrorCode> {
    let mut tag = [0u8; AES_GCM_TAG_SIZE];
    let mut iv = [0u8; AES_GCM_IV_SIZE];
    CryptoEngineRegistry::get().secure_random(&mut iv).map_err(|_| {
        log_e!("secure_random fail");
        ErrorCode::GeneralError
    })?;
    let aes_gcm_param = init_aes_gcm_param(key.to_vec(), iv)?;
    let aes_gcm_result = CryptoEngineRegistry::get()
        .aes_gcm_encrypt(message, &aes_gcm_param)
        .map_err(|e| p!(e))?;

    tag.copy_from_slice(&aes_gcm_result.authentication_tag);
    Ok((aes_gcm_result.ciphertext.clone(), tag, iv))
}

pub fn decrypt_sec_message(sec_message: &[u8], key: &[u8], tag: &[u8], iv: &[u8]) -> Result<Vec<u8>, ErrorCode> {
    let mut tag_array = [0u8; AES_GCM_TAG_SIZE];
    if tag.len() != AES_GCM_TAG_SIZE {
        log_e!("tag len is not match, {}", tag.len());
        return Err(ErrorCode::GeneralError);
    }
    tag_array.copy_from_slice(tag);
    let mut iv_array = [0u8; AES_GCM_IV_SIZE];
    if iv.len() != AES_GCM_IV_SIZE {
        log_e!("iv len is not match, {}", iv.len());
        return Err(ErrorCode::GeneralError);
    }
    iv_array.copy_from_slice(iv);
    let aes_gcm_param = init_aes_gcm_param(key.to_vec(), iv_array)?;
    let aes_gcm_result = AesGcmResult::new(sec_message.to_vec(), tag_array);

    let decrypted_data = CryptoEngineRegistry::get()
        .aes_gcm_decrypt(&aes_gcm_param, &aes_gcm_result)
        .map_err(|e| p!(e))?;
    Ok(decrypted_data)
}

pub fn get_distribute_key(local_device_id: &String, peer_device_id: &String) -> Result<Vec<u8>, ErrorCode> {
    let local_udid: Udid = local_device_id.clone().try_into().map_err(|e| {
        log_e!("Failed to convert device_id to Udid: {:?}", e);
        ErrorCode::GeneralError
    })?;
    let peer_udid: Udid = peer_device_id.clone().try_into().map_err(|e| {
        log_e!("Failed to convert device_id to Udid: {:?}", e);
        ErrorCode::GeneralError
    })?;
    MiscManagerRegistry::get_mut().get_distribute_key(local_udid, peer_udid)
}
