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
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::types::Udid;
use crate::{log_e, p, Vec};

pub const AES_GCM_TOKEN_AAD_BYTES: &[u8] = b"OH_authToken";
pub const AUTH_TOKEN_CIPHER_LEN: usize = core::mem::size_of::<TokenDataToEncrypt>();
pub const TOKEN_VERSION: u32 = 0;

// Encrypted+signed auth token product
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct UserAuthToken {
    pub version: u32,
    pub token_data_plain: TokenDataPlain,
    pub token_data_cipher: [u8; AUTH_TOKEN_CIPHER_LEN],
    pub tag: [u8; AES_GCM_TAG_SIZE],
    pub iv: [u8; AES_GCM_IV_SIZE],
    pub sign: [u8; SHA256_DIGEST_SIZE],
}

impl UserAuthToken {
    pub fn new(
        version: u32,
        token_data_plain: TokenDataPlain,
        token_data_cipher: [u8; AUTH_TOKEN_CIPHER_LEN],
        tag: [u8; AES_GCM_TAG_SIZE],
        iv: [u8; AES_GCM_IV_SIZE],
        sign: [u8; SHA256_DIGEST_SIZE],
    ) -> Self {
        Self { version, token_data_plain, token_data_cipher, tag, iv, sign }
    }

    // Struct serialization
    pub fn serialize(&self) -> &[u8] {
        unsafe { core::slice::from_raw_parts(self as *const Self as *const u8, core::mem::size_of::<Self>()) }
    }

    // Struct deserialization
    pub fn deserialize(bytes: &[u8]) -> Result<Self, ErrorCode> {
        if bytes.len() != core::mem::size_of::<Self>() {
            return Err(ErrorCode::GeneralError);
        }

        Ok(unsafe { core::ptr::read_unaligned(bytes.as_ptr() as *const Self) })
    }
}

// Plaintext in auth token
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct TokenDataPlain {
    pub challenge: [u8; AUTH_TOKEN_CHALLENGE_LEN],
    pub time: u64,
    pub auth_trust_level: AuthTrustLevel,
    pub auth_type: AuthType,
    pub schedule_mode: i32,
    pub security_level: AuthSecurityLevel,
    pub token_type: i32,
}

// Ciphertext in auth token
#[repr(C, packed)]
#[derive(Debug, Copy, Clone, PartialEq)]
pub struct TokenDataToEncrypt {
    user_id: i32,
    secure_uid: u64,
    enrolled_id: u64,
    credential_id: u64,
    collector_udid: Udid,
    verifier_udid: Udid,
}
