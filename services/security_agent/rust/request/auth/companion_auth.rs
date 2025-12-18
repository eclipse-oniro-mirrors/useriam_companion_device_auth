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
use crate::entry::companion_device_auth_ffi::{
    CompanionBeginDelegateAuthInputFfi, CompanionBeginDelegateAuthOutputFfi,
    CompanionEndDelegateAuthInputFfi, CompanionEndDelegateAuthOutputFfi,
    CompanionProcessTokenAuthInputFfi, CompanionProcessTokenAuthOutputFfi, DataArray1024Ffi,
};
use crate::jobs::companion_db_helper;
use crate::jobs::message_crypto;
use crate::traits::companion_db_manager::CompanionDbManagerRegistry;
use crate::traits::companion_request_manager::{
    CompanionRequest, CompanionRequestInput, CompanionRequestOutput,
};
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::db_manager::HostTokenInfo;
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, log_i, p, Box, Vec};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct CompanionTokenAuthRequest {
    pub binding_id: i32,
    pub challenge: u64,
    pub salt: [u8; HKDF_SALT_SIZE],
}

impl CompanionTokenAuthRequest {
    pub fn new(input: &CompanionProcessTokenAuthInputFfi) -> Result<Self, ErrorCode> {
        Ok(CompanionTokenAuthRequest {
            binding_id: input.binding_id,
            challenge: 0,
            salt: [0u8; HKDF_SALT_SIZE],
        })
    }

    fn get_request_id(&self) -> i32 {
        self.binding_id
    }

    fn parse_device_auth_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(sec_message).map_err(|e| p!(e))?;
        let salt = attribute
            .get_u8_slice(AttributeKey::AttrSalt)
            .map_err(|e| p!(e))?;
        let tag = attribute
            .get_u8_slice(AttributeKey::AttrTag)
            .map_err(|e| p!(e))?;
        let iv = attribute
            .get_u8_slice(AttributeKey::AttrIv)
            .map_err(|e| p!(e))?;
        let encrypt_data = attribute
            .get_u8_slice(AttributeKey::AttrEncryptData)
            .map_err(|e| p!(e))?;

        self.salt.copy_from_slice(salt);
        let session_key = companion_db_helper::get_session_key(self.binding_id, &self.salt)?;
        let decrypt_data = message_crypto::decrypt_sec_message(encrypt_data, &session_key, tag, iv)
            .map_err(|e| p!(e))?;
        let decrypt_attribute = Attribute::try_from_bytes(&decrypt_data).map_err(|e| p!(e))?;

        let challenge = decrypt_attribute
            .get_u64(AttributeKey::AttrChallenge)
            .map_err(|e| p!(e))?;
        self.challenge = challenge;
        Ok(())
    }

    fn parse_begin_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(sec_message).map_err(|e| p!(e))?;
        if let Ok(value) = attribute.get_u8_slice(AttributeKey::AttrMessage) {
            if let Ok(()) = self.parse_device_auth_message(value) {
                return Ok(());
            }
        }

        log_e!("No valid auth message found in sec_message");
        Err(ErrorCode::GeneralError)
    }

    fn create_begin_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let token_info = CompanionDbManagerRegistry::get_mut()
            .read_token_db(self.binding_id)
            .map_err(|e| p!(e))?;
        let hmac = CryptoEngineRegistry::get()
            .hmac_sha256(&token_info.token, &self.challenge.to_ne_bytes())
            .map_err(|e| p!(e))?;

        let mut attribute = Attribute::new();
        attribute.set_u8_slice(AttributeKey::AttrHmac, &hmac);

        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes()?.as_slice());
        Ok(final_attribute.to_bytes()?)
    }
}

impl CompanionRequest for CompanionTokenAuthRequest {
    fn get_request_id(&self) -> i32 {
        self.get_request_id()
    }

    fn prepare(
        &mut self,
        _input: CompanionRequestInput,
    ) -> Result<CompanionRequestOutput, ErrorCode> {
        log_e!("CompanionTokenAuthRequest prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode> {
        log_i!("CompanionTokenAuthRequest begin start");
        let CompanionRequestInput::TokenAuthBegin(ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        self.parse_begin_sec_message(ffi_input.sec_message.as_slice())?;
        let sec_message = self.create_begin_sec_message()?;

        Ok(CompanionRequestOutput::TokenAuthBegin(
            CompanionProcessTokenAuthOutputFfi {
                sec_message: DataArray1024Ffi::try_from(sec_message).map_err(|_| {
                    log_e!("sec_message try from fail");
                    ErrorCode::GeneralError
                })?,
            },
        ))
    }

    fn end(&mut self, _input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode> {
        log_i!("CompanionTokenAuthRequest end start");
        Ok(CompanionRequestOutput::TokenAuthEnd(
            CompanionProcessTokenAuthOutputFfi::default(),
        ))
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct CompanionDelegateAuthRequest {
    pub request_id: i32,
    pub binding_id: i32,
    pub challenge: u64,
    pub atl: AuthTrustLevel,
    pub auth_type: i32,
    pub salt: [u8; HKDF_SALT_SIZE],
    pub session_key: Vec<u8>,
}

impl CompanionDelegateAuthRequest {
    pub fn new(input: &CompanionBeginDelegateAuthInputFfi) -> Result<Self, ErrorCode> {
        Ok(CompanionDelegateAuthRequest {
            request_id: input.request_id,
            binding_id: input.binding_id,
            challenge: 0,
            atl: AuthTrustLevel::Atl2,
            auth_type: 1,
            salt: [0u8; HKDF_SALT_SIZE],
            session_key: Vec::new(),
        })
    }

    fn get_request_id(&self) -> i32 {
        self.request_id
    }

    fn parse_begin_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(sec_message).map_err(|e| p!(e))?;
        let message_data = attribute
            .get_u8_slice(AttributeKey::AttrMessage)
            .map_err(|e| p!(e))?;

        let message_attribute = Attribute::try_from_bytes(message_data).map_err(|e| p!(e))?;
        let salt = message_attribute
            .get_u8_slice(AttributeKey::AttrSalt)
            .map_err(|e| p!(e))?;
        let tag = message_attribute
            .get_u8_slice(AttributeKey::AttrTag)
            .map_err(|e| p!(e))?;
        let iv = message_attribute
            .get_u8_slice(AttributeKey::AttrIv)
            .map_err(|e| p!(e))?;
        let encrypt_data = message_attribute
            .get_u8_slice(AttributeKey::AttrEncryptData)
            .map_err(|e| p!(e))?;

        self.salt.copy_from_slice(salt);
        let session_key = companion_db_helper::get_session_key(self.binding_id, &self.salt)?;
        self.session_key = session_key.clone();

        let decrypt_data = message_crypto::decrypt_sec_message(encrypt_data, &session_key, tag, iv)
            .map_err(|e| p!(e))?;
        let decrypt_attribute = Attribute::try_from_bytes(&decrypt_data).map_err(|e| p!(e))?;
        let challenge = decrypt_attribute
            .get_u64(AttributeKey::AttrChallenge)
            .map_err(|e| p!(e))?;
        let atl_value = decrypt_attribute
            .get_i32(AttributeKey::AttrAuthTrustLevel)
            .map_err(|e| p!(e))?;
        self.challenge = challenge;
        self.atl = AuthTrustLevel::try_from(atl_value).map_err(|_| {
            log_e!("Invalid ATL value: {}", atl_value);
            ErrorCode::GeneralError
        })?;

        Ok(())
    }

    fn create_end_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let mut encrypt_attribute = Attribute::new();
        encrypt_attribute.set_u64(AttributeKey::AttrChallenge, self.challenge);
        encrypt_attribute.set_i32(AttributeKey::AttrType, self.auth_type);
        encrypt_attribute.set_i32(AttributeKey::AttrAuthTrustLevel, self.atl as i32); // todo: hj

        let (encrypt_data, tag, iv) = message_crypto::encrypt_sec_message(
            encrypt_attribute.to_bytes()?.as_slice(),
            &self.session_key,
        )
        .map_err(|e| p!(e))?;

        let mut attribute = Attribute::new();
        attribute.set_u8_slice(AttributeKey::AttrSalt, &self.salt);
        attribute.set_u8_slice(AttributeKey::AttrTag, &tag);
        attribute.set_u8_slice(AttributeKey::AttrIv, &iv);
        attribute.set_u8_slice(AttributeKey::AttrEncryptData, &encrypt_data);

        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes()?.as_slice());

        Ok(final_attribute.to_bytes()?)
    }
}

impl CompanionRequest for CompanionDelegateAuthRequest {
    fn get_request_id(&self) -> i32 {
        self.get_request_id()
    }

    fn prepare(
        &mut self,
        _input: CompanionRequestInput,
    ) -> Result<CompanionRequestOutput, ErrorCode> {
        log_e!("CompanionDelegateAuthRequest prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode> {
        log_i!("CompanionDelegateAuthRequest begin start");
        let CompanionRequestInput::DelegateAuthBegin(ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        self.parse_begin_sec_message(ffi_input.sec_message.as_slice())?;

        Ok(CompanionRequestOutput::DelegateAuthBegin(
            CompanionBeginDelegateAuthOutputFfi {
                challenge: self.challenge,
                atl: self.atl as i32,
            },
        ))
    }

    fn end(&mut self, input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode> {
        log_i!("CompanionDelegateAuthRequest end start");
        let CompanionRequestInput::DelegateAuthEnd(_ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        // todo: hj校验 auth_token, 获取 atl, 更新 self.atl
        let sec_message = self.create_end_sec_message()?;
        companion_db_helper::update_host_device_last_used_time(self.binding_id)?;

        Ok(CompanionRequestOutput::DelegateAuthEnd(
            CompanionEndDelegateAuthOutputFfi {
                sec_message: DataArray1024Ffi::try_from(sec_message).map_err(|_| {
                    log_e!("sec_message try from fail");
                    ErrorCode::GeneralError
                })?,
            },
        ))
    }
}
