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
    CompanionPreIssueTokenInputFfi, CompanionPreIssueTokenOutputFfi,
    CompanionProcessIssueTokenInputFfi, CompanionProcessIssueTokenOutputFfi, DataArray1024Ffi,
};
use crate::jobs::companion_db_helper;
use crate::jobs::message_crypto;
use crate::traits::companion_db_manager::CompanionDbManagerRegistry;
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::db_manager::HostTokenInfo;
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, log_i, p, Box, Vec};

use crate::traits::companion_request_manager::{
    CompanionRequest, CompanionRequestInput, CompanionRequestOutput,
};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct PreIssueParam {
    pub salt: [u8; HKDF_SALT_SIZE],
    pub challenge: u64,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct CompanionDeviceIssueTokenRequest {
    pub request_id: i32,
    pub binding_id: i32,
    pub pre_issue_param: PreIssueParam,
    pub token: Vec<u8>,
    pub atl: AuthTrustLevel,
    pub session_key: Vec<u8>,
}

impl CompanionDeviceIssueTokenRequest {
    pub fn new(input: &CompanionPreIssueTokenInputFfi) -> Result<Self, ErrorCode> {
        let mut challenge = [0u8; CHALLENGE_LEN];
        CryptoEngineRegistry::get()
            .secure_random(&mut challenge)
            .map_err(|_| {
                log_e!("secure_random fail");
                ErrorCode::GeneralError
            })?;

        Ok(CompanionDeviceIssueTokenRequest {
            request_id: input.request_id,
            binding_id: input.binding_id,
            pre_issue_param: PreIssueParam {
                salt: [0u8; HKDF_SALT_SIZE],
                challenge: u64::from_ne_bytes(challenge),
            },
            token: Vec::new(),
            atl: AuthTrustLevel::Atl0,
            session_key: Vec::new(),
        })
    }

    fn get_request_id(&self) -> i32 {
        self.request_id
    }

    fn parse_pre_issue_request_data(&mut self, message_data: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(message_data).map_err(|e| p!(e))?;
        let salt = attribute
            .get_u8_slice(AttributeKey::AttrSalt)
            .map_err(|e| p!(e))?;
        self.pre_issue_param.salt.copy_from_slice(salt);
        Ok(())
    }

    fn parse_begin_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(sec_message).map_err(|e| p!(e))?;
        if let Ok(value) = attribute.get_u8_slice(AttributeKey::AttrMessage) {
            if let Ok(()) = self.parse_pre_issue_request_data(value) {
                return Ok(());
            }
        }

        log_e!("No valid pre-issue message found in sec_message");
        Err(ErrorCode::GeneralError)
    }

    fn create_begin_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let session_key =
            companion_db_helper::get_session_key(self.binding_id, &self.pre_issue_param.salt)?;
        self.session_key = session_key.clone();

        let mut encrypt_attribute = Attribute::new();
        encrypt_attribute.set_u64(AttributeKey::AttrChallenge, self.pre_issue_param.challenge);

        let (encrypt_data, tag, iv) = message_crypto::encrypt_sec_message(
            encrypt_attribute.to_bytes()?.as_slice(),
            &session_key,
        )
        .map_err(|e| p!(e))?;

        let mut attribute = Attribute::new();
        attribute.set_u8_slice(AttributeKey::AttrTag, &tag);
        attribute.set_u8_slice(AttributeKey::AttrIv, &iv);
        attribute.set_u8_slice(AttributeKey::AttrEncryptData, &encrypt_data);

        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes()?.as_slice());

        Ok(final_attribute.to_bytes()?)
    }

    fn parse_issue_token_data(&mut self, message_data: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(message_data).map_err(|e| p!(e))?;
        let tag = attribute
            .get_u8_slice(AttributeKey::AttrTag)
            .map_err(|e| p!(e))?;
        let iv = attribute
            .get_u8_slice(AttributeKey::AttrIv)
            .map_err(|e| p!(e))?;
        let encrypt_data = attribute
            .get_u8_slice(AttributeKey::AttrEncryptData)
            .map_err(|e| p!(e))?;

        let decrypt_data =
            message_crypto::decrypt_sec_message(encrypt_data, &self.session_key, tag, iv)
                .map_err(|e| p!(e))?;
        let decrypt_attribute = Attribute::try_from_bytes(&decrypt_data).map_err(|e| p!(e))?;

        let challenge = decrypt_attribute
            .get_u64(AttributeKey::AttrChallenge)
            .map_err(|e| p!(e))?;
        if challenge != self.pre_issue_param.challenge {
            log_e!("Challenge verification failed");
            return Err(ErrorCode::GeneralError);
        }

        let token = decrypt_attribute
            .get_u8_slice(AttributeKey::AttrToken)
            .map_err(|e| p!(e))?;
        let atl_value = decrypt_attribute
            .get_i32(AttributeKey::AttrAuthTrustLevel)
            .map_err(|e| p!(e))?;

        self.token = token.to_vec();
        self.atl = AuthTrustLevel::try_from(atl_value).map_err(|_| {
            log_e!("Invalid ATL value: {}", atl_value);
            ErrorCode::GeneralError
        })?;

        Ok(())
    }

    fn parse_end_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(sec_message).map_err(|e| p!(e))?;
        if let Ok(value) = attribute.get_u8_slice(AttributeKey::AttrMessage) {
            if let Ok(()) = self.parse_issue_token_data(value) {
                return Ok(());
            }
        }

        log_e!("No valid issue token message found in sec_message");
        Err(ErrorCode::GeneralError)
    }

    fn create_end_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let mut attribute = Attribute::new();
        attribute.set_i32(AttributeKey::AttrResultCode, 0);
        let mut final_attribute = Attribute::new();
        final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes()?.as_slice());
        Ok(final_attribute.to_bytes()?)
    }

    fn store_token(&self) -> Result<(), ErrorCode> {
        let token_info = HostTokenInfo {
            token: self.token.clone(),
            atl: self.atl,
        };

        CompanionDbManagerRegistry::get_mut().write_token_db(self.binding_id, &token_info)?;
        Ok(())
    }
}

impl CompanionRequest for CompanionDeviceIssueTokenRequest {
    fn get_request_id(&self) -> i32 {
        self.get_request_id()
    }

    fn prepare(
        &mut self,
        _input: CompanionRequestInput,
    ) -> Result<CompanionRequestOutput, ErrorCode> {
        log_e!("CompanionDeviceIssueTokenRequest prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode> {
        log_i!("CompanionDeviceIssueTokenRequest begin start");
        let CompanionRequestInput::IssueTokenBegin(ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        self.parse_begin_sec_message(ffi_input.sec_message.as_slice())?;

        let sec_message = self.create_begin_sec_message()?;
        Ok(CompanionRequestOutput::IssueTokenBegin(
            CompanionPreIssueTokenOutputFfi {
                sec_message: DataArray1024Ffi::try_from(sec_message).map_err(|e| p!(e))?,
            },
        ))
    }

    fn end(&mut self, input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode> {
        log_i!("CompanionDeviceIssueTokenRequest end start");
        let CompanionRequestInput::IssueTokenEnd(ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        self.parse_end_sec_message(ffi_input.sec_message.as_slice())?;

        let sec_message = self.create_end_sec_message()?;
        self.store_token()?;

        companion_db_helper::update_host_device_token_valid_flag(self.binding_id, true)?;
        Ok(CompanionRequestOutput::IssueTokenEnd(
            CompanionProcessIssueTokenOutputFfi {
                sec_message: DataArray1024Ffi::try_from(sec_message).map_err(|e| p!(e))?,
            },
        ))
    }
}
