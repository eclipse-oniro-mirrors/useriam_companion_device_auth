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
    CompanionPreIssueTokenInputFfi, CompanionPreIssueTokenOutputFfi, CompanionProcessIssueTokenInputFfi,
    CompanionProcessIssueTokenOutputFfi, DataArray1024Ffi,
};
use crate::jobs::companion_db_helper;
use crate::jobs::message_crypto;
use crate::request::jobs::common_message::{SecCommonReply, SecCommonRequest, SecIssueToken};
use crate::request::token_issue::token_issue_message::SecIssueTokenReply;
use crate::request::token_issue::token_issue_message::SecPreIssueRequest;
use crate::traits::companion_db_manager::CompanionDbManagerRegistry;
use crate::traits::companion_request_manager::{CompanionRequest, CompanionRequestInput, CompanionRequestOutput};
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::db_manager::HostTokenInfo;
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, log_i, p, Box, Vec};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct PreIssueParam {
    pub salt: [u8; HKDF_SALT_SIZE],
    pub challenge: u64,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct TokenInfo {
    pub token: Vec<u8>,
    pub atl: AuthTrustLevel,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct CompanionDeviceIssueTokenRequest {
    pub request_id: i32,
    pub binding_id: i32,
    pub pre_issue_param: PreIssueParam,
    pub token_info: TokenInfo,
    pub session_key: Vec<u8>,
}

impl CompanionDeviceIssueTokenRequest {
    pub fn new(input: &CompanionPreIssueTokenInputFfi) -> Result<Self, ErrorCode> {
        let mut challenge = [0u8; CHALLENGE_LEN];
        CryptoEngineRegistry::get().secure_random(&mut challenge).map_err(|_| {
            log_e!("secure_random fail");
            ErrorCode::GeneralError
        })?;

        Ok(CompanionDeviceIssueTokenRequest {
            request_id: input.request_id,
            binding_id: input.binding_id,
            pre_issue_param: PreIssueParam { salt: [0u8; HKDF_SALT_SIZE], challenge: u64::from_ne_bytes(challenge) },
            token_info: TokenInfo { token: Vec::new(), atl: AuthTrustLevel::Atl0 },
            session_key: Vec::new(),
        })
    }

    fn get_request_id(&self) -> i32 {
        self.request_id
    }

    fn parse_pre_issue_request(&mut self, device_type: DeviceType, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let output = SecPreIssueRequest::decode(sec_message, device_type)?;
        self.pre_issue_param.salt = output.salt;
        Ok(())
    }

    fn parse_begin_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        if let Err(e) = self.parse_pre_issue_request(DeviceType::None, sec_message) {
            log_e!("parse pre-issue request message fail: {:?}", e);
            return Err(ErrorCode::GeneralError);
        }

        Ok(())
    }

    fn create_begin_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let session_key = companion_db_helper::get_session_key(self.binding_id, &self.pre_issue_param.salt)?;
        self.session_key = session_key.clone();

        let mut encrypt_attribute = Attribute::new();
        encrypt_attribute.set_u64(AttributeKey::AttrChallenge, self.pre_issue_param.challenge);

        let (encrypt_data, tag, iv) =
            message_crypto::encrypt_sec_message(encrypt_attribute.to_bytes()?.as_slice(), &session_key)
                .map_err(|e| p!(e))?;

        let sec_pre_issue_reply = SecCommonReply { tag: tag, iv: iv, encrypt_data: encrypt_data };

        let output = sec_pre_issue_reply.encode(DeviceType::None)?;
        Ok(output)
    }

    fn parse_issue_token_request(&mut self, device_type: DeviceType, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let issue_token = SecIssueToken::decrypt_issue_token(&sec_message, device_type, &self.session_key)?;

        if issue_token.challenge != self.pre_issue_param.challenge {
            log_e!("Challenge verification failed");
            return Err(ErrorCode::GeneralError);
        }

        self.token_info = TokenInfo {
            token: issue_token.token.clone(),
            atl: AuthTrustLevel::try_from(issue_token.atl).map_err(|_| {
                log_e!("Invalid ATL value: {}", issue_token.atl);
                ErrorCode::GeneralError
            })?,
        };
        Ok(())
    }

    fn parse_end_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        if let Err(e) = self.parse_issue_token_request(DeviceType::None, sec_message) {
            log_e!("parse issue token request message fail: {:?}", e);
            return Err(ErrorCode::GeneralError);
        }

        Ok(())
    }

    fn create_end_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let issue_token_reply = SecIssueTokenReply { result: 0 };

        let output = issue_token_reply.encode(DeviceType::None)?;
        Ok(output)
    }

    fn store_token(&self) -> Result<(), ErrorCode> {
        let token_info = HostTokenInfo { token: self.token_info.token.clone(), atl: self.token_info.atl };

        CompanionDbManagerRegistry::get_mut().write_device_token(self.binding_id, &token_info)?;
        Ok(())
    }
}

impl CompanionRequest for CompanionDeviceIssueTokenRequest {
    fn get_request_id(&self) -> i32 {
        self.get_request_id()
    }

    fn prepare(&mut self, _input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode> {
        log_e!("CompanionDeviceIssueTokenRequest prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode> {
        log_i!("CompanionDeviceIssueTokenRequest begin start");
        let CompanionRequestInput::IssueTokenBegin(ffi_input) = input else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.parse_begin_sec_message(ffi_input.sec_message.as_slice())?;

        let sec_message = self.create_begin_sec_message()?;
        Ok(CompanionRequestOutput::IssueTokenBegin(CompanionPreIssueTokenOutputFfi {
            sec_message: DataArray1024Ffi::try_from(sec_message).map_err(|e| p!(e))?,
        }))
    }

    fn end(&mut self, input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode> {
        log_i!("CompanionDeviceIssueTokenRequest end start");
        let CompanionRequestInput::IssueTokenEnd(ffi_input) = input else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.parse_end_sec_message(ffi_input.sec_message.as_slice())?;

        let sec_message = self.create_end_sec_message()?;
        self.store_token()?;

        Ok(CompanionRequestOutput::IssueTokenEnd(CompanionProcessIssueTokenOutputFfi {
            sec_message: DataArray1024Ffi::try_from(sec_message).map_err(|e| p!(e))?,
        }))
    }
}
