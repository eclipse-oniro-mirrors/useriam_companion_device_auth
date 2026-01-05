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
use crate::entry::companion_device_auth_ffi::PROPERTY_MODE_UNFREEZE;
use crate::entry::companion_device_auth_ffi::{
    CompanionBeginObtainTokenInputFfi, CompanionBeginObtainTokenOutputFfi, CompanionEndObtainTokenInputFfi,
    CompanionEndObtainTokenOutputFfi, DataArray1024Ffi,
};
use crate::jobs::companion_db_helper;
use crate::jobs::message_crypto;
use crate::request::jobs::common_message::{SecCommonReply, SecCommonRequest, SecIssueToken};
use crate::request::token_obtain::token_obtain_message::{FwkObtainTokenRequest, SecPreObtainTokenRequest};
use crate::traits::companion_db_manager::CompanionDbManagerRegistry;
use crate::traits::companion_request_manager::{CompanionRequest, CompanionRequestInput, CompanionRequestOutput};
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::db_manager::HostTokenInfo;
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::utils::message_codec::MessageCodec;
use crate::utils::message_codec::MessageSignParam;
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, log_i, p, Box, Vec};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct ObtainParam {
    pub salt: [u8; HKDF_SALT_SIZE],
    pub challenge: u64,
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct CompanionDeviceObtainTokenRequest {
    pub request_id: i32,
    pub binding_id: i32,
    pub obtain_param: ObtainParam,
    pub token: Vec<u8>,
    pub atl: AuthTrustLevel,
    pub session_key: Vec<u8>,
}

impl CompanionDeviceObtainTokenRequest {
    pub fn new(input: &CompanionBeginObtainTokenInputFfi) -> Result<Self, ErrorCode> {
        Ok(CompanionDeviceObtainTokenRequest {
            request_id: input.request_id,
            binding_id: input.binding_id,
            obtain_param: ObtainParam { salt: [0u8; HKDF_SALT_SIZE], challenge: 0 },
            token: Vec::new(),
            atl: AuthTrustLevel::Atl0,
            session_key: Vec::new(),
        })
    }

    fn get_request_id(&self) -> i32 {
        self.request_id
    }

    fn parse_begin_fwk_message(&mut self, fwk_message: &[u8]) -> Result<(), ErrorCode> {
        let output = FwkObtainTokenRequest::decode(fwk_message)?;

        if output.property_mode != PROPERTY_MODE_UNFREEZE {
            log_e!("property_mode is not unfreeze: {}", output.property_mode);
            return Err(ErrorCode::GeneralError);
        }

        if output.auth_type != AuthType::CompanionDevice as u32 {
            log_e!("auth_type is not companionDevice: {}", output.auth_type);
            return Err(ErrorCode::GeneralError);
        }

        self.atl = AuthTrustLevel::try_from(output.atl).map_err(|_| {
            log_e!("Invalid ATL value: {}", output.atl);
            ErrorCode::GeneralError
        })?;
        Ok(())
    }

    fn parse_obtain_token_request(&mut self, device_type: DeviceType, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let output = SecPreObtainTokenRequest::decode(sec_message, device_type)?;
        self.obtain_param.salt = output.salt;
        self.obtain_param.challenge = output.challenge;
        Ok(())
    }

    fn parse_begin_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        if let Err(e) = self.parse_obtain_token_request(DeviceType::None, sec_message) {
            log_e!("parse obtain token request message fail: {:?}", e);
            return Err(ErrorCode::GeneralError);
        }

        Ok(())
    }

    fn create_begin_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let session_key = companion_db_helper::get_session_key(self.binding_id, &self.obtain_param.salt)?;
        self.session_key = session_key.clone();

        let mut encrypt_attribute = Attribute::new();
        encrypt_attribute.set_u64(AttributeKey::AttrChallenge, self.obtain_param.challenge);
        encrypt_attribute.set_i32(AttributeKey::AttrAuthTrustLevel, self.atl as i32);

        let (encrypt_data, tag, iv) =
            message_crypto::encrypt_sec_message(encrypt_attribute.to_bytes()?.as_slice(), &session_key)
                .map_err(|e| p!(e))?;

        let obtain_token_request =
            SecCommonRequest { salt: self.obtain_param.salt, tag: tag, iv: iv, encrypt_data: encrypt_data };

        let output = obtain_token_request.encode(DeviceType::None)?;
        Ok(output)
    }

    fn parse_obtain_token_reply(&mut self, device_type: DeviceType, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let issue_token = SecIssueToken::decrypt_issue_token(sec_message, device_type, &self.session_key)?;

        if issue_token.challenge != self.obtain_param.challenge {
            log_e!("Challenge verification failed");
            return Err(ErrorCode::GeneralError);
        }

        self.token = issue_token.token.to_vec();
        self.atl = AuthTrustLevel::try_from(issue_token.atl).map_err(|_| {
            log_e!("Invalid ATL value: {}", issue_token.atl);
            ErrorCode::GeneralError
        })?;

        Ok(())
    }

    fn parse_end_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        if let Err(e) = self.parse_obtain_token_reply(DeviceType::None, sec_message) {
            log_e!("parse obtain token reply message fail: {:?}", e);
            return Err(ErrorCode::GeneralError);
        }

        Ok(())
    }

    fn store_token(&self) -> Result<(), ErrorCode> {
        let token_info = HostTokenInfo { token: self.token.clone(), atl: self.atl };

        CompanionDbManagerRegistry::get_mut().write_device_token(self.binding_id, &token_info)?;
        Ok(())
    }
}

impl CompanionRequest for CompanionDeviceObtainTokenRequest {
    fn get_request_id(&self) -> i32 {
        self.get_request_id()
    }

    fn prepare(&mut self, _input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode> {
        log_e!("CompanionDeviceObtainTokenRequest prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode> {
        log_i!("CompanionDeviceObtainTokenRequest begin start");
        let CompanionRequestInput::ObtainTokenBegin(ffi_input) = input else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.parse_begin_fwk_message(ffi_input.fwk_message.as_slice())?;
        self.parse_begin_sec_message(ffi_input.sec_message.as_slice())?;

        let sec_message = self.create_begin_sec_message()?;
        Ok(CompanionRequestOutput::ObtainTokenBegin(CompanionBeginObtainTokenOutputFfi {
            sec_message: DataArray1024Ffi::try_from(sec_message).map_err(|e| p!(e))?,
        }))
    }

    fn end(&mut self, input: CompanionRequestInput) -> Result<CompanionRequestOutput, ErrorCode> {
        log_i!("CompanionDeviceObtainTokenRequest end start");
        let CompanionRequestInput::ObtainTokenEnd(ffi_input) = input else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.parse_end_sec_message(ffi_input.sec_message.as_slice())?;
        self.store_token()?;

        Ok(CompanionRequestOutput::ObtainTokenEnd(CompanionEndObtainTokenOutputFfi::default()))
    }
}
