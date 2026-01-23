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
    DataArray1024Ffi, HostBeginIssueTokenInputFfi, HostBeginIssueTokenOutputFfi, HostEndIssueTokenInputFfi,
    HostEndIssueTokenOutputFfi, HostPreIssueTokenInputFfi, HostPreIssueTokenOutputFfi,
};
use crate::jobs::host_db_helper;
use crate::jobs::message_crypto;
use crate::request::jobs::common_message::{SecCommonReply, SecCommonRequest, SecIssueToken};
use crate::request::jobs::token_helper;
use crate::request::jobs::token_helper::DeviceTokenInfo;
use crate::request::token_issue::token_issue_message::{FwkIssueTokenRequest, SecIssueTokenReply, SecPreIssueRequest};
use crate::traits::crypto_engine::{AesGcmParam, AesGcmResult, CryptoEngineRegistry};
use crate::traits::db_manager::CompanionTokenInfo;
use crate::traits::host_db_manager::HostDbManagerRegistry;
use crate::traits::request_manager::{Request, RequestParam};
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::utils::message_codec::{MessageCodec, MessageSignParam};
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, log_i, p, Box, Vec};

#[derive(Debug, Clone, PartialEq)]
pub struct TokenIssueParam {
    pub request_id: i32,
    pub template_id: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HostDeviceIssueTokenRequest {
    pub token_issue_param: TokenIssueParam,
    pub token_infos: Vec<DeviceTokenInfo>,
    pub salt: [u8; HKDF_SALT_SIZE],
    pub atl: AuthTrustLevel,
}

impl HostDeviceIssueTokenRequest {
    pub fn new(issue_token_param: &HostPreIssueTokenInputFfi) -> Result<Self, ErrorCode> {
        let mut salt = [0u8; HKDF_SALT_SIZE];
        CryptoEngineRegistry::get().secure_random(&mut salt).map_err(|_| {
            log_e!("secure_random fail");
            ErrorCode::GeneralError
        })?;

        Ok(HostDeviceIssueTokenRequest {
            token_issue_param: TokenIssueParam {
                request_id: issue_token_param.request_id,
                template_id: issue_token_param.template_id,
            },
            token_infos: Vec::new(),
            salt: salt,
            atl: AuthTrustLevel::Atl0,
        })
    }

    fn get_request_id(&self) -> i32 {
        self.token_issue_param.request_id
    }

    fn parse_begin_fwk_message(&mut self, fwk_message: &[u8]) -> Result<(), ErrorCode> {
        let output = FwkIssueTokenRequest::decode(fwk_message)?;
        if output.property_mode != PROPERTY_MODE_UNFREEZE {
            log_e!("property_mode is not unfreeze: {}", output.property_mode);
            return Err(ErrorCode::GeneralError);
        }

        if output.auth_type != AuthType::CompanionDevice as u32 {
            log_e!("auth_type is not companionDevice: {}", output.auth_type);
            return Err(ErrorCode::GeneralError);
        }

        if !output.template_ids.contains(&self.token_issue_param.template_id) {
            log_e!("template_id check fail");
            return Err(ErrorCode::GeneralError);
        }

        self.atl = AuthTrustLevel::try_from(output.atl).map_err(|_| {
            log_e!("Invalid ATL value: {}", output.atl);
            ErrorCode::GeneralError
        })?;
        Ok(())
    }

    fn create_prepare_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let pre_issue_request = SecPreIssueRequest { salt: self.salt };
        let mut output = Vec::new();
        let capability_infos =
            HostDbManagerRegistry::get_mut().read_device_capability_info(self.token_issue_param.template_id)?;
        for capability_info in capability_infos {
            output.extend(pre_issue_request.encode(capability_info.device_type)?);
        }
        Ok(output)
    }

    fn parse_pre_issue_reply(&mut self, device_type: DeviceType, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let output = SecCommonReply::decode(sec_message, device_type)?;

        let session_key = host_db_helper::get_session_key(self.token_issue_param.template_id, device_type, &self.salt)?;
        let decrypt_data =
            message_crypto::decrypt_sec_message(&output.encrypt_data, &session_key, &output.tag, &output.iv)
                .map_err(|e| p!(e))?;
        let decrypt_attribute = Attribute::try_from_bytes(&decrypt_data).map_err(|e| p!(e))?;
        let challenge = decrypt_attribute.get_u64(AttributeKey::AttrChallenge).map_err(|e| p!(e))?;

        let mut token = [0u8; TOKEN_KEY_LEN];
        CryptoEngineRegistry::get().secure_random(&mut token).map_err(|_| {
            log_e!("secure_random fail");
            ErrorCode::GeneralError
        })?;

        let token_info = token_helper::generate_token(device_type, challenge, self.atl)?;
        self.token_infos.push(token_info);
        Ok(())
    }

    fn parse_begin_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let capability_infos =
            HostDbManagerRegistry::get_mut().read_device_capability_info(self.token_issue_param.template_id)?;
        for capability_info in capability_infos {
            if let Err(e) = self.parse_pre_issue_reply(capability_info.device_type, sec_message) {
                log_e!("parse pre issue token reply message fail: {:?}", e);
                return Err(ErrorCode::GeneralError);
            }
        }

        if self.token_infos.is_empty() {
            log_e!("pre issue token parameters found");
            return Err(ErrorCode::GeneralError);
        }

        Ok(())
    }

    fn create_begin_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let mut output = Vec::new();
        for token_info in &self.token_infos {
            let session_key = host_db_helper::get_session_key(
                self.token_issue_param.template_id,
                token_info.device_type,
                &self.salt,
            )?;

            let issue_token = SecIssueToken {
                challenge: token_info.challenge,
                atl: self.atl as i32,
                token: token_info.token.clone(),
            };

            output.extend(issue_token.encrypt_issue_token(&self.salt, token_info.device_type, &session_key)?);
        }

        Ok(output)
    }

    fn parse_issue_token_reply(&mut self, device_type: DeviceType, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let output = SecIssueTokenReply::decode(sec_message, device_type)?;
        if output.result != 0 {
            log_e!("issue token returned error: {}", output.result);
            return Err(ErrorCode::GeneralError);
        }

        Ok(())
    }

    fn parse_end_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        for token_info in self.token_infos.clone() {
            if let Err(e) = self.parse_issue_token_reply(token_info.device_type, sec_message) {
                log_e!("parse issue token replay message fail: {:?}", e);
                return Err(ErrorCode::GeneralError);
            }
        }

        Ok(())
    }

    fn store_token(&self) -> Result<(), ErrorCode> {
        for token_info in &self.token_infos {
            let companion_token = CompanionTokenInfo {
                template_id: self.token_issue_param.template_id,
                device_type: token_info.device_type,
                token: token_info.token.clone(),
                atl: self.atl,
                added_time: TimeKeeperRegistry::get().get_rtc_time().map_err(|e| p!(e))?,
            };
            HostDbManagerRegistry::get_mut().add_token(&companion_token)?;
        }

        Ok(())
    }
}

impl Request for HostDeviceIssueTokenRequest {
    fn get_request_id(&self) -> i32 {
        self.get_request_id()
    }

    fn prepare(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("HostDeviceIssueTokenRequest prepare start");
        let RequestParam::HostIssueTokenPrepare(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.parse_begin_fwk_message(ffi_input.fwk_message.as_slice()?)?;
        let sec_message = self.create_prepare_sec_message()?;
        ffi_output.sec_message = DataArray1024Ffi::try_from(sec_message).map_err(|e| p!(e))?;
        Ok(())
    }

    fn begin(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("HostDeviceIssueTokenRequest begin start");
        let RequestParam::HostIssueTokenBegin(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.parse_begin_sec_message(ffi_input.sec_message.as_slice()?)?;
        let sec_message = self.create_begin_sec_message()?;
        ffi_output.sec_message = DataArray1024Ffi::try_from(sec_message).map_err(|e| p!(e))?;
        Ok(())
    }

    fn end(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("HostDeviceIssueTokenRequest end start");
        let RequestParam::HostIssueTokenEnd(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.parse_end_sec_message(ffi_input.sec_message.as_slice()?)?;
        self.store_token()?;
        ffi_output.atl = self.atl as i32;
        Ok(())
    }
}
