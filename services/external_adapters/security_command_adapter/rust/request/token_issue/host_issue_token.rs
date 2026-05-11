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

use crate::common::constants::{AuthTrustLevel, AuthType, Capability, ErrorCode, ProcessorType, HKDF_SALT_SIZE};
use crate::entry::companion_device_auth_ffi::HostPreIssueTokenInputFfi;
use crate::entry::companion_device_auth_ffi::PROPERTY_MODE_UNFREEZE;
use crate::jobs::companion_device_db_helper;
use crate::request::jobs::common_message::SecIssueToken;
use crate::request::jobs::token_helper;
use crate::request::jobs::token_helper::DeviceTokenInfo;
use crate::request::token_issue::token_issue_message::{
    FwkIssueTokenRequest, SecIssueTokenReply, SecPreIssueReply, SecPreIssueRequest,
};
use crate::traits::companion_device_db_manager::CompanionDeviceDbManagerRegistry;
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::request_manager::{Request, RequestParam};
use crate::{log_e, log_i, Box, Vec};
use crate::traits::log_trace::RustFileId;
pub(crate) const FILE_ID: u16 = RustFileId::HostIssueToken as u16;
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
    pub fn new(input: &HostPreIssueTokenInputFfi) -> Result<Self, ErrorCode> {
        let mut salt = [0u8; HKDF_SALT_SIZE];
        CryptoEngineRegistry::get().secure_random(&mut salt).map_err(|_| {
            log_e!("secure_random salt fail");
            ErrorCode::GeneralError
        })?;

        Ok(HostDeviceIssueTokenRequest {
            token_issue_param: TokenIssueParam { request_id: input.request_id, template_id: input.template_id },
            token_infos: Vec::new(),
            salt,
            atl: AuthTrustLevel::Atl0,
        })
    }

    fn get_request_id(&self) -> i32 {
        self.token_issue_param.request_id
    }

    fn decode_fwk_token_issue_request(&mut self, fwk_message: &[u8]) -> Result<(), ErrorCode> {
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

    fn encode_sec_token_pre_issue_request(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let pre_issue_request = Box::new(SecPreIssueRequest { salt: self.salt });
        let mut output = Vec::new();
        let capability_infos = CompanionDeviceDbManagerRegistry::get_mut()
            .read_device_capability_info(self.token_issue_param.template_id)?;
        for capability_info in capability_infos {
            output.extend(pre_issue_request.encode(capability_info.processor_type)?);
        }
        Ok(output)
    }

    fn decode_sec_pre_issue_reply_message(
        &mut self,
        processor_type: ProcessorType,
        sec_message: &[u8],
    ) -> Result<(), ErrorCode> {
        let output = SecPreIssueReply::decode(sec_message, processor_type)?;
        self.token_infos.push(token_helper::generate_token(processor_type, output.challenge, self.atl)?);
        Ok(())
    }

    fn decode_sec_pre_issue_reply(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let capability_infos = CompanionDeviceDbManagerRegistry::get_mut()
            .read_device_capability_info(self.token_issue_param.template_id)?;
        for capability_info in capability_infos {
            if let Err(e) = self.decode_sec_pre_issue_reply_message(capability_info.processor_type, sec_message) {
                log_e!(
                    "parse pre issue token reply message fail: processor_type: {:?}, result: {:?}",
                    capability_info.processor_type,
                    e
                );
                return Err(ErrorCode::GeneralError);
            }
        }

        if self.token_infos.is_empty() {
            log_e!("no pre issue token parameters found");
            return Err(ErrorCode::GeneralError);
        }

        Ok(())
    }

    fn encode_sec_token_issue_request(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let mut output = Vec::new();
        for token_info in &self.token_infos {
            let session_key = companion_device_db_helper::get_session_key(
                self.token_issue_param.template_id,
                token_info.processor_type,
                &self.salt,
            )?;

            let issue_token = SecIssueToken {
                challenge: token_info.challenge,
                atl: self.atl as i32,
                token: token_info.token.clone(),
            };

            output.extend(issue_token.encrypt_issue_token(&self.salt, token_info.processor_type, &session_key)?);
        }

        Ok(output)
    }

    fn decode_issue_token_reply_message(
        &mut self,
        processor_type: ProcessorType,
        sec_message: &[u8],
    ) -> Result<(), ErrorCode> {
        let output = SecIssueTokenReply::decode(sec_message, processor_type)?;
        if output.result != ErrorCode::Success as i32 {
            log_e!("issue token returned error: {}", output.result);
            return Err(ErrorCode::GeneralError);
        }

        Ok(())
    }

    fn decode_issue_token_reply(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let processor_types: Vec<ProcessorType> = self.token_infos.iter().map(|param| param.processor_type).collect();
        for processor_type in processor_types {
            if let Err(e) = self.decode_issue_token_reply_message(processor_type, sec_message) {
                log_e!("parse issue token reply message fail: processor_type: {:?}, result: {:?}", processor_type, e);
                return Err(ErrorCode::GeneralError);
            }
        }

        Ok(())
    }

    fn store_token(&self) -> Result<(), ErrorCode> {
        if self.token_infos.is_empty() {
            log_e!("token info is null");
            return Err(ErrorCode::GeneralError);
        }
        token_helper::add_companion_device_token(self.token_issue_param.template_id, &self.token_infos)?;
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

        companion_device_db_helper::check_device_capability(self.token_issue_param.template_id, Capability::TokenAuth)?;

        self.decode_fwk_token_issue_request(ffi_input.fwk_message.as_slice()?)?;
        let sec_message = self.encode_sec_token_pre_issue_request()?;
        ffi_output.sec_message.copy_from_vec(&sec_message)?;
        Ok(())
    }

    fn begin(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("HostDeviceIssueTokenRequest begin start");
        let RequestParam::HostIssueTokenBegin(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.decode_sec_pre_issue_reply(ffi_input.sec_message.as_slice()?)?;
        let sec_message = self.encode_sec_token_issue_request()?;
        ffi_output.sec_message.copy_from_vec(&sec_message)?;
        Ok(())
    }

    fn end(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("HostDeviceIssueTokenRequest end start");
        let RequestParam::HostIssueTokenEnd(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.decode_issue_token_reply(ffi_input.sec_message.as_slice()?)?;
        self.store_token()?;
        // Calculate the max ATL from token_infos
        let max_atl = self.token_infos.iter().map(|info| info.atl as i32).max().unwrap_or(self.atl as i32);
        ffi_output.atl = max_atl;
        Ok(())
    }
}
