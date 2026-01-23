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
    DataArray1024Ffi, HostProcessObtainTokenInputFfi, HostProcessObtainTokenOutputFfi,
    HostProcessPreObtainTokenInputFfi, HostProcessPreObtainTokenOutputFfi,
};
use crate::jobs::host_db_helper;
use crate::jobs::message_crypto;
use crate::request::jobs::common_message::{SecCommonReply, SecCommonRequest, SecIssueToken};
use crate::request::jobs::token_helper;
use crate::request::jobs::token_helper::DeviceTokenInfo;
use crate::request::token_obtain::token_obtain_message::{FwkObtainTokenRequest, SecPreObtainTokenRequest};
use crate::traits::crypto_engine::{AesGcmParam, AesGcmResult, CryptoEngineRegistry};
use crate::traits::db_manager::CompanionTokenInfo;
use crate::traits::host_db_manager::HostDbManagerRegistry;
use crate::traits::request_manager::{Request, RequestParam};
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::utils::message_codec::{MessageCodec, MessageSignParam};
use crate::utils::{Attribute, AttributeKey};
use crate::vec;
use crate::{log_e, log_i, p, Box, Vec};

#[derive(Debug, Clone, PartialEq)]
pub struct TokenObtainParam {
    pub request_id: i32,
    pub template_id: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HostDeviceObtainTokenRequest {
    pub obtain_param: TokenObtainParam,
    pub token_infos: Vec<DeviceTokenInfo>,
    pub salt: [u8; HKDF_SALT_SIZE],
    pub challenge: u64,
}

impl HostDeviceObtainTokenRequest {
    pub fn new(input: &HostProcessPreObtainTokenInputFfi) -> Result<Self, ErrorCode> {
        let mut salt = [0u8; HKDF_SALT_SIZE];
        CryptoEngineRegistry::get().secure_random(&mut salt).map_err(|_| {
            log_e!("secure_random fail");
            ErrorCode::GeneralError
        })?;
        let mut challenge = [0u8; CHALLENGE_LEN];
        CryptoEngineRegistry::get().secure_random(&mut challenge).map_err(|_| {
            log_e!("secure_random fail");
            ErrorCode::GeneralError
        })?;
        Ok(HostDeviceObtainTokenRequest {
            obtain_param: TokenObtainParam { request_id: input.request_id, template_id: input.template_id },
            token_infos: Vec::new(),
            salt: salt,
            challenge: u64::from_ne_bytes(challenge),
        })
    }

    fn get_request_id(&self) -> i32 {
        self.obtain_param.request_id
    }

    fn create_prepare_sec_message(&self) -> Result<Vec<u8>, ErrorCode> {
        let mut output = Vec::new();
        let obtain_token_request = SecPreObtainTokenRequest { salt: self.salt, challenge: self.challenge };
        let capability_infos =
            HostDbManagerRegistry::get_mut().read_device_capability_info(self.obtain_param.template_id)?;
        for capability_info in capability_infos {
            output.extend(obtain_token_request.encode(capability_info.device_type)?);
        }

        Ok(output)
    }

    fn parse_obtain_token_request(&mut self, device_type: DeviceType, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let output = SecCommonRequest::decode(sec_message, device_type)?;
        let session_key = host_db_helper::get_session_key(self.obtain_param.template_id, device_type, &self.salt)?;
        let decrypt_data =
            message_crypto::decrypt_sec_message(&output.encrypt_data, &session_key, &output.tag, &output.iv)
                .map_err(|e| p!(e))?;
        let decrypt_attribute = Attribute::try_from_bytes(&decrypt_data).map_err(|e| p!(e))?;
        let challenge = decrypt_attribute.get_u64(AttributeKey::AttrChallenge).map_err(|e| p!(e))?;
        if challenge != self.challenge {
            log_e!("Challenge verification failed");
            return Err(ErrorCode::GeneralError);
        }
        let atl_value = decrypt_attribute.get_i32(AttributeKey::AttrAuthTrustLevel).map_err(|e| p!(e))?;
        let atl = AuthTrustLevel::try_from(atl_value).map_err(|_| {
            log_e!("Invalid ATL value: {}", atl_value);
            ErrorCode::GeneralError
        })?;

        let mut token = [0u8; TOKEN_KEY_LEN];
        CryptoEngineRegistry::get().secure_random(&mut token).map_err(|_| {
            log_e!("secure_random fail");
            ErrorCode::GeneralError
        })?;

        let token_info = token_helper::generate_token(device_type, challenge, atl)?;
        self.token_infos.push(token_info);
        Ok(())
    }

    fn parse_begin_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let capability_infos =
            HostDbManagerRegistry::get_mut().read_device_capability_info(self.obtain_param.template_id)?;
        for capability_info in capability_infos {
            if let Err(e) = self.parse_obtain_token_request(capability_info.device_type, sec_message) {
                log_e!("parse obtain token request message fail: {:?}", e);
                return Err(ErrorCode::GeneralError);
            }
        }
        if self.token_infos.is_empty() {
            log_e!("obtain token parameters found");
            return Err(ErrorCode::GeneralError);
        }

        Ok(())
    }

    fn create_begin_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let mut output = Vec::new();
        for token_info in &self.token_infos {
            let session_key =
                host_db_helper::get_session_key(self.obtain_param.template_id, token_info.device_type, &self.salt)?;
            let issue_token = SecIssueToken {
                challenge: self.challenge,
                atl: token_info.atl as i32,
                token: token_info.token.clone(),
            };
            output.extend(issue_token.encrypt_issue_token(&self.salt, token_info.device_type, &session_key)?);
        }

        Ok(output)
    }

    fn store_token(&self) -> Result<(), ErrorCode> {
        for token_info in &self.token_infos {
            let companion_token = CompanionTokenInfo {
                template_id: self.obtain_param.template_id,
                device_type: token_info.device_type,
                token: token_info.token.clone(),
                atl: token_info.atl,
                added_time: TimeKeeperRegistry::get().get_rtc_time().map_err(|e| p!(e))?,
            };
            HostDbManagerRegistry::get_mut().add_token(&companion_token)?;
        }

        Ok(())
    }
}

impl Request for HostDeviceObtainTokenRequest {
    fn get_request_id(&self) -> i32 {
        self.get_request_id()
    }

    fn prepare(&mut self, _param: RequestParam) -> Result<(), ErrorCode> {
        log_e!("HostDeviceObtainTokenRequest prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("HostDeviceObtainTokenRequest begin start");
        let RequestParam::HostObtainTokenBegin(_ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        let sec_message = self.create_prepare_sec_message()?;
        ffi_output.sec_message = DataArray1024Ffi::try_from(sec_message).map_err(|e| p!(e))?;
        Ok(())
    }

    fn end(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("HostDeviceObtainTokenRequest end start");
        let RequestParam::HostObtainTokenEnd(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.parse_begin_sec_message(ffi_input.sec_message.as_slice()?)?;
        let sec_message = self.create_begin_sec_message()?;
        self.store_token()?;
        let max_atl = self
            .token_infos
            .iter()
            .map(|info| info.atl as i32)
            .max()
            .unwrap_or(AuthTrustLevel::Atl0 as i32);
        ffi_output.sec_message = DataArray1024Ffi::try_from(sec_message).map_err(|e| p!(e))?;
        ffi_output.atl = max_atl;
        Ok(())
    }
}
