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

use crate::common::constants::{AuthTrustLevel, Capability, ErrorCode, ProcessorType, CHALLENGE_LEN, HKDF_SALT_SIZE};
use crate::entry::companion_device_auth_ffi::HostProcessPreObtainTokenInputFfi;
use crate::jobs::companion_device_db_helper;
use crate::jobs::message_crypto;
use crate::request::jobs::common_message::SecIssueToken;
use crate::request::jobs::token_helper;
use crate::request::jobs::token_helper::DeviceTokenInfo;
use crate::request::token_obtain::token_obtain_message::{SecPreObtainTokenReply, SecPreObtainTokenRequest};
use crate::traits::companion_device_db_manager::CompanionDeviceDbManagerRegistry;
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::request_manager::{Request, RequestParam};
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, log_i, p, Box, Vec};
use crate::traits::log_trace::RustFileId;
pub(crate) const FILE_ID: u16 = RustFileId::HostObtainToken as u16;

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
    pub host_challenge: u64,
}

impl HostDeviceObtainTokenRequest {
    pub fn new(input: &HostProcessPreObtainTokenInputFfi) -> Result<Self, ErrorCode> {
        let mut salt = [0u8; HKDF_SALT_SIZE];
        CryptoEngineRegistry::get().secure_random(&mut salt).map_err(|_| {
            log_e!("secure_random salt fail");
            ErrorCode::GeneralError
        })?;
        let mut challenge = [0u8; CHALLENGE_LEN];
        CryptoEngineRegistry::get().secure_random(&mut challenge).map_err(|_| {
            log_e!("secure_random challenge fail");
            ErrorCode::GeneralError
        })?;
        Ok(HostDeviceObtainTokenRequest {
            obtain_param: TokenObtainParam { request_id: input.request_id, template_id: input.template_id },
            token_infos: Vec::new(),
            salt,
            host_challenge: u64::from_ne_bytes(challenge),
        })
    }

    fn get_request_id(&self) -> i32 {
        self.obtain_param.request_id
    }

    fn encode_sec_token_pre_obtain_request(&self) -> Result<Vec<u8>, ErrorCode> {
        let mut output = Vec::new();
        let obtain_token_request =
            Box::new(SecPreObtainTokenRequest { salt: self.salt, challenge: self.host_challenge });
        let capability_infos =
            CompanionDeviceDbManagerRegistry::get_mut().read_device_capability_info(self.obtain_param.template_id)?;
        for capability_info in capability_infos {
            output.extend(obtain_token_request.encode(capability_info.processor_type)?);
        }

        if output.is_empty() {
            log_e!("proc obtain token fail");
            return Err(ErrorCode::GeneralError);
        }

        Ok(output)
    }

    fn decode_sec_token_obtain_request_message(
        &mut self,
        processor_type: ProcessorType,
        sec_message: &[u8],
    ) -> Result<(), ErrorCode> {
        let output = SecPreObtainTokenReply::decode(sec_message, processor_type)?;
        let session_key =
            companion_device_db_helper::get_session_key(self.obtain_param.template_id, processor_type, &self.salt)?;
        let decrypt_data =
            message_crypto::decrypt_sec_message(&output.encrypt_data, &session_key, &output.tag, &output.iv)
                .map_err(|e| p!(e))?;
        let decrypt_attribute = Attribute::try_from_bytes(&decrypt_data).map_err(|e| p!(e))?;
        let challenge = decrypt_attribute.get_u64(AttributeKey::AttrHostChallenge).map_err(|e| p!(e))?;
        if challenge != self.host_challenge {
            log_e!("Challenge verification failed");
            return Err(ErrorCode::GeneralError);
        }
        let atl_value = decrypt_attribute.get_i32(AttributeKey::AttrAuthTrustLevel).map_err(|e| p!(e))?;
        let atl = AuthTrustLevel::try_from(atl_value).map_err(|_| {
            log_e!("Invalid ATL value: {}", atl_value);
            ErrorCode::GeneralError
        })?;

        let token_info = token_helper::generate_token(processor_type, output.challenge, atl)?;
        self.token_infos.push(token_info);
        Ok(())
    }

    fn decode_sec_token_obtain_request(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let capability_infos =
            CompanionDeviceDbManagerRegistry::get_mut().read_device_capability_info(self.obtain_param.template_id)?;
        for capability_info in capability_infos {
            if let Err(e) = self.decode_sec_token_obtain_request_message(capability_info.processor_type, sec_message) {
                log_e!(
                    "parse obtain token reply message fail: processor_type: {:?}, result: {:?}",
                    capability_info.processor_type,
                    e
                );
                return Err(ErrorCode::GeneralError);
            }
        }

        Ok(())
    }

    fn encode_sec_token_obtain_reply(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let mut output = Vec::new();
        for token_info in &self.token_infos {
            let session_key = companion_device_db_helper::get_session_key(
                self.obtain_param.template_id,
                token_info.processor_type,
                &self.salt,
            )?;
            let issue_token = SecIssueToken {
                challenge: token_info.challenge,
                atl: token_info.atl as i32,
                token: token_info.token.clone(),
            };
            output.extend(issue_token.encrypt_issue_token(&self.salt, token_info.processor_type, &session_key)?);
        }

        Ok(output)
    }

    fn store_token(&self) -> Result<(), ErrorCode> {
        if self.token_infos.is_empty() {
            log_e!("token info is null");
            return Err(ErrorCode::GeneralError);
        }
        token_helper::add_companion_device_token(self.obtain_param.template_id, &self.token_infos)?;
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

        companion_device_db_helper::check_device_capability(self.obtain_param.template_id, Capability::ObtainToken)?;

        let sec_message = self.encode_sec_token_pre_obtain_request()?;
        ffi_output.sec_message.copy_from_vec(&sec_message)?;
        Ok(())
    }

    fn end(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("HostDeviceObtainTokenRequest end start");
        let RequestParam::HostObtainTokenEnd(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.decode_sec_token_obtain_request(ffi_input.sec_message.as_slice()?)?;
        let sec_message = self.encode_sec_token_obtain_reply()?;
        self.store_token()?;
        let max_atl = self.token_infos.iter().map(|info| info.atl as i32).max().unwrap_or(AuthTrustLevel::Atl0 as i32);
        ffi_output.sec_message.copy_from_vec(&sec_message)?;
        ffi_output.atl = max_atl;
        Ok(())
    }
}
