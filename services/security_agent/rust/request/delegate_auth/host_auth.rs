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
    DataArray1024Ffi, HostBeginDelegateAuthInputFfi, HostBeginDelegateAuthOutputFfi, HostEndDelegateAuthInputFfi,
    HostEndDelegateAuthOutputFfi,
};
use crate::jobs::host_db_helper;
use crate::jobs::message_crypto;
use crate::request::delegate_auth::auth_message::{FwkAuthReply, FwkAuthRequest};
use crate::request::jobs::common_message::{SecCommonReply, SecCommonRequest};
use crate::traits::crypto_engine::{AesGcmParam, AesGcmResult, CryptoEngineRegistry};
use crate::traits::db_manager::CompanionTokenInfo;
use crate::traits::host_db_manager::HostDbManagerRegistry;
use crate::traits::host_request_manager::{HostRequest, HostRequestParam};
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::traits::time_keeper::TimeKeeperRegistry;
use crate::utils::message_codec::{MessageCodec, MessageSignParam};
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, log_i, p, Box, Vec};

#[derive(Debug, Clone, PartialEq)]
pub struct AuthParam {
    pub request_id: i32,
    pub schedule_id: u64,
    pub template_id: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct HostDelegateAuthRequest {
    pub auth_param: AuthParam,
    pub challenge: u64,
    pub atl: AuthTrustLevel,
    pub acl: AuthCapabilityLevel,
    pub salt: [u8; HKDF_SALT_SIZE],
    pub auth_type: i32,
}

impl HostDelegateAuthRequest {
    pub fn new(input: &HostBeginDelegateAuthInputFfi) -> Result<Self, ErrorCode> {
        let mut challenge = [0u8; CHALLENGE_LEN];
        CryptoEngineRegistry::get().secure_random(&mut challenge).map_err(|_| {
            log_e!("secure_random fail");
            ErrorCode::GeneralError
        })?;

        let mut salt = [0u8; HKDF_SALT_SIZE];
        CryptoEngineRegistry::get().secure_random(&mut salt).map_err(|_| {
            log_e!("secure_random fail");
            ErrorCode::GeneralError
        })?;

        Ok(HostDelegateAuthRequest {
            auth_param: AuthParam {
                request_id: input.request_id,
                schedule_id: input.schedule_id,
                template_id: input.template_id,
            },
            challenge: u64::from_ne_bytes(challenge),
            atl: AuthTrustLevel::Atl2,
            acl: AuthCapabilityLevel::Acl0,
            salt: salt,
            auth_type: 0,
        })
    }

    fn parse_begin_fwk_message(&mut self, fwk_message: &[u8]) -> Result<(), ErrorCode> {
        let output = FwkAuthRequest::decode(fwk_message)?;
        if self.auth_param.schedule_id != output.schedule_id {
            log_e!("scheduleId check fail");
            return Err(ErrorCode::GeneralError);
        }

        self.atl = AuthTrustLevel::try_from(output.atl).map_err(|_| {
            log_e!("Invalid ATL value: {}", output.atl);
            ErrorCode::GeneralError
        })?;

        Ok(())
    }

    fn create_begin_sec_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let mut output = Vec::new();
        let device_capabilitys =
            HostDbManagerRegistry::get_mut().read_device_capability_info(self.auth_param.template_id)?;
        for device_capability in device_capabilitys {
            let session_key = host_db_helper::get_session_key(
                self.auth_param.template_id,
                device_capability.device_type,
                &self.salt,
            )?;

            let mut encrypt_attribute = Attribute::new();
            encrypt_attribute.set_u64(AttributeKey::AttrChallenge, self.challenge);
            encrypt_attribute.set_i32(AttributeKey::AttrAuthTrustLevel, self.atl as i32);

            let (encrypt_data, tag, iv) =
                message_crypto::encrypt_sec_message(encrypt_attribute.to_bytes()?.as_slice(), &session_key)
                    .map_err(|e| p!(e))?;

            let sec_auth_request = SecCommonRequest { salt: self.salt, tag, iv, encrypt_data };
            output.extend(sec_auth_request.encode(device_capability.device_type)?);
        }
        Ok(output)
    }

    fn parse_auth_reply_data(&mut self, device_type: DeviceType, message_data: &[u8]) -> Result<(), ErrorCode> {
        let output = SecCommonReply::decode(message_data, device_type)?;
        let session_key = host_db_helper::get_session_key(self.auth_param.template_id, device_type, &self.salt)?;
        let decrypt_data =
            message_crypto::decrypt_sec_message(&output.encrypt_data, &session_key, &output.tag, &output.iv)
                .map_err(|e| p!(e))?;
        let decrypt_attribute = Attribute::try_from_bytes(&decrypt_data).map_err(|e| p!(e))?;
        let auth_type = decrypt_attribute.get_i32(AttributeKey::AttrType).map_err(|e| p!(e))?;
        let atl_value = decrypt_attribute.get_i32(AttributeKey::AttrAuthTrustLevel).map_err(|e| p!(e))?;
        let challenge = decrypt_attribute.get_u64(AttributeKey::AttrChallenge).map_err(|e| p!(e))?;
        if challenge != self.challenge {
            log_e!("Challenge verification failed");
            return Err(ErrorCode::GeneralError);
        }

        self.auth_type = auth_type;
        self.atl = AuthTrustLevel::try_from(atl_value).map_err(|_| {
            log_e!("Invalid ATL value: {}", atl_value);
            ErrorCode::GeneralError
        })?;

        Ok(())
    }

    fn parse_end_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let device_capabilitys =
            HostDbManagerRegistry::get_mut().read_device_capability_info(self.auth_param.template_id)?;
        for device_capability in device_capabilitys {
            if let Err(e) = self.parse_auth_reply_data(device_capability.device_type, sec_message) {
                log_e!("parse auth reply message fail: {:?}", e);
                return Err(ErrorCode::GeneralError);
            }
        }

        Ok(())
    }

    fn create_end_fwk_message(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let fwk_auth_reply = FwkAuthReply {
            schedule_id: self.auth_param.schedule_id,
            template_id: self.auth_param.template_id,
            result_code: 0,
            acl: AuthCapabilityLevel::Acl3 as i32,
            pin_sub_type: 0,
            remain_attempts: 0,
            lock_duration: 0,
        };
        let output = fwk_auth_reply.encode()?;
        Ok(output)
    }
}

impl HostRequest for HostDelegateAuthRequest {
    fn get_request_id(&self) -> i32 {
        self.auth_param.request_id
    }

    fn prepare(&mut self, _param: HostRequestParam) -> Result<(), ErrorCode> {
        log_e!("HostDelegateAuthRequest prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, param: HostRequestParam) -> Result<(), ErrorCode> {
        log_i!("HostDelegateAuthRequest begin start");
        let HostRequestParam::DelegateAuthBegin(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.parse_begin_fwk_message(ffi_input.fwk_message.as_slice()?)?;
        let sec_message = self.create_begin_sec_message()?;
        ffi_output.sec_message = DataArray1024Ffi::try_from(sec_message).map_err(|e| p!(e))?;
        Ok(())
    }

    fn end(&mut self, param: HostRequestParam) -> Result<(), ErrorCode> {
        log_i!("HostDelegateAuthRequest end start");
        let HostRequestParam::DelegateAuthEnd(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.parse_end_sec_message(ffi_input.sec_message.as_slice()?)?;
        let fwk_message = self.create_end_fwk_message()?;
        ffi_output.fwk_message = DataArray1024Ffi::try_from(fwk_message).map_err(|e| p!(e))?;
        ffi_output.auth_type = self.auth_type;
        ffi_output.atl = self.atl as i32;
        Ok(())
    }
}
