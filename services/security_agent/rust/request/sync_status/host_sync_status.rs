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
    DataArray1024Ffi, HostBeginCompanionCheckInputFfi, HostBeginCompanionCheckOutputFfi,
    HostEndCompanionCheckInputFfi, HostEndCompanionCheckOutputFfi,
};
use crate::jobs::host_db_helper;
use crate::jobs::message_crypto;
use crate::traits::crypto_engine::{AesGcmParam, AesGcmResult, CryptoEngineRegistry};
use crate::traits::db_manager::CompanionTokenInfo;
use crate::traits::host_db_manager::HostDbManagerRegistry;
use crate::traits::host_request_manager::{HostRequest, HostRequestInput, HostRequestOutput};
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::utils::message_codec::{MessageCodec, MessageSignParam};
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, log_i, p, Box, Vec};

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct HostDeviceSyncStatusRequest {
    pub request_id: i32,
    pub challenge: u64,
    pub salt: [u8; HKDF_SALT_SIZE],
    pub template_id: u64,
    pub algorithm_list: Vec<u16>,
    pub capability_list: Vec<u16>,
}

impl HostDeviceSyncStatusRequest {
    pub fn new(input: &HostBeginCompanionCheckInputFfi) -> Result<Self, ErrorCode> {
        let mut challenge = [0u8; CHALLENGE_LEN];
        CryptoEngineRegistry::get()
            .secure_random(&mut challenge)
            .map_err(|_| {
                log_e!("secure_random fail");
                ErrorCode::GeneralError
            })?;

        let mut salt = [0u8; HKDF_SALT_SIZE];
        CryptoEngineRegistry::get()
            .secure_random(&mut salt)
            .map_err(|_| {
                log_e!("secure_random fail");
                ErrorCode::GeneralError
            })?;

        Ok(HostDeviceSyncStatusRequest {
            request_id: input.request_id,
            challenge: u64::from_ne_bytes(challenge),
            salt,
            template_id: 0,
            algorithm_list: Vec::new(),
            capability_list: Vec::new(),
        })
    }

    fn parse_check_reply_data(
        &mut self,
        device_type: DeviceType,
        message_data: &[u8],
    ) -> Result<(), ErrorCode> {
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

        let session_key =
            host_db_helper::get_session_key(self.template_id, device_type, &self.salt)?;
        let decrypt_data = message_crypto::decrypt_sec_message(encrypt_data, &session_key, tag, iv)
            .map_err(|e| p!(e))?;
        let decrypt_attribute = Attribute::try_from_bytes(&decrypt_data).map_err(|e| p!(e))?;
        let decrypt_challenge = decrypt_attribute
            .get_u64(AttributeKey::AttrChallenge)
            .map_err(|e| p!(e))?;
        if decrypt_challenge != self.challenge {
            log_e!("Challenge verification failed");
            return Err(ErrorCode::GeneralError);
        }
        let decrypt_algorithms = decrypt_attribute
            .get_u16_vec(AttributeKey::AttrAlgoList)
            .map_err(|e| p!(e))?;
        if !self.algorithm_list.contains(&decrypt_algorithms[0]) {
            log_e!("Algorithms verification failed");
            return Err(ErrorCode::GeneralError);
        }
        let decrypt_capabilities = decrypt_attribute
            .get_u16_vec(AttributeKey::AttrCapabilityList)
            .map_err(|e| p!(e))?;
        if decrypt_capabilities != self.capability_list {
            log_e!("Capabilities verification failed");
            return Err(ErrorCode::GeneralError);
        }

        Ok(())
    }

    fn parse_end_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let attribute = Attribute::try_from_bytes(sec_message).map_err(|e| p!(e))?;

        if let Ok(value) = attribute.get_u8_slice(AttributeKey::AttrMessage) {
            if let Err(e) = self.parse_check_reply_data(DeviceType::None, value) {
                log_e!("parse common message fail: {:?}", e);
                return Err(ErrorCode::GeneralError);
            }
        }

        Ok(())
    }
}

impl HostRequest for HostDeviceSyncStatusRequest {
    fn get_request_id(&self) -> i32 {
        self.request_id
    }

    fn prepare(&mut self, _input: HostRequestInput) -> Result<HostRequestOutput, ErrorCode> {
        log_e!("HostDeviceSyncStatusRequest prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, input: HostRequestInput) -> Result<HostRequestOutput, ErrorCode> {
        log_i!("HostDeviceSyncStatusRequest begin start");
        let HostRequestInput::SyncStatusBegin(_ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };
        Ok(HostRequestOutput::SyncStatusBegin(
            HostBeginCompanionCheckOutputFfi {
                challenge: self.challenge,
                salt: self.salt,
            },
        ))
    }

    fn end(&mut self, input: HostRequestInput) -> Result<HostRequestOutput, ErrorCode> {
        log_i!("HostDeviceSyncStatusRequest end start");
        let HostRequestInput::SyncStatusEnd(ffi_input) = input else {
            return Err(ErrorCode::BadParam);
        };

        self.template_id = ffi_input.template_id;
        self.algorithm_list = Vec::<u16>::try_from(ffi_input.algorithm_list).map_err(|e| {
            log_e!("Failed to convert algorithm_list: {:?}", e);
            ErrorCode::GeneralError
        })?;

        self.capability_list = Vec::<u16>::try_from(ffi_input.capability_list).map_err(|e| {
            log_e!("Failed to convert capability_list: {:?}", e);
            ErrorCode::GeneralError
        })?;

        if self
            .parse_end_sec_message(ffi_input.sec_message.as_slice())
            .is_ok()
        {
            host_db_helper::update_companion_device_valid_flag(self.template_id, true)?;
        } else {
            host_db_helper::update_companion_device_valid_flag(self.template_id, false)?;
        }

        Ok(HostRequestOutput::SyncStatusEnd(
            HostEndCompanionCheckOutputFfi::default(),
        ))
    }
}
