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
    DataArray1024Ffi, HostBeginCompanionCheckInputFfi, HostBeginCompanionCheckOutputFfi, HostEndCompanionCheckInputFfi,
    HostEndCompanionCheckOutputFfi,
};
use crate::jobs::host_db_helper;
use crate::jobs::message_crypto;
use crate::request::jobs::common_message::{SecCommonReply, SecCommonRequest};
use crate::traits::crypto_engine::{AesGcmParam, AesGcmResult, CryptoEngineRegistry};
use crate::traits::db_manager::CompanionTokenInfo;
use crate::traits::host_db_manager::HostDbManagerRegistry;
use crate::traits::host_request_manager::{HostRequest, HostRequestParam};
use crate::traits::misc_manager::MiscManagerRegistry;
use crate::utils::message_codec::{MessageCodec, MessageSignParam};
use crate::utils::{Attribute, AttributeKey};
use crate::vec;
use crate::{log_e, log_i, p, Box, Vec};

#[derive(Debug, Clone, PartialEq)]
pub struct HostDeviceSyncStatusRequest {
    pub request_id: i32,
    pub challenge: u64,
    pub salt: [u8; HKDF_SALT_SIZE],
    pub template_id: u64,
    pub protocal_list: Vec<u16>,
    pub capability_list: Vec<u16>,
}

impl HostDeviceSyncStatusRequest {
    pub fn new(input: &HostBeginCompanionCheckInputFfi) -> Result<Self, ErrorCode> {
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

        Ok(HostDeviceSyncStatusRequest {
            request_id: input.request_id,
            challenge: u64::from_ne_bytes(challenge),
            salt,
            template_id: 0,
            protocal_list: Vec::new(),
            capability_list: SUPPORT_CAPABILITY.to_vec(),
        })
    }

    fn parse_status_sync_reply(&mut self, device_type: DeviceType, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let output = SecCommonReply::decode(sec_message, device_type)?;
        let session_key = host_db_helper::get_session_key(self.template_id, device_type, &self.salt)?;
        let decrypt_data =
            message_crypto::decrypt_sec_message(&output.encrypt_data, &session_key, &output.tag, &output.iv)
                .map_err(|e| p!(e))?;
        let decrypt_attribute = Attribute::try_from_bytes(&decrypt_data).map_err(|e| p!(e))?;
        let challenge = decrypt_attribute.get_u64(AttributeKey::AttrChallenge).map_err(|e| p!(e))?;
        if challenge != self.challenge {
            log_e!("Challenge verification failed");
            return Err(ErrorCode::GeneralError);
        }
        let protocol_list = decrypt_attribute
            .get_u16_vec(AttributeKey::AttrProtocolList)
            .map_err(|e| p!(e))?;
        if protocol_list != self.protocal_list {
            log_e!("Protocol verification failed");
            return Err(ErrorCode::GeneralError);
        }
        let capabilities = decrypt_attribute
            .get_u16_vec(AttributeKey::AttrCapabilityList)
            .map_err(|e| p!(e))?;
        if capabilities != self.capability_list {
            log_e!("Capabilities verification failed");
            return Err(ErrorCode::GeneralError);
        }

        Ok(())
    }

    fn parse_end_sec_message(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let device_capabilitys = HostDbManagerRegistry::get_mut().read_device_capability_info(self.template_id)?;
        for device_capability in device_capabilitys {
            if let Err(e) = self.parse_status_sync_reply(device_capability.device_type, sec_message) {
                log_e!("parse sync status reply message fail: {:?}", e);
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

    fn prepare(&mut self, _param: HostRequestParam) -> Result<(), ErrorCode> {
        log_e!("HostDeviceSyncStatusRequest prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, param: HostRequestParam) -> Result<(), ErrorCode> {
        log_i!("HostDeviceSyncStatusRequest begin start");
        let HostRequestParam::SyncStatusBegin(_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };
        ffi_output.challenge = self.challenge;
        ffi_output.salt.data.copy_from_slice(&self.salt);
        ffi_output.salt.len = self.salt.len() as u32;
        Ok(())
    }

    fn end(&mut self, param: HostRequestParam) -> Result<(), ErrorCode> {
        log_i!("HostDeviceSyncStatusRequest end start");
        let HostRequestParam::SyncStatusEnd(ffi_input, _ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.template_id = ffi_input.template_id;
        self.protocal_list = Vec::<u16>::try_from(ffi_input.protocal_list).map_err(|e| {
            log_e!("Failed to convert protocal_list: {:?}", e);
            ErrorCode::GeneralError
        })?;

        self.capability_list = Vec::<u16>::try_from(ffi_input.capability_list).map_err(|e| {
            log_e!("Failed to convert capability_list: {:?}", e);
            ErrorCode::GeneralError
        })?;

        if self.parse_end_sec_message(ffi_input.sec_message.as_slice()?).is_ok() {
            host_db_helper::update_companion_device_valid_flag(self.template_id, true)?;
        } else {
            host_db_helper::update_companion_device_valid_flag(self.template_id, false)?;
        }

        Ok(())
    }
}
