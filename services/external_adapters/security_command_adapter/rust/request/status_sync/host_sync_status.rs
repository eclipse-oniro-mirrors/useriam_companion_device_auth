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

use crate::common::constants::{
    ErrorCode, ProcessorType, CHALLENGE_LEN, HKDF_SALT_SIZE, SUPPORTED_PROTOCOL_VERSIONS, SUPPORT_CAPABILITIES,
};
use crate::entry::companion_device_auth_ffi::HostBeginCompanionCheckInputFfi;
use crate::jobs::companion_device_db_helper;
use crate::jobs::message_crypto;
use crate::request::jobs::common_message::SecCommonReply;
use crate::traits::companion_device_db_manager::CompanionDeviceDbManagerRegistry;
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::request_manager::{Request, RequestParam};
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, log_i, p};

#[derive(Debug, Clone, PartialEq)]
pub struct HostDeviceSyncStatusRequest {
    pub request_id: i32,
    pub host_challenge: u64,
    pub salt: [u8; HKDF_SALT_SIZE],
    pub template_id: u64,
}

impl HostDeviceSyncStatusRequest {
    pub fn new(input: &HostBeginCompanionCheckInputFfi) -> Result<Self, ErrorCode> {
        let mut challenge = [0u8; CHALLENGE_LEN];
        CryptoEngineRegistry::get().secure_random(&mut challenge).map_err(|_| {
            log_e!("secure_random challenge fail");
            ErrorCode::GeneralError
        })?;

        let mut salt = [0u8; HKDF_SALT_SIZE];
        CryptoEngineRegistry::get().secure_random(&mut salt).map_err(|_| {
            log_e!("secure_random salt fail");
            ErrorCode::GeneralError
        })?;

        Ok(HostDeviceSyncStatusRequest {
            request_id: input.request_id,
            host_challenge: u64::from_ne_bytes(challenge),
            salt,
            template_id: 0,
        })
    }

    fn decode_sec_status_sync_reply_message(
        &mut self,
        processor_type: ProcessorType,
        sec_message: &[u8],
    ) -> Result<(), ErrorCode> {
        let output = SecCommonReply::decode(sec_message, processor_type)?;
        let session_key = companion_device_db_helper::get_session_key(self.template_id, processor_type, &self.salt)?;
        let decrypt_data =
            message_crypto::decrypt_sec_message(&output.encrypt_data, &session_key, &output.tag, &output.iv)
                .map_err(|e| p!(e))?;
        let decrypt_attribute = Attribute::try_from_bytes(&decrypt_data).map_err(|e| p!(e))?;
        let challenge = decrypt_attribute.get_u64(AttributeKey::AttrHostChallenge).map_err(|e| p!(e))?;
        if challenge != self.host_challenge {
            log_e!("Challenge verification failed");
            return Err(ErrorCode::GeneralError);
        }
        let protocol_list = decrypt_attribute.get_u16_vec(AttributeKey::AttrProtocolList).map_err(|e| p!(e))?;
        // Validate that TA's protocol_list is a subset of CA's SUPPORTED_PROTOCOL_VERSIONS
        for protocol in &protocol_list {
            if !SUPPORTED_PROTOCOL_VERSIONS.contains(protocol) {
                log_e!("protocol {} is not supported by CA, supported: {:?}", protocol, SUPPORTED_PROTOCOL_VERSIONS);
                return Err(ErrorCode::GeneralError);
            }
        }
        let capabilities = decrypt_attribute.get_u16_vec(AttributeKey::AttrCapabilityList).map_err(|e| p!(e))?;
        // Validate that TA's capabilities is a subset of CA's SUPPORT_CAPABILITIES
        for capability in &capabilities {
            if !SUPPORT_CAPABILITIES.contains(capability) {
                log_e!("capability {} is not supported by CA, supported: {:?}", capability, SUPPORT_CAPABILITIES);
                return Err(ErrorCode::GeneralError);
            }
        }

        Ok(())
    }

    fn decode_sec_status_sync_reply(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let device_capabilities =
            CompanionDeviceDbManagerRegistry::get_mut().read_device_capability_info(self.template_id)?;
        for device_capability in &device_capabilities {
            if let Err(e) = self.decode_sec_status_sync_reply_message(device_capability.processor_type, sec_message) {
                log_e!(
                    "parse sync status reply message fail: device_type: {:?}, result: {:?}",
                    device_capability.processor_type,
                    e
                );
                return Err(ErrorCode::GeneralError);
            }
        }
        Ok(())
    }
}

impl Request for HostDeviceSyncStatusRequest {
    fn get_request_id(&self) -> i32 {
        self.request_id
    }

    fn prepare(&mut self, _param: RequestParam) -> Result<(), ErrorCode> {
        log_e!("HostDeviceSyncStatusRequest prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("HostDeviceSyncStatusRequest begin start");
        let RequestParam::HostSyncStatusBegin(_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };
        ffi_output.challenge = self.host_challenge;
        ffi_output.salt.data.copy_from_slice(&self.salt);
        ffi_output.salt.len = self.salt.len() as u32;
        Ok(())
    }

    fn end(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("HostDeviceSyncStatusRequest end start");
        let RequestParam::HostSyncStatusEnd(ffi_input, _ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        self.template_id = ffi_input.template_id;

        if self.decode_sec_status_sync_reply(ffi_input.sec_message.as_slice()?).is_err() {
            companion_device_db_helper::update_companion_device_valid_flag(self.template_id, false)?;
            log_e!("proc status sync reply fail");
            return Err(ErrorCode::GeneralError);
        }

        Ok(())
    }
}
