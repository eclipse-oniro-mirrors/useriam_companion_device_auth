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
    ErrorCode, ProcessorType, CHALLENGE_LEN, HKDF_SALT_SIZE, intersect_lists, is_subset, same_elements,
    validate_secure_protocol_id,
};
use crate::entry::companion_device_auth_ffi::HostBeginCompanionCheckInputFfi;
use crate::jobs::companion_device_db_helper;
use crate::jobs::message_crypto;
use crate::request::jobs::common_message::SecCommonReply;
use crate::traits::companion_device_db_manager::CompanionDeviceDbManagerRegistry;
use crate::traits::crypto_engine::CryptoEngineRegistry;
use crate::traits::log_trace::RustFileId;
use crate::traits::request_manager::{Request, RequestParam};
use crate::utils::scope_guard::ScopeGuard;
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, log_i, p, Vec};
pub(crate) const FILE_ID: u16 = RustFileId::HostSyncStatus as u16;

#[derive(Debug, Clone, PartialEq)]
pub struct HostDeviceSyncStatusRequest {
    pub request_id: i32,
    pub host_challenge: u64,
    pub salt: [u8; HKDF_SALT_SIZE],
    pub template_id: u64,
    pub secure_protocol_id: u16,
    pub inner_protocol_list: Vec<u16>,
    pub inner_capability_list: Vec<u16>,
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
            secure_protocol_id: 0,
            inner_protocol_list: Vec::new(),
            inner_capability_list: Vec::new(),
        })
    }

    fn decode_sec_status_sync_reply_message(
        &self,
        processor_type: ProcessorType,
        sec_message: &[u8],
    ) -> Result<(Vec<u16>, Vec<u16>), ErrorCode> {
        let output = SecCommonReply::decode(sec_message, processor_type)?;
        let session_key_param =
            companion_device_db_helper::get_session_key(self.template_id, processor_type, &self.salt)?;
        let decrypt_data = message_crypto::decrypt_sec_message(
            session_key_param.aead_algorithm,
            &output.encrypt_data,
            &session_key_param.session_key,
            &output.tag,
            &output.iv,
        )
        .map_err(|e| p!(e))?;
        let decrypt_attribute = Attribute::try_from_bytes(&decrypt_data).map_err(|e| p!(e))?;
        let challenge = decrypt_attribute.get_u64(AttributeKey::AttrHostChallenge).map_err(|e| p!(e))?;
        if challenge != self.host_challenge {
            log_e!("Challenge verification failed");
            return Err(ErrorCode::GeneralError);
        }
        let protocol_list = decrypt_attribute.get_u16_vec(AttributeKey::AttrProtocolList).map_err(|e| p!(e))?;
        let capability_list = decrypt_attribute.get_u16_vec(AttributeKey::AttrCapabilityList).map_err(|e| p!(e))?;
        Ok((protocol_list, capability_list))
    }

    fn decode_sec_status_sync_reply(&mut self, sec_message: &[u8]) -> Result<(), ErrorCode> {
        let device_capabilities =
            CompanionDeviceDbManagerRegistry::get_mut().read_device_capability_info(self.template_id)?;
        let mut inner_protocol_list: Option<Vec<u16>> = None;
        let mut inner_capability_list: Option<Vec<u16>> = None;
        for device_capability in &device_capabilities {
            let (protocol_list, capability_list) =
                self.decode_sec_status_sync_reply_message(device_capability.processor_type, sec_message).map_err(
                    |e| {
                        log_e!(
                            "parse sync status reply message fail: processor_type: {:?}, result: {:?}",
                            device_capability.processor_type,
                            e
                        );
                        ErrorCode::GeneralError
                    },
                )?;

            if let Some(first) = &inner_protocol_list {
                if !same_elements(&protocol_list, first) {
                    log_e!(
                        "protocol list differs across processor types: {:?} vs {:?}",
                        protocol_list,
                        first
                    );
                    self.invalidate_device();
                    return Err(ErrorCode::ProtocolNegotiationFailed);
                }
            }
            if let Some(first) = &inner_capability_list {
                if !same_elements(&capability_list, first) {
                    log_e!(
                        "capability list differs across processor types: {:?} vs {:?}",
                        capability_list,
                        first
                    );
                    self.invalidate_device();
                    return Err(ErrorCode::CapabilityNegotiationFailed);
                }
            }
            inner_protocol_list = Some(protocol_list);
            inner_capability_list = Some(capability_list);
        }

        let (Some(protocol_list), Some(capability_list)) = (inner_protocol_list, inner_capability_list) else {
            log_e!("no device capabilities found");
            return Err(ErrorCode::GeneralError);
        };
        self.inner_protocol_list = protocol_list;
        self.inner_capability_list = capability_list;
        Ok(())
    }

    fn invalidate_device(&self) {
        let _ = companion_device_db_helper::update_companion_device_valid_flag(self.template_id, false);
    }

    fn check_authenticated_reply(
        &self,
        device_info: &crate::traits::db_manager::CompanionDevice,
    ) -> Result<Vec<u16>, ErrorCode> {
        let mut invalidate_guard = ScopeGuard::new(|| self.invalidate_device());
        let inner_protocol_list = self.inner_protocol_list.clone();
        if !inner_protocol_list.contains(&device_info.protocol_id) {
            log_e!(
                "authenticated protocol list {:?} does not cover enrolled protocol {}",
                inner_protocol_list,
                device_info.protocol_id
            );
            return Err(ErrorCode::ProtocolNegotiationFailed);
        }

        let persisted = device_info.capability_list.clone();
        let effective = intersect_lists(&self.inner_capability_list, &persisted);
        if !is_subset(&persisted, &self.inner_capability_list) {
            log_e!(
                "authenticated capability list {:?} does not cover enrolled pin {:?}, template_id:{:04x}",
                self.inner_capability_list,
                persisted,
                self.template_id as u16
            );
            return Err(ErrorCode::CapabilityNegotiationFailed);
        }

        invalidate_guard.cancel();
        Ok(effective)
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
        let RequestParam::HostSyncStatusEnd(ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        validate_secure_protocol_id(ffi_input.secure_protocol_id)?;

        self.template_id = ffi_input.template_id;
        self.secure_protocol_id = companion_device_db_helper::get_device_secure_protocol_id(self.template_id)?;

        let device_info = CompanionDeviceDbManagerRegistry::get()
            .get_device(self.template_id)
            .map_err(|e| p!(e))?;

        if let Err(e) = self.decode_sec_status_sync_reply(ffi_input.sec_message.as_slice()?) {
            log_e!("proc status sync reply fail: {:?}", e);
            return Err(e);
        }

        let converged = self.check_authenticated_reply(&device_info)?;

        let (capability_data, capability_len) =
            crate::commands::common_command::try_array_from_vec(converged)?;
        ffi_output.capability_list.data = capability_data;
        ffi_output.capability_list.len = capability_len;

        Ok(())
    }
}
