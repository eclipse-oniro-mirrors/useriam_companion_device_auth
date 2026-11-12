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
    ErrorCode, ProcessorType, HKDF_SALT_SIZE, validate_capability_list, validate_protocol_list,
    validate_secure_protocol_id,
};
use crate::entry::companion_device_auth_ffi::CompanionProcessCheckInputFfi;
use crate::jobs::host_binding_db_helper;
use crate::jobs::message_crypto;
use crate::request::jobs::common_message::SecCommonReply;
use crate::traits::log_trace::RustFileId;
use crate::traits::request_manager::{Request, RequestParam};
use crate::utils::{Attribute, AttributeKey};
use crate::{log_e, log_i, p, Box, Vec};
pub(crate) const FILE_ID: u16 = RustFileId::CompanionSyncStatus as u16;
#[derive(Debug, Clone, PartialEq)]
pub struct CompanionDeviceSyncStatusRequest {
    pub binding_id: i32,
    pub secure_protocol_id: u16,
    pub host_challenge: u64,
    pub salt: Vec<u8>,
    pub companion_protocol_list: Vec<u16>,
    pub companion_capability_list: Vec<u16>,
}

impl CompanionDeviceSyncStatusRequest {
    pub fn new(input: &CompanionProcessCheckInputFfi) -> Result<Self, ErrorCode> {
        validate_secure_protocol_id(input.secure_protocol_id)?;
        let salt_slice = input.salt.as_slice()?;
        if salt_slice.len() != HKDF_SALT_SIZE {
            log_e!("salt length mismatch: expected {}, got {}", HKDF_SALT_SIZE, salt_slice.len());
            return Err(ErrorCode::GeneralError);
        }

        let companion_protocol_list: Vec<u16> = input.protocol_list.try_into().map_err(|e| {
            log_e!("protocol_list try_into fail: {:?}", e);
            ErrorCode::GeneralError
        })?;
        let companion_capability_list: Vec<u16> = input.companion_capability_list.try_into().map_err(|e| {
            log_e!("companion_capability_list try_into fail: {:?}", e);
            ErrorCode::GeneralError
        })?;

        validate_protocol_list(&companion_protocol_list)?;
        validate_capability_list(&companion_capability_list)?;

        Ok(CompanionDeviceSyncStatusRequest {
            binding_id: input.binding_id,
            secure_protocol_id: input.secure_protocol_id,
            host_challenge: input.challenge,
            salt: salt_slice.to_vec(),
            companion_protocol_list,
            companion_capability_list,
        })
    }

    fn encode_sec_status_sync_reply(&mut self) -> Result<Vec<u8>, ErrorCode> {
        let mut encrypt_attribute = Attribute::new();
        encrypt_attribute.set_u64(AttributeKey::AttrHostChallenge, self.host_challenge);
        encrypt_attribute.set_u16_slice(AttributeKey::AttrProtocolList, &self.companion_protocol_list);
        encrypt_attribute.set_u16_slice(AttributeKey::AttrCapabilityList, &self.companion_capability_list);

        let attribute_bytes = encrypt_attribute.to_bytes()?;

        let session_key_param = host_binding_db_helper::get_session_key(self.binding_id, &self.salt)?;
        let (encrypt_data, tag, iv) = message_crypto::encrypt_sec_message(
            session_key_param.aead_algorithm,
            &attribute_bytes,
            &session_key_param.session_key,
        )
        .map_err(|e| p!(e))?;

        let status_sync_reply = Box::new(SecCommonReply { tag, iv, encrypt_data });
        let output = status_sync_reply.encode(ProcessorType::from_secure_protocol_id(self.secure_protocol_id)?)?;
        Ok(output)
    }
}

impl Request for CompanionDeviceSyncStatusRequest {
    fn get_request_id(&self) -> i32 {
        self.binding_id
    }

    fn prepare(&mut self, _param: RequestParam) -> Result<(), ErrorCode> {
        log_e!("CompanionDeviceSyncStatusRequest prepare not implemented");
        Err(ErrorCode::GeneralError)
    }

    fn begin(&mut self, param: RequestParam) -> Result<(), ErrorCode> {
        log_i!("CompanionDeviceSyncStatusRequest begin start");
        let RequestParam::CompanionSyncStatus(_ffi_input, ffi_output) = param else {
            log_e!("param type is error");
            return Err(ErrorCode::BadParam);
        };

        let persisted = host_binding_db_helper::get_binding_secure_protocol_id(self.binding_id)?;
        self.secure_protocol_id = persisted;

        let reply_sec_message = self.encode_sec_status_sync_reply()?;
        ffi_output.sec_message.copy_from_vec(&reply_sec_message)?;
        Ok(())
    }

    fn end(&mut self, _param: RequestParam) -> Result<(), ErrorCode> {
        log_e!("CompanionDeviceSyncStatusRequest end not implemented");
        Err(ErrorCode::GeneralError)
    }
}
