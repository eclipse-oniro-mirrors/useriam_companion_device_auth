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

use crate::common::algorithm::SelectedAlgorithms;
use crate::common::constants::{
    AuthTrustLevel, ErrorCode, ExecutorSecurityLevel, ProcessorType, TrackAbilityLevel, SHARE_KEY_LEN,
    TOKEN_KEY_LEN, is_valid_device_id_type,
};
use crate::entry::companion_device_auth_ffi::DeviceKeyFfi;
use crate::log_e;
use crate::traits::log_trace::RustFileId;
use crate::String;
use crate::Vec;
pub(crate) const FILE_ID: u16 = RustFileId::DbManager as u16;

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct DeviceKey {
    pub device_id: String,
    pub device_id_type: i32,
    pub user_id: i32,
    pub sub_profile_id: i32,
}

impl TryFrom<&DeviceKeyFfi> for DeviceKey {
    type Error = ErrorCode;

    fn try_from(ffi_key: &DeviceKeyFfi) -> Result<Self, ErrorCode> {
        if !is_valid_device_id_type(ffi_key.device_id_type) {
            log_e!("invalid device_id_type: {}", ffi_key.device_id_type);
            return Err(ErrorCode::BadParam);
        }
        let device_id = ffi_key.device_id.to_string()?;
        Ok(DeviceKey {
            device_id,
            device_id_type: ffi_key.device_id_type,
            user_id: ffi_key.user_id,
            sub_profile_id: ffi_key.sub_profile_id,
        })
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "test-utils", derive(PartialEq))]
pub struct UserInfo {
    pub user_key: UserKey,
    pub user_type: i32,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub struct UserKey {
    pub user_id: i32,
    pub sub_profile_id: i32,
}

// Host Binding Db
#[derive(Debug, Clone)]
#[cfg_attr(feature = "test-utils", derive(PartialEq))]
pub struct HostBindingKeyMaterial {
    pub selected_algorithms: SelectedAlgorithms,
    pub sk: [u8; SHARE_KEY_LEN],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "test-utils", derive(PartialEq))]
pub struct SessionKeyParam {
    pub session_key: Vec<u8>,
    pub aead_algorithm: u16,
    pub mac_algorithm: u16,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "test-utils", derive(PartialEq))]
pub struct HostBinding {
    pub device_key: DeviceKey,
    pub binding_id: i32,
    pub user_info: UserInfo,
    pub binding_time: u64,
    pub last_used_time: u64,
    pub enrolled_protocol_id: u16,
    pub secure_protocol_id: u16,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "test-utils", derive(PartialEq))]
pub struct HostBindingToken {
    pub token: [u8; TOKEN_KEY_LEN],
    pub atl: AuthTrustLevel,
}

// Companion Device Db
#[derive(Debug, Clone)]
#[cfg_attr(feature = "test-utils", derive(PartialEq))]
pub struct CompanionDeviceProfile {
    pub device_model_info: String,
    pub device_name: String,
    pub device_user_name: String,
    pub business_ids: Vec<i32>,
    pub device_type: i32,
    pub supported_business_ids: Vec<i32>,
    pub device_sub_profile_name: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompanionDeviceCapability {
    pub processor_type: ProcessorType,
    pub esl: ExecutorSecurityLevel,
    pub track_ability_level: TrackAbilityLevel,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompanionDeviceKeyMaterial {
    pub processor_type: ProcessorType,
    pub selected_algorithms: SelectedAlgorithms,
    pub sk: [u8; SHARE_KEY_LEN],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "test-utils", derive(PartialEq))]
pub struct CompanionDevice {
    pub template_id: u64,
    pub device_key: DeviceKey,
    pub user_info: UserInfo,
    pub added_time: u64,
    pub is_valid: bool,
    pub enrolled_capability_list: Vec<u16>,
    pub enrolled_protocol_id: u16,
    pub secure_protocol_id: u16,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "test-utils", derive(PartialEq))]
pub struct CompanionDeviceToken {
    pub template_id: u64,
    pub processor_type: ProcessorType,
    pub token: [u8; TOKEN_KEY_LEN],
    pub atl: AuthTrustLevel,
    pub expire_time: u64,
    pub issue_time: u64,
}
