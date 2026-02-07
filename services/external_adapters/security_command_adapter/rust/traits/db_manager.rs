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
use crate::entry::companion_device_auth_ffi::DeviceKeyFfi;
use crate::String;
use crate::Vec;

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct DeviceKey {
    pub device_id: String,
    pub device_id_type: i32,
    pub user_id: i32,
}

impl TryFrom<&DeviceKeyFfi> for DeviceKey {
    type Error = ErrorCode;

    fn try_from(ffi_key: &DeviceKeyFfi) -> Result<Self, ErrorCode> {
        let device_id = ffi_key.device_id.to_string()?;
        Ok(DeviceKey { device_id, device_id_type: ffi_key.device_id_type, user_id: ffi_key.user_id })
    }
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "test-utils", derive(PartialEq))]
pub struct UserInfo {
    pub user_id: i32,
    pub user_type: i32,
}

// Companion Db
#[derive(Debug, Clone)]
#[cfg_attr(feature = "test-utils", derive(PartialEq))]
pub struct HostDeviceSk {
    pub sk: [u8; SHARE_KEY_LEN],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "test-utils", derive(PartialEq))]
pub struct HostDeviceInfo {
    pub device_key: DeviceKey,
    pub binding_id: i32,
    pub user_info: UserInfo,
    pub binding_time: u64,
    pub last_used_time: u64,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "test-utils", derive(PartialEq))]
pub struct HostTokenInfo {
    pub token: [u8; TOKEN_KEY_LEN],
    pub atl: AuthTrustLevel,
}

// Host Db
#[derive(Debug, Clone)]
#[cfg_attr(feature = "test-utils", derive(PartialEq))]
pub struct CompanionDeviceBaseInfo {
    pub device_model: String,
    pub device_name: String,
    pub device_user_name: String,
    pub business_ids: Vec<i32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompanionDeviceCapability {
    pub device_type: DeviceType,
    pub esl: ExecutorSecurityLevel,
    pub track_ability_level: TrackAbilityLevel,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompanionDeviceSk {
    pub device_type: DeviceType,
    pub sk: [u8; SHARE_KEY_LEN],
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "test-utils", derive(PartialEq))]
pub struct CompanionDeviceInfo {
    pub template_id: u64,
    pub device_key: DeviceKey,
    pub user_info: UserInfo,
    pub added_time: u64,
    pub secure_protocol_id: u16,
    pub is_valid: bool,
    pub capability_list: Vec<u16>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "test-utils", derive(PartialEq))]
pub struct CompanionTokenInfo {
    pub template_id: u64,
    pub device_type: DeviceType,
    pub token: [u8; TOKEN_KEY_LEN],
    pub atl: AuthTrustLevel,
    pub added_time: u64,
}
