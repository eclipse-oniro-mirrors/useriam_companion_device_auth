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

use crate::common::constants::ErrorCode;
use crate::ensure_or_return_val;
use crate::entry::companion_device_auth_entry::{
    handle_rust_command, handle_rust_env_init, handle_rust_env_uninit,
};
use crate::{log_e, CString, Vec};
use core::mem;
use core::slice;
use serde::{Deserialize, Serialize};

pub const SALT_LEN_FFI: usize = 32;
pub const UDID_LEN_FFI: usize = 64;
pub const MAX_EVENT_NUM_FFI: usize = 20;
pub const MAX_TEMPLATE_ID_NUM_PER_USER_FFI: usize = 10;
pub const MAX_USER_NUM_FFI: usize = 5;
pub const MAX_DATA_LEN_64: usize = 64;
pub const MAX_DATA_LEN_128: usize = 128;
pub const MAX_DATA_LEN_256: usize = 256;
pub const MAX_DATA_LEN_1024: usize = 1024;
pub const MAX_STRUCT_SIZE_FFI: usize = 409600;
pub const AUTH_TOKEN_SIZE_FFI: usize = 344;
pub const PROPERTY_MODE_FREEZE: u32 = 5;
pub const PROPERTY_MODE_UNFREEZE: u32 = 6;

macro_rules! assert_max_size {
    ($t:ty) => {
        const _: () = {
            // if size_of::<$t>() > MAX_STRUCT_SIZE_FFI, compile will fail
            let _ = [(); MAX_STRUCT_SIZE_FFI - core::mem::size_of::<$t>()];
        };
    };
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DataArray64Ffi {
    pub data: [u8; MAX_DATA_LEN_64],
    pub len: u32,
}
assert_max_size!(DataArray64Ffi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DataArray128Ffi {
    pub data: [u8; MAX_DATA_LEN_128],
    pub len: u32,
}
assert_max_size!(DataArray128Ffi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DataArray256Ffi {
    pub data: [u8; MAX_DATA_LEN_256],
    pub len: u32,
}
assert_max_size!(DataArray256Ffi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct DataArray1024Ffi {
    pub data: [u8; MAX_DATA_LEN_1024],
    pub len: u32,
}
assert_max_size!(DataArray1024Ffi);

macro_rules! impl_default_data_array {
    ($name:ident, $size:expr) => {
        impl Default for $name {
            fn default() -> Self {
                $name {
                    data: [0; $size],
                    len: 0,
                }
            }
        }
    };
}
impl_default_data_array!(DataArray64Ffi, MAX_DATA_LEN_64);
impl_default_data_array!(DataArray128Ffi, MAX_DATA_LEN_128);
impl_default_data_array!(DataArray256Ffi, MAX_DATA_LEN_256);
impl_default_data_array!(DataArray1024Ffi, MAX_DATA_LEN_1024);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct TemplateIdArrayFfi {
    pub data: [u64; MAX_TEMPLATE_ID_NUM_PER_USER_FFI],
    pub len: u32,
}
assert_max_size!(TemplateIdArrayFfi);

impl Default for TemplateIdArrayFfi {
    fn default() -> Self {
        TemplateIdArrayFfi {
            data: [0; MAX_TEMPLATE_ID_NUM_PER_USER_FFI],
            len: 0,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Int32Array64Ffi {
    pub data: [i32; MAX_DATA_LEN_64],
    pub len: u32,
}
assert_max_size!(Int32Array64Ffi);

impl Default for Int32Array64Ffi {
    fn default() -> Self {
        Int32Array64Ffi {
            data: [0; MAX_DATA_LEN_64],
            len: 0,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct Uint16Array64Ffi {
    pub data: [u16; MAX_DATA_LEN_64],
    pub len: u32,
}
assert_max_size!(Uint16Array64Ffi);

impl Default for Uint16Array64Ffi {
    fn default() -> Self {
        Uint16Array64Ffi {
            data: [0; MAX_DATA_LEN_64],
            len: 0,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct PlaceHolderFfi {
    pub place_holder: u8,
}
assert_max_size!(PlaceHolderFfi);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct EventFfi {
    pub time: u64,
    pub file_name: DataArray64Ffi,
    pub line_number: u32,
    pub event_type: i32,
    pub event_info: DataArray256Ffi,
}
assert_max_size!(EventFfi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct EventArrayFfi {
    pub data: [EventFfi; MAX_EVENT_NUM_FFI],
    pub len: u32,
}
assert_max_size!(EventArrayFfi);

impl Default for EventArrayFfi {
    fn default() -> Self {
        EventArrayFfi {
            data: [EventFfi::default(); MAX_EVENT_NUM_FFI],
            len: 0,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CommonOutputFfi {
    pub result: i32,
    pub has_fatal_error: u8,
    pub events: EventArrayFfi,
}
assert_max_size!(CommonOutputFfi);

impl Default for CommonOutputFfi {
    fn default() -> Self {
        CommonOutputFfi {
            result: 0,
            has_fatal_error: 0,
            events: EventArrayFfi::default(),
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct PersistedCompanionStatusFfi {
    pub template_id: u64,
    pub host_user_id: i32,
    pub companion_device_key: DeviceKeyFfi,
    pub is_valid: u8,
    pub enabled_business_ids: Int32Array64Ffi,
    pub added_time: u64,
    pub secure_protocol_id: u16,
    pub device_model: DataArray256Ffi,
    pub device_user_name: DataArray256Ffi,
    pub device_name: DataArray256Ffi,
}
assert_max_size!(PersistedCompanionStatusFfi);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct PersistedHostBindingStatusFfi {
    pub binding_id: i32,
    pub companion_user_id: i32,
    pub host_device_key: DeviceKeyFfi,
    pub is_token_valid: bool,
}
assert_max_size!(PersistedHostBindingStatusFfi);

#[repr(C)]
#[derive(Clone)]
pub struct CompanionStatusArrayFfi {
    pub data: [PersistedCompanionStatusFfi; MAX_TEMPLATE_ID_NUM_PER_USER_FFI],
    pub len: u32,
}
assert_max_size!(CompanionStatusArrayFfi);

impl Default for CompanionStatusArrayFfi {
    fn default() -> Self {
        CompanionStatusArrayFfi {
            data: [PersistedCompanionStatusFfi::default(); MAX_TEMPLATE_ID_NUM_PER_USER_FFI],
            len: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone)]
pub struct HostBindingStatusArrayFfi {
    pub data: [PersistedHostBindingStatusFfi; MAX_TEMPLATE_ID_NUM_PER_USER_FFI],
    pub len: u32,
}
assert_max_size!(HostBindingStatusArrayFfi);

impl Default for HostBindingStatusArrayFfi {
    fn default() -> Self {
        HostBindingStatusArrayFfi {
            data: [PersistedHostBindingStatusFfi::default(); MAX_TEMPLATE_ID_NUM_PER_USER_FFI],
            len: 0,
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct DeviceKeyFfi {
    pub device_id_type: i32,
    pub device_id: DataArray64Ffi,
    pub user_id: i32,
}

// Init
pub type InitInputFfi = PlaceHolderFfi;
pub type InitOutputFfi = PlaceHolderFfi;

// GetExecutorInfo
pub type GetExecutorInfoInputFfi = PlaceHolderFfi;

#[repr(C)]
#[derive(Copy, Clone)]
pub struct GetExecutorInfoOutputFfi {
    pub esl: i32,
    pub max_template_acl: i32,
    pub public_key: DataArray1024Ffi,
}
assert_max_size!(GetExecutorInfoOutputFfi);

// OnRegisterFinish
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostRegisterFinishInputFfi {
    pub template_ids: TemplateIdArrayFfi,
    pub public_key: DataArray1024Ffi,
    pub fwk_msg: DataArray1024Ffi,
}

pub type HostRegisterFinishOutputFfi = PlaceHolderFfi;

// host
// HostGetPersistedStatus
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostGetPersistedStatusInputFfi {
    pub user_id: i32,
}
assert_max_size!(HostGetPersistedStatusInputFfi);

#[repr(C)]
#[derive(Clone)]
pub struct HostGetPersistedStatusOutputFfi {
    pub companion_status_list: CompanionStatusArrayFfi,
}
assert_max_size!(HostGetPersistedStatusOutputFfi);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct SetActiveUserInputFfi {
    pub user_id: i32,
}
assert_max_size!(SetActiveUserInputFfi);

pub type SetActiveUserOutputFfi = PlaceHolderFfi;

// HostBeginCompanionCheck
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostBeginCompanionCheckInputFfi {
    pub request_id: i32,
}
assert_max_size!(HostBeginCompanionCheckInputFfi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostBeginCompanionCheckOutputFfi {
    pub challenge: u64,
    pub salt: [u8; SALT_LEN_FFI],
}
assert_max_size!(HostBeginCompanionCheckOutputFfi);

// HostEndCompanionCheck
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostEndCompanionCheckInputFfi {
    pub request_id: i32,
    pub template_id: u64,
    pub algorithm_list: Uint16Array64Ffi,
    pub capability_list: Uint16Array64Ffi,
    pub secure_protocol_id: u16,
    pub sec_message: DataArray1024Ffi, /* algorithm, capability_list, challenge*/
}
assert_max_size!(HostEndCompanionCheckInputFfi);

pub type HostEndCompanionCheckOutputFfi = PlaceHolderFfi;

// HostCancelCompanionCheck
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostCancelCompanionCheckInputFfi {
    pub request_id: i32,
}
assert_max_size!(HostCancelCompanionCheckInputFfi);

pub type HostCancelCompanionCheckOutputFfi = PlaceHolderFfi;

// HostGetInitKeyNegotiation
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostGetInitKeyNegotiationInputFfi {
    pub request_id: i32,
    pub secure_protocol_id: u16,
}
assert_max_size!(HostGetInitKeyNegotiationInputFfi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostGetInitKeyNegotiationOutputFfi {
    pub sec_message: DataArray1024Ffi, /* algorithm_list */
}
assert_max_size!(HostGetInitKeyNegotiationOutputFfi);

// HostBeginAddCompanion
#[repr(C)]
#[derive(Clone)]
pub struct HostBeginAddCompanionInputFfi {
    pub request_id: i32,
    pub schedule_id: u64,
    pub host_device_key: DeviceKeyFfi,
    pub companion_device_key: DeviceKeyFfi,
    pub fwk_message: DataArray1024Ffi,
    pub secure_protocol_id: u16,
    pub sec_message: DataArray1024Ffi, /* algo, challenge, pub_key */
}
assert_max_size!(HostBeginAddCompanionInputFfi);

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct HostBeginAddCompanionOutputFfi {
    pub sec_message: DataArray1024Ffi, /* device_id, user_id, pub_key, salt, tag, iv, encrypt_data(challenge, device_id, user_id) */
}
assert_max_size!(HostBeginAddCompanionOutputFfi);

// HostEndAddCompanion
#[repr(C)]
#[derive(Default, Clone)]
pub struct HostEndAddCompanionInputFfi {
    pub request_id: i32,
    pub companion_status: PersistedCompanionStatusFfi,
    pub secure_protocol_id: u16,
    pub sec_message: DataArray1024Ffi, /* device_id, user_id, track_ability_level, tag, iv, encrypt_data(device_id, user_id) */
}
assert_max_size!(HostEndAddCompanionInputFfi);

#[repr(C)]
#[derive(Default, Copy, Clone)]
pub struct HostEndAddCompanionOutputFfi {
    pub fwk_message: DataArray1024Ffi,
    pub template_id: u64,
}
assert_max_size!(HostEndAddCompanionOutputFfi);

// HostCancelAddCompanion
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostCancelAddCompanionInputFfi {
    pub request_id: i32,
}
assert_max_size!(HostCancelAddCompanionInputFfi);

pub type HostCancelAddCompanionOutputFfi = PlaceHolderFfi;

// HostRemoveCompanion
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostRemoveCompanionInputFfi {
    pub template_id: u64,
}
assert_max_size!(HostRemoveCompanionInputFfi);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct HostRemoveCompanionOutputFfi {
    pub user_id: i32,
    pub companion_device_key: DeviceKeyFfi,
}
assert_max_size!(HostRemoveCompanionOutputFfi);

// HostPreIssueToken
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostPreIssueTokenInputFfi {
    pub request_id: i32,
    pub template_id: u64,
    pub fwk_message: DataArray1024Ffi,
}
assert_max_size!(HostPreIssueTokenInputFfi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostPreIssueTokenOutputFfi {
    pub sec_message: DataArray1024Ffi, /* salt */
}
assert_max_size!(HostPreIssueTokenOutputFfi);

// HostBeginIssueToken
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostBeginIssueTokenInputFfi {
    pub request_id: i32,
    pub secure_protocol_id: u16,
    pub sec_message: DataArray1024Ffi, /* tag, iv, encrypt_data(challenge) */
}
assert_max_size!(HostBeginIssueTokenInputFfi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostBeginIssueTokenOutputFfi {
    pub sec_message: DataArray1024Ffi, /* tag, iv, encrypt_data(challenge, token, atl) */
}
assert_max_size!(HostBeginIssueTokenOutputFfi);

// HostEndIssueToken
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostEndIssueTokenInputFfi {
    pub request_id: i32,
    pub secure_protocol_id: u16,
    pub sec_message: DataArray1024Ffi, /* result */
}
assert_max_size!(HostEndIssueTokenInputFfi);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct HostEndIssueTokenOutputFfi {
    pub atl: i32,
}
assert_max_size!(HostEndIssueTokenOutputFfi);

// HostCancelIssueToken
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostCancelIssueTokenInputFfi {
    pub request_id: i32,
}
assert_max_size!(HostCancelIssueTokenInputFfi);

pub type HostCancelIssueTokenOutputFfi = PlaceHolderFfi;

// HostBeginTokenAuth
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostBeginTokenAuthInputFfi {
    pub request_id: i32,
    pub schedule_id: u64,
    pub template_id: u64,
    pub fwk_message: DataArray1024Ffi,
}
assert_max_size!(HostBeginTokenAuthInputFfi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostBeginTokenAuthOutputFfi {
    pub sec_message: DataArray1024Ffi, /* salt, tag, iv, encrypt_data(challenge, atl) */
}
assert_max_size!(HostBeginTokenAuthOutputFfi);

// HostEndTokenAuth
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostEndTokenAuthInputFfi {
    pub request_id: i32,
    pub template_id: u64,
    pub secure_protocol_id: u16,
    pub sec_message: DataArray1024Ffi, /* mac */
}
assert_max_size!(HostEndTokenAuthInputFfi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostEndTokenAuthOutputFfi {
    pub fwk_message: DataArray1024Ffi,
}
assert_max_size!(HostEndTokenAuthOutputFfi);

// HostRevokeToken
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostRevokeTokenInputFfi {
    pub template_id: u64,
}
assert_max_size!(HostRevokeTokenInputFfi);

pub type HostRevokeTokenOutputFfi = PlaceHolderFfi;

// HostUpdateCompanionStatus
#[repr(C)]
#[derive(Clone)]
pub struct HostUpdateCompanionStatusInputFfi {
    pub template_id: u64,
    pub device_name: DataArray256Ffi,
    pub device_user_name: DataArray256Ffi,
}
assert_max_size!(HostUpdateCompanionStatusInputFfi);

pub type HostUpdateCompanionStatusOutputFfi = PlaceHolderFfi;

// HostUpdateCompanionEnabledBusinessIds
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostUpdateCompanionEnabledBusinessIdsInputFfi {
    pub template_id: u64,
    pub business_ids: Int32Array64Ffi,
}
assert_max_size!(HostUpdateCompanionEnabledBusinessIdsInputFfi);

pub type HostUpdateCompanionEnabledBusinessIdsOutputFfi = PlaceHolderFfi;

// HostBeginDelegateAuth
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostBeginDelegateAuthInputFfi {
    pub request_id: i32,
    pub schedule_id: u64,
    pub template_id: u64,
    pub fwk_message: DataArray1024Ffi,
}
assert_max_size!(HostBeginDelegateAuthInputFfi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostBeginDelegateAuthOutputFfi {
    pub sec_message: DataArray1024Ffi, /* salt, tag, iv, encrypt_data(challenge, atl) */
}
assert_max_size!(HostBeginDelegateAuthOutputFfi);

// HostEndDelegateAuth
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostEndDelegateAuthInputFfi {
    pub request_id: i32,
    pub secure_protocol_id: u16,
    pub sec_message: DataArray1024Ffi,
}
assert_max_size!(HostEndDelegateAuthInputFfi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostEndDelegateAuthOutputFfi {
    pub fwk_message: DataArray1024Ffi,
    pub auth_type: i32,
    pub atl: i32,
}
assert_max_size!(HostEndDelegateAuthOutputFfi);

// HostCancelDelegateAuth
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostCancelDelegateAuthInputFfi {
    pub request_id: i32,
}
assert_max_size!(HostCancelDelegateAuthInputFfi);

pub type HostCancelDelegateAuthOutputFfi = PlaceHolderFfi;

// HostProcessPreObtainTokenInput
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostProcessPreObtainTokenInputFfi {
    pub request_id: i32,
    pub template_id: u64,
    pub secure_protocol_id: u16,
}
assert_max_size!(HostProcessPreObtainTokenInputFfi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostProcessPreObtainTokenOutputFfi {
    pub sec_message: DataArray1024Ffi, /* salt, challenge */
}
assert_max_size!(HostProcessPreObtainTokenOutputFfi);

// HostProcessObtainTokenInput
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostProcessObtainTokenInputFfi {
    pub request_id: i32,
    pub template_id: u64,
    pub secure_protocol_id: u16,
    pub sec_message: DataArray1024Ffi, /* tag, iv, encrypt_data(challenge, atl) */
}
assert_max_size!(HostProcessObtainTokenInputFfi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostProcessObtainTokenOutputFfi {
    pub sec_message: DataArray1024Ffi, /* tag, iv, encrypt_data(challenge, token, atl) */
    pub atl: i32,
}
assert_max_size!(HostProcessObtainTokenOutputFfi);

// HostCancelObtainTokenInput
#[repr(C)]
#[derive(Copy, Clone)]
pub struct HostCancelObtainTokenInputFfi {
    pub request_id: i32,
}
assert_max_size!(HostCancelObtainTokenInputFfi);

pub type HostCancelObtainTokenOutputFfi = PlaceHolderFfi;

// companion
// CompanionGetPersistedStatus
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionGetPersistedStatusInputFfi {
    pub user_id: i32,
}
assert_max_size!(CompanionGetPersistedStatusInputFfi);

#[repr(C)]
#[derive(Clone)]
pub struct CompanionGetPersistedStatusOutputFfi {
    pub binding_status_list: HostBindingStatusArrayFfi,
}
assert_max_size!(CompanionGetPersistedStatusOutputFfi);

// CompanionProcessCheck
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionProcessCheckInputFfi {
    pub binding_id: i32,
    pub capability_list: Uint16Array64Ffi,
    pub secure_protocol_id: u16,
    pub salt: [u8; SALT_LEN_FFI],
    pub challenge: u64,
    pub sec_message: DataArray1024Ffi, /* algorithm_list, capability_list */
}
assert_max_size!(CompanionProcessCheckInputFfi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionProcessCheckOutputFfi {
    pub sec_message: DataArray1024Ffi, /* salt, tag, iv, encrypt_data(algorithm, capability_list, challenge) */
}
assert_max_size!(CompanionProcessCheckOutputFfi);

// CompanionInitKeyNegotiation
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionInitKeyNegotiationInputFfi {
    pub request_id: i32,
    pub secure_protocol_id: u16,
    pub companion_device_key: DeviceKeyFfi,
    pub host_device_key: DeviceKeyFfi,
    pub sec_message: DataArray1024Ffi, /* algorithm_list */
}
assert_max_size!(CompanionInitKeyNegotiationInputFfi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionInitKeyNegotiationOutputFfi {
    pub sec_message: DataArray1024Ffi, /* challenge, algorithm, algorithm_data */
}
assert_max_size!(CompanionInitKeyNegotiationOutputFfi);

// CompanionBeginAddHostBinding
#[repr(C)]
#[derive(Clone)]
pub struct CompanionBeginAddHostBindingInputFfi {
    pub request_id: i32,
    pub secure_protocol_id: u16,
    pub sec_message: DataArray1024Ffi, /* device_id, user_id, pub_key, salt, tag, iv, encrypt_data(challenge, device_id, user_id) */
}
assert_max_size!(CompanionBeginAddHostBindingInputFfi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionBeginAddHostBindingOutputFfi {
    pub sec_message: DataArray1024Ffi, /* device_id, user_id, track_ability_level, tag, iv, encrypt_data(device_id, user_id) */
    pub binding_id: i32,
    pub binding_status: PersistedHostBindingStatusFfi,
}
assert_max_size!(CompanionBeginAddHostBindingOutputFfi);

// CompanionEndAddHostBinding
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionEndAddHostBindingInputFfi {
    pub request_id: i32,
    pub result: i32,
}
assert_max_size!(CompanionEndAddHostBindingInputFfi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionEndAddHostBindingOutputFfi {
    pub binding_id: i32,
}
assert_max_size!(CompanionEndAddHostBindingOutputFfi);

// CompanionRemoveHostBinding
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionRemoveHostBindingInputFfi {
    pub binding_id: i32,
}
assert_max_size!(CompanionRemoveHostBindingInputFfi);

pub type CompanionRemoveHostBindingOutputFfi = PlaceHolderFfi;

// CompanionPreIssueToken
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionPreIssueTokenInputFfi {
    pub request_id: i32,
    pub binding_id: i32,
    pub secure_protocol_id: u16,
    pub sec_message: DataArray1024Ffi, /* salt */
}
assert_max_size!(CompanionPreIssueTokenInputFfi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionPreIssueTokenOutputFfi {
    pub sec_message: DataArray1024Ffi, /* tag, iv, encrypt_data(challenge) */
}
assert_max_size!(CompanionPreIssueTokenOutputFfi);

// CompanionProcessIssueToken
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionProcessIssueTokenInputFfi {
    pub request_id: i32,
    pub secure_protocol_id: u16,
    pub sec_message: DataArray1024Ffi, /* tag, iv, encrypt_data(challenge, token, atl) */
}
assert_max_size!(CompanionProcessIssueTokenInputFfi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionProcessIssueTokenOutputFfi {
    pub sec_message: DataArray1024Ffi, /* result */
}
assert_max_size!(CompanionProcessIssueTokenOutputFfi);

// CompanionCancelIssueToken
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionCancelIssueTokenInputFfi {
    pub request_id: i32,
}
assert_max_size!(CompanionCancelIssueTokenInputFfi);

pub type CompanionCancelIssueTokenOutputFfi = PlaceHolderFfi;

// CompanionProcessTokenAuth
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionProcessTokenAuthInputFfi {
    pub binding_id: i32,
    pub secure_protocol_id: u16,
    pub sec_message: DataArray1024Ffi, /* salt, tag, iv, encrypt_data(challenge, atl) */
}
assert_max_size!(CompanionProcessTokenAuthInputFfi);

#[repr(C)]
#[derive(Copy, Clone, Default)]
pub struct CompanionProcessTokenAuthOutputFfi {
    pub sec_message: DataArray1024Ffi, /* mac */
}
assert_max_size!(CompanionProcessTokenAuthOutputFfi);

// CompanionRevokeToken
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionRevokeTokenInputFfi {
    pub binding_id: i32,
}
assert_max_size!(CompanionRevokeTokenInputFfi);

pub type CompanionRevokeTokenOutputFfi = PlaceHolderFfi;

// CompanionBeginDelegateAuth
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionBeginDelegateAuthInputFfi {
    pub request_id: i32,
    pub binding_id: i32,
    pub secure_protocol_id: u16,
    pub sec_message: DataArray1024Ffi, /* salt, tag, iv, encrypt_data(challenge, atl) */
}
assert_max_size!(CompanionBeginDelegateAuthInputFfi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionBeginDelegateAuthOutputFfi {
    pub challenge: u64,
    pub atl: i32,
}
assert_max_size!(CompanionBeginDelegateAuthOutputFfi);

// CompanionEndDelegateAuth
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionEndDelegateAuthInputFfi {
    pub request_id: i32,
    pub result: i32,
    pub auth_token: [u8; AUTH_TOKEN_SIZE_FFI],
}
assert_max_size!(CompanionEndDelegateAuthInputFfi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionEndDelegateAuthOutputFfi {
    pub sec_message: DataArray1024Ffi, /* salt, tag, iv, encrypt_data(challenge, atl, authType)) */
}
assert_max_size!(CompanionEndDelegateAuthOutputFfi);

// CompanionBeginObtainToken
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionBeginObtainTokenInputFfi {
    pub request_id: i32,
    pub binding_id: i32,
    pub fwk_message: DataArray1024Ffi,
    pub secure_protocol_id: u16,
    pub sec_message: DataArray1024Ffi, /* salt, challenge */
}
assert_max_size!(CompanionBeginObtainTokenInputFfi);

#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionBeginObtainTokenOutputFfi {
    pub sec_message: DataArray1024Ffi, /* tag, iv, encrypt_data(challenge, atl) */
}
assert_max_size!(CompanionBeginObtainTokenOutputFfi);

// CompanionEndObtainToken
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionEndObtainTokenInputFfi {
    pub request_id: i32,
    pub secure_protocol_id: u16,
    pub sec_message: DataArray1024Ffi, /* tag, iv, encrypt_data(challenge, token, atl) */
}
assert_max_size!(CompanionEndObtainTokenInputFfi);

pub type CompanionEndObtainTokenOutputFfi = PlaceHolderFfi;

//CompanionCancelObtainToken
#[repr(C)]
#[derive(Copy, Clone)]
pub struct CompanionCancelObtainTokenInputFfi {
    pub request_id: i32,
}

pub type CompanionCancelObtainTokenOutputFfi = PlaceHolderFfi;

#[repr(i32)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum CommandId {
    Init = 1,
    GetExecutorInfo = 2,

    // host
    HostRegisterFinish = 1001,
    HostGetPersistedStatus = 1002,
    HostBeginCompanionCheck = 1003,
    HostEndCompanionCheck = 1004,
    HostCancelCompanionCheck = 1005,
    HostGetInitKeyNegotiation = 1006,
    HostBeginAddCompanion = 1007,
    HostEndAddCompanion = 1008,
    HostCancelAddCompanion = 1009,
    HostRemoveCompanion = 1010,
    HostPreIssueToken = 1011,
    HostBeginIssueToken = 1012,
    HostEndIssueToken = 1013,
    HostCancelIssueToken = 1014,
    HostBeginTokenAuth = 1015,
    HostEndTokenAuth = 1016,
    HostRevokeToken = 1017,
    HostUpdateCompanionStatus = 1018,
    HostUpdateCompanionEnabledBusinessIds = 1019,
    HostBeginDelegateAuth = 1020,
    HostEndDelegateAuth = 1021,
    HostCancelDelegateAuth = 1022,
    HostProcessPreObtainToken = 1023,
    HostProcessObtainToken = 1024,
    HostCancelObtainToken = 1025,

    // companion
    CompanionGetPersistedStatus = 2000,
    CompanionProcessCheck = 2001,
    CompanionInitKeyNegotiation = 2002,
    CompanionBeginAddHostBinding = 2003,
    CompanionEndAddHostBinding = 2004,
    CompanionRemoveHostBinding = 2005,
    CompanionPreIssueToken = 2006,
    CompanionProcessIssueToken = 2007,
    CompanionCancelIssueToken = 2008,
    CompanionProcessTokenAuth = 2009,
    CompanionRevokeToken = 2010,
    CompanionBeginDelegateAuth = 2011,
    CompanionEndDelegateAuth = 2012,
    CompanionBeginObtainToken = 2013,
    CompanionEndObtainToken = 2014,
    CompanionCancelObtainToken = 2015,
}

impl TryFrom<i32> for CommandId {
    type Error = ErrorCode;
    fn try_from(value: i32) -> Result<Self, ErrorCode> {
        match value {
            1 => Ok(CommandId::Init),
            2 => Ok(CommandId::GetExecutorInfo),
            1001 => Ok(CommandId::HostRegisterFinish),
            1002 => Ok(CommandId::HostGetPersistedStatus),
            1003 => Ok(CommandId::HostBeginCompanionCheck),
            1004 => Ok(CommandId::HostEndCompanionCheck),
            1005 => Ok(CommandId::HostCancelCompanionCheck),
            1006 => Ok(CommandId::HostGetInitKeyNegotiation),
            1007 => Ok(CommandId::HostBeginAddCompanion),
            1008 => Ok(CommandId::HostEndAddCompanion),
            1009 => Ok(CommandId::HostCancelAddCompanion),
            1010 => Ok(CommandId::HostRemoveCompanion),
            1011 => Ok(CommandId::HostPreIssueToken),
            1012 => Ok(CommandId::HostBeginIssueToken),
            1013 => Ok(CommandId::HostEndIssueToken),
            1014 => Ok(CommandId::HostCancelIssueToken),
            1015 => Ok(CommandId::HostBeginTokenAuth),
            1016 => Ok(CommandId::HostEndTokenAuth),
            1017 => Ok(CommandId::HostRevokeToken),
            1018 => Ok(CommandId::HostUpdateCompanionStatus),
            1019 => Ok(CommandId::HostUpdateCompanionEnabledBusinessIds),
            1020 => Ok(CommandId::HostBeginDelegateAuth),
            1021 => Ok(CommandId::HostEndDelegateAuth),
            1022 => Ok(CommandId::HostCancelDelegateAuth),
            1023 => Ok(CommandId::HostProcessPreObtainToken),
            1024 => Ok(CommandId::HostProcessObtainToken),
            1025 => Ok(CommandId::HostCancelObtainToken),
            2000 => Ok(CommandId::CompanionGetPersistedStatus),
            2001 => Ok(CommandId::CompanionProcessCheck),
            2002 => Ok(CommandId::CompanionInitKeyNegotiation),
            2003 => Ok(CommandId::CompanionBeginAddHostBinding),
            2004 => Ok(CommandId::CompanionEndAddHostBinding),
            2005 => Ok(CommandId::CompanionRemoveHostBinding),
            2006 => Ok(CommandId::CompanionPreIssueToken),
            2007 => Ok(CommandId::CompanionProcessIssueToken),
            2008 => Ok(CommandId::CompanionCancelIssueToken),
            2009 => Ok(CommandId::CompanionProcessTokenAuth),
            2010 => Ok(CommandId::CompanionRevokeToken),
            2011 => Ok(CommandId::CompanionBeginDelegateAuth),
            2012 => Ok(CommandId::CompanionEndDelegateAuth),
            2013 => Ok(CommandId::CompanionBeginObtainToken),
            2014 => Ok(CommandId::CompanionEndObtainToken),
            2015 => Ok(CommandId::CompanionCancelObtainToken),
            _ => {
                log_e!("Invalid command id: {}", value);
                Err(ErrorCode::BadParam)
            }
        }
    }
}

#[repr(i32)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub enum CallerTypeFfi {
    Ca = 0,
    Ta = 1,
}

// cbindgen module
#[cxx::bridge]
mod ffi {
    pub struct RustCommandParam {
        pub command_id: i32,
        pub caller_type: i32,
        pub caller_udid: [u8; 64],
        pub input_data: *const u8,
        pub input_data_len: u32,
        pub output_data: *mut u8,
        pub output_data_len: u32,
        pub common_output_data: *mut u8,
        pub common_output_data_len: u32,
    }

    extern "Rust" {
        fn init_rust_env() -> i32;
        fn uninit_rust_env() -> i32;
        fn invoke_rust_command(param: RustCommandParam) -> i32;
    }
}

pub use ffi::RustCommandParam;

// #[repr(C)]
// pub struct RustCommandParam {
//     pub command_id: i32,
//     pub caller_type: i32,
//     pub caller_udid: [u8; UDID_LEN_FFI],
//     pub input_data: *const u8,
//     pub input_data_len: u32,
//     pub output_data: *mut u8,
//     pub output_data_len: u32,
//     pub common_output_data: *mut u8,
//     pub common_output_data_len: u32,
// }

#[no_mangle]
pub extern "C" fn init_rust_env() -> i32 {
    match handle_rust_env_init() {
        Ok(_) => 0,
        Err(e) => e as i32,
    }
}

#[no_mangle]
pub extern "C" fn uninit_rust_env() -> i32 {
    match handle_rust_env_uninit() {
        Ok(_) => 0,
        Err(e) => e as i32,
    }
}

fn invoke_rust_command_inner(param: RustCommandParam) -> Result<(), ErrorCode> {
    ensure_or_return_val!(param.input_data_len != 0, ErrorCode::BadParam);
    ensure_or_return_val!(!param.input_data.is_null(), ErrorCode::BadParam);
    ensure_or_return_val!(param.output_data_len != 0, ErrorCode::BadParam);
    ensure_or_return_val!(!param.output_data.is_null(), ErrorCode::BadParam);
    ensure_or_return_val!(
        param.common_output_data_len as usize == mem::size_of::<CommonOutputFfi>(),
        ErrorCode::BadParam
    );
    ensure_or_return_val!(!param.common_output_data.is_null(), ErrorCode::BadParam);

    let input = unsafe { slice::from_raw_parts(param.input_data, param.input_data_len as usize) };
    let output =
        unsafe { slice::from_raw_parts_mut(param.output_data, param.output_data_len as usize) };
    let common_output = unsafe {
        slice::from_raw_parts_mut(
            param.common_output_data,
            param.common_output_data_len as usize,
        )
    };

    handle_rust_command(param.command_id, input, output, common_output)
}

#[no_mangle]
pub extern "C" fn invoke_rust_command(param: RustCommandParam) -> i32 {
    match invoke_rust_command_inner(param) {
        Ok(_) => 0,
        Err(e) => e as i32,
    }
}
