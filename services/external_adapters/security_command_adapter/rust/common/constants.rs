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

use crate::log_e;
use crate::utils::AttributeKey;

pub const CHALLENGE_LEN: usize = 8;
pub const AUTH_TOKEN_CHALLENGE_LEN: usize = 32;
pub const UDID_LEN: usize = 64;
pub const SHA256_DIGEST_SIZE: usize = 32;
pub const HKDF_SALT_SIZE: usize = 32;
pub const AES_GCM_TAG_SIZE: usize = 16;
pub const AES_GCM_IV_SIZE: usize = 12;
pub const AES_GCM_AAD: &str = "CDA_AES_MSG_DATA";
pub const TOKEN_KEY_LEN: usize = 32;
pub const SHARE_KEY_LEN: usize = 32;
pub const MAX_EVENT_NUM: usize = 20;
pub const INVALID_USER_ID: i32 = -1;
pub const ABANDON_PIN_VALID_PERIOD: u64 = 96 * 3600 * 1000;
pub const SECURE_RANDOM_MAX_ATTEMPTS: usize = 100;

#[derive(Clone, Copy, PartialEq, Debug)]
#[repr(i32)]
#[derive(Default)]
pub enum ErrorCode {
    Success = 0,
    Fail = 1,
    #[default]
    GeneralError = 2,
    Canceled = 3,
    Timeout = 4,
    TypeNotSupport = 5,
    TrustLevelNotSupport = 6,
    Busy = 7,
    BadParam = 8,
    ReadParcelError = 9,
    WriteParcelError = 10,
    NotFound = 11,
    BadSign = 12,
    IdExists = 13,
    ExceedLimit = 14,
}

impl TryFrom<i32> for ErrorCode {
    type Error = ErrorCode;
    fn try_from(value: i32) -> Result<Self, ErrorCode> {
        match value {
            0 => Ok(ErrorCode::Success),
            1 => Ok(ErrorCode::Fail),
            2 => Ok(ErrorCode::GeneralError),
            3 => Ok(ErrorCode::Canceled),
            4 => Ok(ErrorCode::Timeout),
            5 => Ok(ErrorCode::TypeNotSupport),
            6 => Ok(ErrorCode::TrustLevelNotSupport),
            7 => Ok(ErrorCode::Busy),
            8 => Ok(ErrorCode::BadParam),
            9 => Ok(ErrorCode::ReadParcelError),
            10 => Ok(ErrorCode::WriteParcelError),
            11 => Ok(ErrorCode::NotFound),
            12 => Ok(ErrorCode::BadSign),
            13 => Ok(ErrorCode::IdExists),
            14 => Ok(ErrorCode::ExceedLimit),
            _ => {
                log_e!("Invalid error code: {}", value);
                Err(ErrorCode::BadParam)
            },
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Debug)]
#[repr(i32)]
#[derive(Default)]
pub enum AuthSecurityLevel {
    #[default]
    Asl0 = 0,
    Asl1 = 1,
    Asl2 = 2,
    Asl3 = 3,
    MaxAsl = 4,
}

impl TryFrom<i32> for AuthSecurityLevel {
    type Error = ErrorCode;
    fn try_from(value: i32) -> core::result::Result<Self, ErrorCode> {
        match value {
            0 => Ok(AuthSecurityLevel::Asl0),
            1 => Ok(AuthSecurityLevel::Asl1),
            2 => Ok(AuthSecurityLevel::Asl2),
            3 => Ok(AuthSecurityLevel::Asl3),
            4 => Ok(AuthSecurityLevel::MaxAsl),
            _ => {
                log_e!("Invalid auth security level: {}", value);
                Err(ErrorCode::BadParam)
            },
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Debug)]
#[repr(i32)]
#[derive(Default)]
pub enum ExecutorSecurityLevel {
    #[default]
    Esl0 = 0,
    Esl1 = 1,
    Esl2 = 2,
    Esl3 = 3,
}

impl TryFrom<i32> for ExecutorSecurityLevel {
    type Error = ErrorCode;
    fn try_from(value: i32) -> core::result::Result<Self, ErrorCode> {
        match value {
            0 => Ok(ExecutorSecurityLevel::Esl0),
            1 => Ok(ExecutorSecurityLevel::Esl1),
            2 => Ok(ExecutorSecurityLevel::Esl2),
            3 => Ok(ExecutorSecurityLevel::Esl3),
            _ => {
                log_e!("Invalid executor security level: {}", value);
                Err(ErrorCode::BadParam)
            },
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Debug)]
#[repr(u32)]
#[derive(Default)]
pub enum AuthCapabilityLevel {
    #[default]
    Acl0 = 0,
    Acl1 = 1,
    Acl2 = 2,
    Acl3 = 3,
    Acl4 = 4,
}

impl TryFrom<i32> for AuthCapabilityLevel {
    type Error = ErrorCode;
    fn try_from(value: i32) -> core::result::Result<Self, ErrorCode> {
        match value {
            0 => Ok(AuthCapabilityLevel::Acl0),
            1 => Ok(AuthCapabilityLevel::Acl1),
            2 => Ok(AuthCapabilityLevel::Acl2),
            3 => Ok(AuthCapabilityLevel::Acl3),
            4 => Ok(AuthCapabilityLevel::Acl4),
            _ => {
                log_e!("Invalid auth capability level: {}", value);
                Err(ErrorCode::BadParam)
            },
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Debug)]
#[repr(i32)]
#[derive(Default)]
pub enum AuthTrustLevel {
    #[default]
    Atl0 = 0,
    Atl1 = 10000,
    Atl2 = 20000,
    Atl3 = 30000,
    Atl4 = 40000,
}

impl TryFrom<i32> for AuthTrustLevel {
    type Error = ErrorCode;

    fn try_from(value: i32) -> core::result::Result<Self, ErrorCode> {
        match value {
            0 => Ok(AuthTrustLevel::Atl0),
            10000 => Ok(AuthTrustLevel::Atl1),
            20000 => Ok(AuthTrustLevel::Atl2),
            30000 => Ok(AuthTrustLevel::Atl3),
            40000 => Ok(AuthTrustLevel::Atl4),
            _ => {
                log_e!("Invalid auth trust level: {}", value);
                Err(ErrorCode::BadParam)
            },
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Debug)]
#[repr(i32)]
#[derive(Default)]
pub enum TrackAbilityLevel {
    #[default]
    Tal0 = 0,
    Tal1 = 1,
    Tal2 = 2,
    Tal3 = 3,
    Tal4 = 4,
}

impl TryFrom<i32> for TrackAbilityLevel {
    type Error = ErrorCode;

    fn try_from(value: i32) -> core::result::Result<Self, ErrorCode> {
        match value {
            0 => Ok(TrackAbilityLevel::Tal0),
            1 => Ok(TrackAbilityLevel::Tal1),
            2 => Ok(TrackAbilityLevel::Tal2),
            3 => Ok(TrackAbilityLevel::Tal3),
            4 => Ok(TrackAbilityLevel::Tal4),
            _ => {
                log_e!("Invalid track ability level: {}", value);
                Err(ErrorCode::BadParam)
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(i32)]
pub enum DeviceType {
    Default = 0,
}

impl DeviceType {
    pub fn companion_from_secure_protocol_id(secure_protocol_id: u16) -> Result<DeviceType, ErrorCode> {
        match SecureProtocolId::try_from(secure_protocol_id)? {
            SecureProtocolId::Default => Ok(DeviceType::Default),
            _ => {
                log_e!("secure_protocol_id type is not support, secure_protocol_id: {}", secure_protocol_id);
                Err(ErrorCode::BadParam)
            },
        }
    }
}

impl TryFrom<i32> for DeviceType {
    type Error = ErrorCode;
    fn try_from(value: i32) -> core::result::Result<Self, ErrorCode> {
        match value {
            0 => Ok(DeviceType::Default),
            _ => {
                log_e!("device type: {:?}", value);
                Err(ErrorCode::BadParam)
            },
        }
    }
}

impl TryFrom<AttributeKey> for DeviceType {
    type Error = ErrorCode;
    fn try_from(value: AttributeKey) -> core::result::Result<Self, ErrorCode> {
        match value {
            AttributeKey::AttrMessage => Ok(DeviceType::Default),
            _ => {
                log_e!("attribute key: {:?}", value);
                Err(ErrorCode::BadParam)
            },
        }
    }
}

impl TryFrom<DeviceType> for AttributeKey {
    type Error = ErrorCode;
    fn try_from(value: DeviceType) -> core::result::Result<Self, ErrorCode> {
        match value {
            DeviceType::Default => Ok(AttributeKey::AttrMessage),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeviceCapability {
    pub device_type: DeviceType,
    pub esl: ExecutorSecurityLevel,
    pub track_ability_level: TrackAbilityLevel,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
#[derive(Default)]
pub enum AlgoType {
    #[default]
    None = 0,
    X25519 = 1,
}

impl TryFrom<u16> for AlgoType {
    type Error = ErrorCode;
    fn try_from(value: u16) -> core::result::Result<Self, ErrorCode> {
        match value {
            1 => Ok(AlgoType::X25519),
            _ => {
                log_e!("Invalid algo type: {}", value);
                Err(ErrorCode::BadParam)
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
#[derive(Default)]
pub enum SecureProtocolId {
    #[default]
    Invalid = 0,
    Default = 1,
}

impl TryFrom<u16> for SecureProtocolId {
    type Error = ErrorCode;
    fn try_from(value: u16) -> core::result::Result<Self, ErrorCode> {
        match value {
            0 => Ok(SecureProtocolId::Invalid),
            1 => Ok(SecureProtocolId::Default),
            _ => {
                log_e!("Invalid secure protocol id: {}", value);
                Err(ErrorCode::BadParam)
            },
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Debug)]
#[repr(u32)]
#[derive(Default)]
pub enum AuthType {
    #[default]
    Default = 0,
    Pin = 1,
    Face = 2,
    Fingerprint = 4,
    CompanionDevice = 64,
}

impl TryFrom<u32> for AuthType {
    type Error = ErrorCode;
    fn try_from(value: u32) -> core::result::Result<Self, ErrorCode> {
        match value {
            0 => Ok(AuthType::Default),
            1 => Ok(AuthType::Pin),
            2 => Ok(AuthType::Face),
            4 => Ok(AuthType::Fingerprint),
            64 => Ok(AuthType::CompanionDevice),
            _ => {
                log_e!("Invalid auth capability level: {}", value);
                Err(ErrorCode::BadParam)
            },
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Debug)]
#[repr(u16)]
#[derive(Default)]
pub enum Capability {
    #[default]
    Invalid = 0,
    DelegateAuth = 1,
    TokenAuth = 2,
}

impl TryFrom<u16> for Capability {
    type Error = ErrorCode;
    fn try_from(value: u16) -> core::result::Result<Self, ErrorCode> {
        match value {
            0 => Ok(Capability::Invalid),
            1 => Ok(Capability::DelegateAuth),
            2 => Ok(Capability::TokenAuth),
            _ => {
                log_e!("Invalid capability level: {}", value);
                Err(ErrorCode::BadParam)
            },
        }
    }
}

pub const PROTOCOL_VERSION: &[u16] = &[1];
pub const SUPPORT_CAPABILITY: &[u16] = &[Capability::DelegateAuth as u16, Capability::TokenAuth as u16];
