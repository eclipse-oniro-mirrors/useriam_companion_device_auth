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
use core::ops;

pub const PUBLIC_KEY_LEN: usize = 32;
pub const CHALLENGE_LEN: usize = 8;
pub const UDID_LEN: usize = 64;
pub const UUID_LEN: usize = 16;
pub const ROOT_SECRET_LEN: usize = 32;
pub const ED25519_FIX_SIGN_BUFFER_SIZE: usize = 64;
pub const SHA256_DIGEST_SIZE: usize = 32;
pub const HKDF_SALT_SIZE: usize = 32;
pub const AES_GCM_TAG_SIZE: usize = 16;
pub const AES_GCM_IV_SIZE: usize = 12;
pub const TOKEN_KEY_LEN: usize = 32;
pub const MAX_EVENT_NUM: usize = 20;
pub const INVALID_USER_ID: i32 = -1;
pub const ABANDON_PIN_VALID_PERIOD: u64 = 96 * 3600 * 1000;

#[derive(Clone, Copy, PartialEq, Debug)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
#[repr(i32)]
pub enum ErrorCode {
    Success = 0,
    Fail = 1,
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
}

impl Default for ErrorCode {
    fn default() -> Self {
        ErrorCode::GeneralError
    }
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
            _ => {
                log_e!("Invalid error code: {}", value);
                Err(ErrorCode::BadParam)
            }
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Debug)]
#[repr(i32)]
pub enum AuthSecurityLevel {
    Asl0 = 0,
    Asl1 = 1,
    Asl2 = 2,
    Asl3 = 3,
    MaxAsl = 4,
}

impl Default for AuthSecurityLevel {
    fn default() -> Self {
        AuthSecurityLevel::Asl0
    }
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
            }
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
#[repr(i32)]
pub enum ExecutorSecurityLevel {
    Esl0 = 0,
    Esl1 = 1,
    Esl2 = 2,
    Esl3 = 3,
    MaxEsl = 4,
}

impl Default for ExecutorSecurityLevel {
    fn default() -> Self {
        ExecutorSecurityLevel::Esl0
    }
}

impl TryFrom<i32> for ExecutorSecurityLevel {
    type Error = ErrorCode;
    fn try_from(value: i32) -> core::result::Result<Self, ErrorCode> {
        match value {
            0 => Ok(ExecutorSecurityLevel::Esl0),
            1 => Ok(ExecutorSecurityLevel::Esl1),
            2 => Ok(ExecutorSecurityLevel::Esl2),
            3 => Ok(ExecutorSecurityLevel::Esl3),
            4 => Ok(ExecutorSecurityLevel::MaxEsl),
            _ => {
                log_e!("Invalid executor security level: {}", value);
                Err(ErrorCode::BadParam)
            }
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
#[repr(u32)]
pub enum AuthCapabilityLevel {
    Acl0 = 0,
    Acl1 = 1,
    Acl2 = 2,
    Acl3 = 3,
    MaxAcl = 4,
}

impl Default for AuthCapabilityLevel {
    fn default() -> Self {
        AuthCapabilityLevel::Acl0
    }
}

impl TryFrom<i32> for AuthCapabilityLevel {
    type Error = ErrorCode;
    fn try_from(value: i32) -> core::result::Result<Self, ErrorCode> {
        match value {
            0 => Ok(AuthCapabilityLevel::Acl0),
            1 => Ok(AuthCapabilityLevel::Acl1),
            2 => Ok(AuthCapabilityLevel::Acl2),
            3 => Ok(AuthCapabilityLevel::Acl3),
            _ => {
                log_e!("Invalid auth capability level: {}", value);
                Err(ErrorCode::BadParam)
            }
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Debug)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
#[repr(i32)]
pub enum AuthTrustLevel {
    Atl0 = 0,
    Atl1 = 10000,
    Atl2 = 20000,
    Atl3 = 30000,
    Atl4 = 40000,
    MaxAtl = 5,
}

impl Default for AuthTrustLevel {
    fn default() -> Self {
        AuthTrustLevel::Atl0
    }
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
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(i32)]
pub enum ExecutorRole {
    Collector = 1,
    Verifier = 2,
    AllInOne = 3,
}

impl Default for ExecutorRole {
    fn default() -> Self {
        ExecutorRole::Collector
    }
}

impl TryFrom<i32> for ExecutorRole {
    type Error = ErrorCode;
    fn try_from(value: i32) -> core::result::Result<Self, ErrorCode> {
        match value {
            1 => Ok(ExecutorRole::Collector),
            2 => Ok(ExecutorRole::Verifier),
            3 => Ok(ExecutorRole::AllInOne),
            _ => {
                log_e!("Invalid executor role: {}", value);
                Err(ErrorCode::BadParam)
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(i32)]
pub enum DeviceType {
    None = 0,
    Mcu = 1,
    Ap = 2,
}

impl TryFrom<i32> for DeviceType {
    type Error = ErrorCode;
    fn try_from(value: i32) -> core::result::Result<Self, ErrorCode> {
        match value {
            0 => Ok(DeviceType::None),
            1 => Ok(DeviceType::Mcu),
            2 => Ok(DeviceType::Ap),
            _ => {
                log_e!("device type: {}", value);
                Err(ErrorCode::BadParam)
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeviceCapability {
    pub device_type: DeviceType,
    pub esl: ExecutorSecurityLevel,
    pub track_ability_level: i32,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
pub enum AlgoType {
    None = 0,
    X25519 = 1,
    P256 = 2,
    Rsa = 3,
}

impl Default for AlgoType {
    fn default() -> Self {
        AlgoType::None
    }
}

impl TryFrom<u16> for AlgoType {
    type Error = ErrorCode;
    fn try_from(value: u16) -> core::result::Result<Self, ErrorCode> {
        match value {
            1 => Ok(AlgoType::X25519),
            2 => Ok(AlgoType::P256),
            3 => Ok(AlgoType::Rsa),
            _ => {
                log_e!("Invalid algo type: {}", value);
                Err(ErrorCode::BadParam)
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
pub enum SecureProtocolId {
    Invalid = 0,
    Default = 1,
    Mcu = 2,
    McuAp = 3,
}

impl Default for SecureProtocolId {
    fn default() -> Self {
        SecureProtocolId::Invalid
    }
}

impl TryFrom<u16> for SecureProtocolId {
    type Error = ErrorCode;
    fn try_from(value: u16) -> core::result::Result<Self, ErrorCode> {
        match value {
            0 => Ok(SecureProtocolId::Invalid),
            1 => Ok(SecureProtocolId::Default),
            2 => Ok(SecureProtocolId::Mcu),
            3 => Ok(SecureProtocolId::McuAp),
            _ => {
                log_e!("Invalid secure protocol id: {}", value);
                Err(ErrorCode::BadParam)
            }
        }
    }
}

#[derive(Clone, Copy, Eq, PartialEq, PartialOrd, Ord, Debug)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
#[repr(u32)]
pub enum AuthType {
    Default = 0,
    Pin = 1,
    Face = 2,
    Fingerprint = 4,
}

impl Default for AuthType {
    fn default() -> Self {
        AuthType::Default
    }
}

impl TryFrom<u32> for AuthType {
    type Error = ErrorCode;
    fn try_from(value: u32) -> core::result::Result<Self, ErrorCode> {
        match value {
            1 => Ok(AuthType::Pin),
            2 => Ok(AuthType::Face),
            4 => Ok(AuthType::Fingerprint),
            _ => {
                log_e!("Invalid auth capability level: {}", value);
                Err(ErrorCode::BadParam)
            }
        }
    }
}
