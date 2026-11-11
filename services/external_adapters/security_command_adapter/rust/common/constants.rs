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

use crate::Vec;
use crate::log_e;
use crate::traits::log_trace::RustFileId;
use crate::utils::AttributeKey;
pub(crate) const FILE_ID: u16 = RustFileId::Constants as u16;
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
pub const TOKEN_VALID_PERIOD: u64 = 4 * 60 * 60 * 1000; // 4 hours in ms
pub const TOKEN_REFRESH_THRESHOLD: u64 = 60 * 60 * 1000; // 1 hour in ms
pub const FWK_MSG_MAX_AGE_MS: u64 = 10_000; // 10 seconds in ms
pub const MAX_EVENT_NUM: usize = 20;
pub const INVALID_USER_ID: i32 = -1;
pub const INVALID_SUB_PROFILE_ID: i32 = -1;
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
    Timeout = 4,
    BadParam = 8,
    ReadParcelError = 1003,
    WriteParcelError = 1004,
    NotFound = 10006,
    IdExists = 10015,
    ExceedLimit = 10018,
    TokenNotFound = 20005,
    TokenVerifyFailed = 20006,
    ProtocolNegotiationFailed = 20011,
    SecureProtocolNotSupported = 20013,
    CapabilityNegotiationFailed = 20014,
    AlgorithmNegotiationFailed = 20015,
}

impl TryFrom<i32> for ErrorCode {
    type Error = ErrorCode;
    fn try_from(value: i32) -> Result<Self, ErrorCode> {
        match value {
            0 => Ok(ErrorCode::Success),
            1 => Ok(ErrorCode::Fail),
            2 => Ok(ErrorCode::GeneralError),
            4 => Ok(ErrorCode::Timeout),
            8 => Ok(ErrorCode::BadParam),
            1003 => Ok(ErrorCode::ReadParcelError),
            1004 => Ok(ErrorCode::WriteParcelError),
            10006 => Ok(ErrorCode::NotFound),
            10015 => Ok(ErrorCode::IdExists),
            10018 => Ok(ErrorCode::ExceedLimit),
            20005 => Ok(ErrorCode::TokenNotFound),
            20006 => Ok(ErrorCode::TokenVerifyFailed),
            20011 => Ok(ErrorCode::ProtocolNegotiationFailed),
            20013 => Ok(ErrorCode::SecureProtocolNotSupported),
            20014 => Ok(ErrorCode::CapabilityNegotiationFailed),
            20015 => Ok(ErrorCode::AlgorithmNegotiationFailed),
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

pub const LOCAL_EXECUTOR_MAX_ACL: AuthCapabilityLevel = AuthCapabilityLevel::Acl3;

pub const DEVICE_ID_TYPE_UNIFIED_DEVICE_ID: i32 = 1;
pub const DEVICE_ID_TYPE_VENDOR_BEGIN: i32 = 10000;

pub fn is_valid_device_id_type(device_id_type: i32) -> bool {
    device_id_type == DEVICE_ID_TYPE_UNIFIED_DEVICE_ID || device_id_type >= DEVICE_ID_TYPE_VENDOR_BEGIN
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

/// Processor type for message encoding/decoding (represents authentication protocol type)
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
#[repr(i32)]
pub enum ProcessorType {
    #[default]
    Default = 0,
}

impl ProcessorType {
    pub fn from_secure_protocol_id(secure_protocol_id: u16) -> Result<ProcessorType, ErrorCode> {
        match SecureProtocolId::try_from(secure_protocol_id)? {
            SecureProtocolId::Default => Ok(ProcessorType::default()),
            _ => {
                log_e!("secure_protocol_id type is not support, secure_protocol_id: {}", secure_protocol_id);
                Err(ErrorCode::BadParam)
            },
        }
    }
}

impl TryFrom<AttributeKey> for ProcessorType {
    type Error = ErrorCode;
    fn try_from(value: AttributeKey) -> core::result::Result<Self, ErrorCode> {
        match value {
            AttributeKey::AttrMessage => Ok(ProcessorType::default()),
            _ => {
                log_e!("attribute key: {:?}", value);
                Err(ErrorCode::BadParam)
            },
        }
    }
}

impl TryFrom<ProcessorType> for AttributeKey {
    type Error = ErrorCode;
    fn try_from(_value: ProcessorType) -> core::result::Result<Self, ErrorCode> {
        Ok(AttributeKey::AttrMessage)
    }
}

impl TryFrom<i32> for ProcessorType {
    type Error = ErrorCode;
    fn try_from(value: i32) -> core::result::Result<Self, ErrorCode> {
        match value {
            0 => Ok(ProcessorType::Default),
            _ => {
                log_e!("Invalid processor type: {}", value);
                Err(ErrorCode::BadParam)
            },
        }
    }
}

/// Physical device form type
#[derive(Debug, PartialEq, Eq, Clone, Copy, Default)]
#[repr(i32)]
pub enum DeviceType {
    #[default]
    Invalid = 0,
    Phone = 1,
    Pad = 2,
    TwoInOne = 3,
    Pc = 4,
    Car = 5,
    Unknown = 6,
}

impl TryFrom<i32> for DeviceType {
    type Error = ErrorCode;
    fn try_from(value: i32) -> core::result::Result<Self, ErrorCode> {
        match value {
            0 => Ok(DeviceType::Invalid),
            1 => Ok(DeviceType::Phone),
            2 => Ok(DeviceType::Pad),
            3 => Ok(DeviceType::TwoInOne),
            4 => Ok(DeviceType::Pc),
            5 => Ok(DeviceType::Car),
            6 => Ok(DeviceType::Unknown),
            _ => {
                log_e!("Invalid device type: {}", value);
                Err(ErrorCode::BadParam)
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct DeviceCapability {
    pub processor_type: ProcessorType,
    pub esl: ExecutorSecurityLevel,
    pub track_ability_level: TrackAbilityLevel,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
#[derive(Default)]
pub enum KaAlgoType {
    #[default]
    None = 0,
    X25519 = 1,
}

impl TryFrom<u16> for KaAlgoType {
    type Error = ErrorCode;
    fn try_from(value: u16) -> core::result::Result<Self, ErrorCode> {
        match value {
            1 => Ok(KaAlgoType::X25519),
            _ => {
                log_e!("Invalid ka algo type: {}", value);
                Err(ErrorCode::BadParam)
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
#[derive(Default)]
pub enum KdfAlgoType {
    #[default]
    Invalid = 0,
    HkdfSha256 = 1,
}

impl TryFrom<u16> for KdfAlgoType {
    type Error = ErrorCode;
    fn try_from(value: u16) -> core::result::Result<Self, ErrorCode> {
        match value {
            1 => Ok(KdfAlgoType::HkdfSha256),
            _ => {
                log_e!("Invalid kdf algo type: {}", value);
                Err(ErrorCode::BadParam)
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
#[derive(Default)]
pub enum AeadAlgoType {
    #[default]
    Invalid = 0,
    Aes256Gcm = 1,
}

impl TryFrom<u16> for AeadAlgoType {
    type Error = ErrorCode;
    fn try_from(value: u16) -> core::result::Result<Self, ErrorCode> {
        match value {
            1 => Ok(AeadAlgoType::Aes256Gcm),
            _ => {
                log_e!("Invalid aead algo type: {}", value);
                Err(ErrorCode::BadParam)
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[repr(u16)]
#[derive(Default)]
pub enum MacAlgoType {
    #[default]
    Invalid = 0,
    HmacSha256 = 1,
}

impl TryFrom<u16> for MacAlgoType {
    type Error = ErrorCode;
    fn try_from(value: u16) -> core::result::Result<Self, ErrorCode> {
        match value {
            1 => Ok(MacAlgoType::HmacSha256),
            _ => {
                log_e!("Invalid mac algo type: {}", value);
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
                log_e!("Invalid auth type: {}", value);
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
    ObtainToken = 3,
}

impl TryFrom<u16> for Capability {
    type Error = ErrorCode;
    fn try_from(value: u16) -> core::result::Result<Self, ErrorCode> {
        match value {
            0 => Ok(Capability::Invalid),
            1 => Ok(Capability::DelegateAuth),
            2 => Ok(Capability::TokenAuth),
            3 => Ok(Capability::ObtainToken),
            _ => {
                log_e!("Invalid capability: {}", value);
                Err(ErrorCode::BadParam)
            },
        }
    }
}

pub const PROTOCOL_ID_INVALID: u16 = 0;
pub const SUPPORTED_PROTOCOL_VERSIONS: &[u16] = &[1];

pub const SUPPORTED_KA_ALGORITHMS: &[u16] = &[KaAlgoType::X25519 as u16];
pub const SUPPORTED_KDF_ALGORITHMS: &[u16] = &[KdfAlgoType::HkdfSha256 as u16];
pub const SUPPORTED_AEAD_ALGORITHMS: &[u16] = &[AeadAlgoType::Aes256Gcm as u16];
pub const SUPPORTED_MAC_ALGORITHMS: &[u16] = &[MacAlgoType::HmacSha256 as u16];

pub const SECURE_PROTOCOL_ID_INVALID: u16 = 0;

pub fn validate_secure_protocol_id(secure_protocol_id: u16) -> core::result::Result<(), ErrorCode> {
    if !SUPPORTED_PROTOCOL_VERSIONS.contains(&secure_protocol_id) {
        log_e!("protocol {} is not supported by TA, supported: {:?}", secure_protocol_id, SUPPORTED_PROTOCOL_VERSIONS);
        return Err(ErrorCode::SecureProtocolNotSupported);
    }
    Ok(())
}

pub fn validate_protocol_list(protocol_list: &[u16]) -> core::result::Result<(), ErrorCode> {
    for protocol in protocol_list {
        if !SUPPORTED_PROTOCOL_VERSIONS.contains(protocol) {
            log_e!("protocol {} is not supported by TA, supported: {:?}", protocol, SUPPORTED_PROTOCOL_VERSIONS);
            return Err(ErrorCode::GeneralError);
        }
    }
    Ok(())
}

pub fn validate_capability_list(capability_list: &[u16]) -> core::result::Result<(), ErrorCode> {
    for capability in capability_list {
        let is_valid = match Capability::try_from(*capability) {
            Ok(c) => c != Capability::Invalid,
            Err(_) => false,
        };
        if !is_valid {
            log_e!("capability {} is not supported by TA", capability);
            return Err(ErrorCode::GeneralError);
        }
    }
    Ok(())
}

pub fn canonicalize_list(list: &[u16]) -> Vec<u16> {
    let mut canonical: Vec<u16> = list.to_vec();
    canonical.sort_unstable();
    canonical.dedup();
    canonical
}

pub fn intersect_lists_in_reference_order(reference: &[u16], candidate: &[u16]) -> Vec<u16> {
    let mut result: Vec<u16> = Vec::new();
    for &value in reference {
        if candidate.contains(&value) && !result.contains(&value) {
            result.push(value);
        }
    }
    result
}

pub fn intersect_lists(offered: &[u16], local: &[u16]) -> Vec<u16> {
    let mut result: Vec<u16> = Vec::new();
    for &capability in offered {
        if local.contains(&capability) {
            result.push(capability);
        }
    }
    canonicalize_list(&result)
}

pub fn is_subset(subset: &[u16], superset: &[u16]) -> bool {
    subset.iter().all(|item| superset.contains(item))
}

pub fn same_elements(a: &[u16], b: &[u16]) -> bool {
    canonicalize_list(a) == canonicalize_list(b)
}
