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
use crate::log_i;
use crate::ut_registry_guard;

#[test]
fn error_code_test() {
    let _guard = ut_registry_guard!();
    log_i!("error_code_test start");

    assert_eq!(ErrorCode::default(), ErrorCode::GeneralError);
    assert_eq!(ErrorCode::try_from(0).unwrap(), ErrorCode::Success);
    assert_eq!(ErrorCode::try_from(1).unwrap(), ErrorCode::Fail);
    assert_eq!(ErrorCode::try_from(2).unwrap(), ErrorCode::GeneralError);
    assert_eq!(ErrorCode::try_from(3).unwrap(), ErrorCode::Canceled);
    assert_eq!(ErrorCode::try_from(4).unwrap(), ErrorCode::Timeout);
    assert_eq!(ErrorCode::try_from(5).unwrap(), ErrorCode::TypeNotSupport);
    assert_eq!(ErrorCode::try_from(6).unwrap(), ErrorCode::TrustLevelNotSupport);
    assert_eq!(ErrorCode::try_from(7).unwrap(), ErrorCode::Busy);
    assert_eq!(ErrorCode::try_from(8).unwrap(), ErrorCode::BadParam);
    assert_eq!(ErrorCode::try_from(9).unwrap(), ErrorCode::ReadParcelError);
    assert_eq!(ErrorCode::try_from(10).unwrap(), ErrorCode::WriteParcelError);
    assert_eq!(ErrorCode::try_from(11).unwrap(), ErrorCode::NotFound);
    assert_eq!(ErrorCode::try_from(12).unwrap(), ErrorCode::BadSign);
    assert_eq!(ErrorCode::try_from(13).unwrap(), ErrorCode::IdExists);
    assert_eq!(ErrorCode::try_from(14).unwrap(), ErrorCode::ExceedLimit);
    assert_eq!(ErrorCode::try_from(-1), Err(ErrorCode::BadParam));
}

#[test]
fn auth_security_level_test() {
    let _guard = ut_registry_guard!();
    log_i!("auth_security_level_test start");

    assert_eq!(AuthSecurityLevel::default(), AuthSecurityLevel::Asl0);
    assert_eq!(AuthSecurityLevel::try_from(0).unwrap(), AuthSecurityLevel::Asl0);
    assert_eq!(AuthSecurityLevel::try_from(1).unwrap(), AuthSecurityLevel::Asl1);
    assert_eq!(AuthSecurityLevel::try_from(2).unwrap(), AuthSecurityLevel::Asl2);
    assert_eq!(AuthSecurityLevel::try_from(3).unwrap(), AuthSecurityLevel::Asl3);
    assert_eq!(AuthSecurityLevel::try_from(4).unwrap(), AuthSecurityLevel::MaxAsl);
    assert_eq!(AuthSecurityLevel::try_from(-1), Err(ErrorCode::BadParam));
}

#[test]
fn executor_security_level_test() {
    let _guard = ut_registry_guard!();
    log_i!("executor_security_level_test start");

    assert_eq!(ExecutorSecurityLevel::default(), ExecutorSecurityLevel::Esl0);
    assert_eq!(ExecutorSecurityLevel::try_from(0).unwrap(), ExecutorSecurityLevel::Esl0);
    assert_eq!(ExecutorSecurityLevel::try_from(1).unwrap(), ExecutorSecurityLevel::Esl1);
    assert_eq!(ExecutorSecurityLevel::try_from(2).unwrap(), ExecutorSecurityLevel::Esl2);
    assert_eq!(ExecutorSecurityLevel::try_from(3).unwrap(), ExecutorSecurityLevel::Esl3);
    assert_eq!(ExecutorSecurityLevel::try_from(4).unwrap(), ExecutorSecurityLevel::MaxEsl);
    assert_eq!(ExecutorSecurityLevel::try_from(-1), Err(ErrorCode::BadParam));
}

#[test]
fn auth_capability_level_test() {
    let _guard = ut_registry_guard!();
    log_i!("auth_capability_level_test start");

    assert_eq!(AuthCapabilityLevel::default(), AuthCapabilityLevel::Acl0);
    assert_eq!(AuthCapabilityLevel::try_from(0).unwrap(), AuthCapabilityLevel::Acl0);
    assert_eq!(AuthCapabilityLevel::try_from(1).unwrap(), AuthCapabilityLevel::Acl1);
    assert_eq!(AuthCapabilityLevel::try_from(2).unwrap(), AuthCapabilityLevel::Acl2);
    assert_eq!(AuthCapabilityLevel::try_from(3).unwrap(), AuthCapabilityLevel::Acl3);
    assert_eq!(AuthCapabilityLevel::try_from(-1), Err(ErrorCode::BadParam));
}

#[test]
fn auth_trust_level_test() {
    let _guard = ut_registry_guard!();
    log_i!("auth_trust_level_test start");

    assert_eq!(AuthTrustLevel::default(), AuthTrustLevel::Atl0);
    assert_eq!(AuthTrustLevel::try_from(0).unwrap(), AuthTrustLevel::Atl0);
    assert_eq!(AuthTrustLevel::try_from(10000).unwrap(), AuthTrustLevel::Atl1);
    assert_eq!(AuthTrustLevel::try_from(20000).unwrap(), AuthTrustLevel::Atl2);
    assert_eq!(AuthTrustLevel::try_from(30000).unwrap(), AuthTrustLevel::Atl3);
    assert_eq!(AuthTrustLevel::try_from(40000).unwrap(), AuthTrustLevel::Atl4);
    assert_eq!(AuthTrustLevel::try_from(-1), Err(ErrorCode::BadParam));
}

#[test]
fn device_type_test() {
    let _guard = ut_registry_guard!();
    log_i!("device_type_test start");

    assert_eq!(DeviceType::try_from(0).unwrap(), DeviceType::Default);
    assert_eq!(DeviceType::try_from(-1), Err(ErrorCode::BadParam));
}

#[test]
fn algo_type_test() {
    let _guard = ut_registry_guard!();
    log_i!("algo_type_test start");

    assert_eq!(AlgoType::default(), AlgoType::None);
    assert_eq!(AlgoType::try_from(1).unwrap(), AlgoType::X25519);
    assert_eq!(AlgoType::try_from(999), Err(ErrorCode::BadParam));
}

#[test]
fn secure_protocol_id_test() {
    let _guard = ut_registry_guard!();
    log_i!("secure_protocol_id_test start");

    assert_eq!(SecureProtocolId::default(), SecureProtocolId::Invalid);
    assert_eq!(SecureProtocolId::try_from(0).unwrap(), SecureProtocolId::Invalid);
    assert_eq!(SecureProtocolId::try_from(1).unwrap(), SecureProtocolId::Default);
    assert_eq!(SecureProtocolId::try_from(999), Err(ErrorCode::BadParam));
}

#[test]
fn auth_type_test() {
    let _guard = ut_registry_guard!();
    log_i!("auth_type_test start");

    assert_eq!(AuthType::default(), AuthType::Default);
    assert_eq!(AuthType::try_from(0).unwrap(), AuthType::Default);
    assert_eq!(AuthType::try_from(1).unwrap(), AuthType::Pin);
    assert_eq!(AuthType::try_from(2).unwrap(), AuthType::Face);
    assert_eq!(AuthType::try_from(4).unwrap(), AuthType::Fingerprint);
    assert_eq!(AuthType::try_from(64).unwrap(), AuthType::CompanionDevice);
    assert_eq!(AuthType::try_from(999), Err(ErrorCode::BadParam));
}

#[test]
fn capability_test() {
    let _guard = ut_registry_guard!();
    log_i!("capability_test start");

    assert_eq!(Capability::default(), Capability::Invalid);
    assert_eq!(Capability::try_from(0).unwrap(), Capability::Invalid);
    assert_eq!(Capability::try_from(1).unwrap(), Capability::DelegateAuth);
    assert_eq!(Capability::try_from(2).unwrap(), Capability::TokenAuth);
    assert_eq!(Capability::try_from(999), Err(ErrorCode::BadParam));
}
