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

use crate::traits::log_trace::TestFileId;
const FILE_ID: u16 = TestFileId::ConstantsTest as u16;

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
    assert_eq!(ErrorCode::try_from(4).unwrap(), ErrorCode::Timeout);
    assert_eq!(ErrorCode::try_from(8).unwrap(), ErrorCode::BadParam);
    assert_eq!(ErrorCode::try_from(1003).unwrap(), ErrorCode::ReadParcelError);
    assert_eq!(ErrorCode::try_from(1004).unwrap(), ErrorCode::WriteParcelError);
    assert_eq!(ErrorCode::try_from(10006).unwrap(), ErrorCode::NotFound);
    assert_eq!(ErrorCode::try_from(10015).unwrap(), ErrorCode::IdExists);
    assert_eq!(ErrorCode::try_from(10018).unwrap(), ErrorCode::ExceedLimit);
    assert_eq!(ErrorCode::try_from(20005).unwrap(), ErrorCode::TokenNotFound);
    assert_eq!(ErrorCode::try_from(20006).unwrap(), ErrorCode::TokenVerifyFailed);
    assert_eq!(ErrorCode::try_from(20011).unwrap(), ErrorCode::ProtocolNegotiationFailed);
    assert_eq!(ErrorCode::try_from(20013).unwrap(), ErrorCode::SecureProtocolNotSupported);
    assert_eq!(ErrorCode::try_from(20014).unwrap(), ErrorCode::CapabilityNegotiationFailed);
    assert_eq!(ErrorCode::try_from(20015).unwrap(), ErrorCode::AlgorithmNegotiationFailed);
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

    assert_eq!(ProcessorType::try_from(0).unwrap(), ProcessorType::Default);
    assert_eq!(ProcessorType::try_from(-1), Err(ErrorCode::BadParam));
}

#[test]
fn algo_type_test() {
    let _guard = ut_registry_guard!();
    log_i!("algo_type_test start");

    assert_eq!(KaAlgoType::default(), KaAlgoType::None);
    assert_eq!(KaAlgoType::try_from(1).unwrap(), KaAlgoType::X25519);
    assert_eq!(KaAlgoType::try_from(999), Err(ErrorCode::BadParam));
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

// Negotiation lists are unordered sets: canonicalize sorts and dedups, and the
// intersection is order- and duplicate-insensitive with a legal empty result.
#[test]
fn canonicalize_list_test() {
    let _guard = ut_registry_guard!();
    log_i!("canonicalize_list_test start");

    assert_eq!(canonicalize_list(&[]), Vec::<u16>::new());
    assert_eq!(canonicalize_list(&[3, 1, 2]), vec![1, 2, 3]);
    assert_eq!(canonicalize_list(&[2, 2, 1, 1]), vec![1, 2]);
}

#[test]
fn intersect_lists_test() {
    let _guard = ut_registry_guard!();
    log_i!("intersect_lists_test start");

    // Order and duplicates on either side do not change the result.
    assert_eq!(intersect_lists(&[2, 1, 2], &[3, 2, 1, 1]), vec![1, 2]);
    // Subset offer narrows the result.
    assert_eq!(intersect_lists(&[1], &[3, 1, 2]), vec![1]);
    // Empty sides are legal.
    assert_eq!(intersect_lists(&[], &[1, 2]), Vec::<u16>::new());
    assert_eq!(intersect_lists(&[1, 2], &[]), Vec::<u16>::new());
    // Disjoint sets negotiate to the legal empty set.
    assert_eq!(intersect_lists(&[1], &[2]), Vec::<u16>::new());
}

#[test]
fn intersect_lists_in_reference_order_test() {
    let _guard = ut_registry_guard!();
    log_i!("intersect_lists_in_reference_order_test start");

    // Result keeps the reference (priority) order and drops duplicates.
    assert_eq!(intersect_lists_in_reference_order(&[3, 1, 3, 2], &[2, 1, 4]), vec![1, 2]);
    // Candidate order and duplicates do not leak into the result.
    assert_eq!(intersect_lists_in_reference_order(&[1, 2], &[2, 2, 1, 1]), vec![1, 2]);
    // Empty and disjoint sides stay legal.
    assert_eq!(intersect_lists_in_reference_order(&[], &[1, 2]), Vec::<u16>::new());
    assert_eq!(intersect_lists_in_reference_order(&[1], &[2]), Vec::<u16>::new());
}

#[test]
fn is_subset_test() {
    let _guard = ut_registry_guard!();
    log_i!("is_subset_test start");

    assert!(is_subset(&[], &[1]));
    assert!(is_subset(&[1, 1], &[2, 1]));
    assert!(!is_subset(&[3], &[1, 2]));
    assert!(!is_subset(&[1], &[]));
}

#[test]
fn same_elements_test() {
    let _guard = ut_registry_guard!();
    log_i!("same_elements_test start");

    assert!(same_elements(&[], &[]));
    assert!(same_elements(&[3, 1, 2], &[2, 1, 3]));
    assert!(same_elements(&[1, 1], &[1]));
    assert!(!same_elements(&[1, 2], &[1]));
    assert!(!same_elements(&[], &[1]));
}

#[test]
fn validate_secure_protocol_id_test() {
    let _guard = ut_registry_guard!();
    log_i!("validate_secure_protocol_id_test start");

    assert_eq!(validate_secure_protocol_id(SecureProtocolId::Default as u16), Ok(()));
    assert_eq!(validate_secure_protocol_id(SECURE_PROTOCOL_ID_INVALID), Err(ErrorCode::SecureProtocolNotSupported));
    assert_eq!(validate_secure_protocol_id(SecureProtocolId::Default as u16 + 1), Err(ErrorCode::SecureProtocolNotSupported));
}
