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
use crate::entry::companion_device_auth_ffi::{
    CompanionBeginDelegateAuthInputFfi, CompanionEndDelegateAuthInputFfi, DataArray1024Ffi,
};
use crate::log_i;
use crate::request::delegate_auth::companion_auth::CompanionDelegateAuthRequest;
use crate::request::jobs::common_message::SecCommonRequest;
use crate::traits::companion_db_manager::{CompanionDbManagerRegistry, MockCompanionDbManager};
use crate::traits::companion_request_manager::{CompanionRequest, CompanionRequestParam};
use crate::traits::crypto_engine::{AesGcmResult, CryptoEngineRegistry, MockCryptoEngine};
use crate::traits::db_manager::{DeviceKey, HostDeviceSk, UserInfo};
use crate::ut_registry_guard;
use crate::utils::auth_token::{TokenDataPlain, UserAuthToken};
use crate::utils::{Attribute, AttributeKey};
use std::boxed::Box;

#[test]
fn companion_delegate_auth_request_new_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("companion_delegate_auth_request_new_test_success start");

    let input = CompanionBeginDelegateAuthInputFfi {
        request_id: 1,
        binding_id: 123,
        secure_protocol_id: 0,
        sec_message: DataArray1024Ffi::default(),
    };

    let result = CompanionDelegateAuthRequest::new(&input);
    assert!(result.is_ok());

    let request = result.unwrap();
    assert_eq!(request.get_request_id(), 1);
    assert_eq!(request.binding_id, 123);
    assert_eq!(request.challenge, 0);
    assert_eq!(request.atl, AuthTrustLevel::Atl2);
    assert_eq!(request.auth_type, 1);
    assert_eq!(request.salt, [0u8; HKDF_SALT_SIZE]);
}

#[test]
fn companion_delegate_auth_request_prepare_test_not_implemented() {
    let _guard = ut_registry_guard!();
    log_i!("companion_delegate_auth_request_prepare_test_not_implemented start");

    let input = CompanionBeginDelegateAuthInputFfi {
        request_id: 1,
        binding_id: 123,
        secure_protocol_id: 0,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut request = CompanionDelegateAuthRequest::new(&input).unwrap();
    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginDelegateAuthOutputFfi::default();
    let param = CompanionRequestParam::DelegateAuthBegin(&input, &mut output);
    let result = request.prepare(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_delegate_auth_request_begin_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("companion_delegate_auth_request_begin_test_wrong_input_type start");

    let input = CompanionBeginDelegateAuthInputFfi {
        request_id: 1,
        binding_id: 123,
        secure_protocol_id: 0,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut request = CompanionDelegateAuthRequest::new(&input).unwrap();

    let wrong_input =
        CompanionEndDelegateAuthInputFfi { request_id: 1, result: 0, auth_token: DataArray1024Ffi::default() };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionEndDelegateAuthOutputFfi::default();
    let param = CompanionRequestParam::DelegateAuthEnd(&wrong_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn companion_delegate_auth_request_end_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("companion_delegate_auth_request_end_test_wrong_input_type start");

    let input = CompanionBeginDelegateAuthInputFfi {
        request_id: 1,
        binding_id: 123,
        secure_protocol_id: 0,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut request = CompanionDelegateAuthRequest::new(&input).unwrap();

    let wrong_input = CompanionBeginDelegateAuthInputFfi {
        request_id: 1,
        binding_id: 123,
        secure_protocol_id: 0,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginDelegateAuthOutputFfi::default();
    let param = CompanionRequestParam::DelegateAuthBegin(&wrong_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn companion_delegate_auth_request_end_test_wrong_auth_token_len() {
    let _guard = ut_registry_guard!();
    log_i!("companion_delegate_auth_request_end_test_wrong_auth_token_len start");

    let input = CompanionBeginDelegateAuthInputFfi {
        request_id: 1,
        binding_id: 123,
        secure_protocol_id: 0,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut request = CompanionDelegateAuthRequest::new(&input).unwrap();

    let end_input =
        CompanionEndDelegateAuthInputFfi { request_id: 1, result: 0, auth_token: DataArray1024Ffi::default() };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionEndDelegateAuthOutputFfi::default();
    let param = CompanionRequestParam::DelegateAuthEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn parse_begin_sec_message_test_get_session_key_fail() {
    let _guard = ut_registry_guard!();
    log_i!("parse_begin_sec_message_test_get_session_key_fail start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_sk()
        .returning(|| Err(ErrorCode::NotFound));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut attr = Attribute::new();
    attr.set_u64(AttributeKey::AttrChallenge, 0);
    attr.set_i32(AttributeKey::AttrAuthTrustLevel, 30000);

    let sec_common_request = SecCommonRequest {
        salt: [0u8; HKDF_SALT_SIZE],
        tag: [0u8; AES_GCM_TAG_SIZE],
        iv: [0u8; AES_GCM_IV_SIZE],
        encrypt_data: attr.to_bytes().unwrap(),
    };
    let sec_message = sec_common_request.encode(DeviceType::None).unwrap();

    let input = CompanionBeginDelegateAuthInputFfi {
        request_id: 1,
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(&sec_message).unwrap(),
    };

    let mut request = CompanionDelegateAuthRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginDelegateAuthOutputFfi::default();
    let param = CompanionRequestParam::DelegateAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn parse_begin_sec_message_test_decrypt_sec_message_fail() {
    let _guard = ut_registry_guard!();
    log_i!("parse_begin_sec_message_test_decrypt_sec_message_fail start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(HostDeviceSk { sk: Vec::new() }));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut attr = Attribute::new();
    attr.set_u64(AttributeKey::AttrChallenge, 0);
    attr.set_i32(AttributeKey::AttrAuthTrustLevel, 30000);

    let sec_common_request = SecCommonRequest {
        salt: [0u8; HKDF_SALT_SIZE],
        tag: [0u8; AES_GCM_TAG_SIZE],
        iv: [0u8; AES_GCM_IV_SIZE],
        encrypt_data: attr.to_bytes().unwrap(),
    };
    let sec_message = sec_common_request.encode(DeviceType::None).unwrap();

    let input = CompanionBeginDelegateAuthInputFfi {
        request_id: 1,
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(&sec_message).unwrap(),
    };

    let mut request = CompanionDelegateAuthRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginDelegateAuthOutputFfi::default();
    let param = CompanionRequestParam::DelegateAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn parse_begin_sec_message_test_try_from_bytes_fail() {
    let _guard = ut_registry_guard!();
    log_i!("parse_begin_sec_message_test_try_from_bytes_fail start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(HostDeviceSk { sk: Vec::new() }));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let sec_common_request = SecCommonRequest {
        salt: [0u8; HKDF_SALT_SIZE],
        tag: [0u8; AES_GCM_TAG_SIZE],
        iv: [0u8; AES_GCM_IV_SIZE],
        encrypt_data: Vec::new(),
    };
    let sec_message = sec_common_request.encode(DeviceType::None).unwrap();

    let input = CompanionBeginDelegateAuthInputFfi {
        request_id: 1,
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(&sec_message).unwrap(),
    };

    let mut request = CompanionDelegateAuthRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginDelegateAuthOutputFfi::default();
    let param = CompanionRequestParam::DelegateAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn parse_begin_sec_message_test_get_challenge_fail() {
    let _guard = ut_registry_guard!();
    log_i!("parse_begin_sec_message_test_get_challenge_fail start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(HostDeviceSk { sk: Vec::new() }));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut attr = Attribute::new();
    attr.set_i32(AttributeKey::AttrAuthTrustLevel, 30000);

    let sec_common_request = SecCommonRequest {
        salt: [0u8; HKDF_SALT_SIZE],
        tag: [0u8; AES_GCM_TAG_SIZE],
        iv: [0u8; AES_GCM_IV_SIZE],
        encrypt_data: attr.to_bytes().unwrap(),
    };
    let sec_message = sec_common_request.encode(DeviceType::None).unwrap();

    let input = CompanionBeginDelegateAuthInputFfi {
        request_id: 1,
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(&sec_message).unwrap(),
    };

    let mut request = CompanionDelegateAuthRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginDelegateAuthOutputFfi::default();
    let param = CompanionRequestParam::DelegateAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn parse_begin_sec_message_test_get_atl_fail() {
    let _guard = ut_registry_guard!();
    log_i!("parse_begin_sec_message_test_get_atl_fail start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(HostDeviceSk { sk: Vec::new() }));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut attr = Attribute::new();
    attr.set_u64(AttributeKey::AttrChallenge, 0);

    let sec_common_request = SecCommonRequest {
        salt: [0u8; HKDF_SALT_SIZE],
        tag: [0u8; AES_GCM_TAG_SIZE],
        iv: [0u8; AES_GCM_IV_SIZE],
        encrypt_data: attr.to_bytes().unwrap(),
    };
    let sec_message = sec_common_request.encode(DeviceType::None).unwrap();

    let input = CompanionBeginDelegateAuthInputFfi {
        request_id: 1,
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(&sec_message).unwrap(),
    };

    let mut request = CompanionDelegateAuthRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginDelegateAuthOutputFfi::default();
    let param = CompanionRequestParam::DelegateAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn parse_begin_sec_message_test_atl_try_from_fail() {
    let _guard = ut_registry_guard!();
    log_i!("parse_begin_sec_message_test_atl_try_from_fail start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(HostDeviceSk { sk: Vec::new() }));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut attr = Attribute::new();
    attr.set_u64(AttributeKey::AttrChallenge, 0);
    attr.set_i32(AttributeKey::AttrAuthTrustLevel, 99999);

    let sec_common_request = SecCommonRequest {
        salt: [0u8; HKDF_SALT_SIZE],
        tag: [0u8; AES_GCM_TAG_SIZE],
        iv: [0u8; AES_GCM_IV_SIZE],
        encrypt_data: attr.to_bytes().unwrap(),
    };
    let sec_message = sec_common_request.encode(DeviceType::None).unwrap();

    let input = CompanionBeginDelegateAuthInputFfi {
        request_id: 1,
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(&sec_message).unwrap(),
    };

    let mut request = CompanionDelegateAuthRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginDelegateAuthOutputFfi::default();
    let param = CompanionRequestParam::DelegateAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}
