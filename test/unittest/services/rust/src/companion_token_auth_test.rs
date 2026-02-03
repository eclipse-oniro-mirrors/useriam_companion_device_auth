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
    CompanionProcessCheckInputFfi, CompanionProcessTokenAuthInputFfi, DataArray1024Ffi, DataArray32Ffi,
    Uint16Array64Ffi,
};
use crate::log_i;
use crate::request::jobs::common_message::SecCommonRequest;
use crate::request::token_auth::companion_token_auth::CompanionTokenAuthRequest;
use crate::traits::companion_db_manager::{CompanionDbManagerRegistry, MockCompanionDbManager};
use crate::traits::crypto_engine::{CryptoEngineRegistry, MockCryptoEngine};
use crate::traits::db_manager::{HostDeviceSk, HostTokenInfo};
use crate::traits::request_manager::{Request, RequestParam};
use crate::ut_registry_guard;
use crate::utils::{Attribute, AttributeKey};
use std::boxed::Box;

fn create_valid_auth_request_message(challenge: u64) -> Vec<u8> {
    let mut encrypt_attribute = Attribute::new();
    encrypt_attribute.set_u64(AttributeKey::AttrChallenge, challenge);

    let encrypt_data = encrypt_attribute.to_bytes().unwrap();
    let salt = [0u8; HKDF_SALT_SIZE];
    let tag = [1u8; AES_GCM_TAG_SIZE];
    let iv = [2u8; AES_GCM_IV_SIZE];

    let request = SecCommonRequest { salt, tag, iv, encrypt_data };
    request.encode(DeviceType::Default).unwrap()
}

#[test]
fn companion_token_auth_request_get_request_id_test() {
    let _guard = ut_registry_guard!();
    log_i!("companion_token_auth_request_get_request_id_test start");

    let input = CompanionProcessTokenAuthInputFfi {
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let request = CompanionTokenAuthRequest::new(&input).unwrap();
    assert_eq!(request.get_request_id(), 123);
}

#[test]
fn companion_token_auth_request_prepare_test_not_implemented() {
    let _guard = ut_registry_guard!();
    log_i!("companion_token_auth_request_prepare_test_not_implemented start");

    let input = CompanionProcessTokenAuthInputFfi {
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut request = CompanionTokenAuthRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionProcessTokenAuthOutputFfi::default();
    let param = RequestParam::CompanionTokenAuthBegin(&input, &mut output);
    let result = request.prepare(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_token_auth_request_begin_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("companion_token_auth_request_begin_test_wrong_input_type start");

    let input = CompanionProcessTokenAuthInputFfi {
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut request = CompanionTokenAuthRequest::new(&input).unwrap();

    let wrong_input = CompanionProcessCheckInputFfi {
        binding_id: 123,
        secure_protocol_id: 1,
        challenge: 0,
        salt: DataArray32Ffi { data: [0u8; HKDF_SALT_SIZE], len: HKDF_SALT_SIZE as u32 },
        capability_list: Uint16Array64Ffi::default(),
        sec_message: DataArray1024Ffi::default(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionProcessCheckOutputFfi::default();
    let param = RequestParam::CompanionSyncStatus(&wrong_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn companion_token_auth_request_begin_test_get_session_key_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_token_auth_request_begin_test_get_session_key_fail start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_sk()
        .returning(|| Err(ErrorCode::NotFound));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let sec_message = create_valid_auth_request_message(0);
    let input = CompanionProcessTokenAuthInputFfi {
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut request = CompanionTokenAuthRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionProcessTokenAuthOutputFfi::default();
    let param = RequestParam::CompanionTokenAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_token_auth_request_begin_test_aes_gcm_decrypt_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_token_auth_request_begin_test_aes_gcm_decrypt_fail start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(HostDeviceSk { sk: [0u8; SHARE_KEY_LEN] }));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let sec_message = create_valid_auth_request_message(0);
    let input = CompanionProcessTokenAuthInputFfi {
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut request = CompanionTokenAuthRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionProcessTokenAuthOutputFfi::default();
    let param = RequestParam::CompanionTokenAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_token_auth_request_begin_test_attribute_try_from_bytes_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_token_auth_request_begin_test_attribute_try_from_bytes_fail start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(HostDeviceSk { sk: [0u8; SHARE_KEY_LEN] }));
    mock_companion_db_manager
        .expect_read_device_token()
        .returning(|| Ok(HostTokenInfo { token: [0u8; TOKEN_KEY_LEN], atl: AuthTrustLevel::Atl3 }));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_decrypt().returning(|_| Ok(Vec::new()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let sec_message = create_valid_auth_request_message(0);
    let input = CompanionProcessTokenAuthInputFfi {
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut request = CompanionTokenAuthRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionProcessTokenAuthOutputFfi::default();
    let param = RequestParam::CompanionTokenAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_token_auth_request_begin_test_get_challenge_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_token_auth_request_begin_test_get_challenge_fail start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(HostDeviceSk { sk: [0u8; SHARE_KEY_LEN] }));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut encrypt_attribute = Attribute::new();
    encrypt_attribute.set_i32(AttributeKey::AttrAuthTrustLevel, 30000);

    let encrypt_data = encrypt_attribute.to_bytes().unwrap();
    let salt = [0u8; HKDF_SALT_SIZE];
    let tag = [1u8; AES_GCM_TAG_SIZE];
    let iv = [2u8; AES_GCM_IV_SIZE];

    let request_msg = SecCommonRequest { salt, tag, iv, encrypt_data };
    let sec_message = request_msg.encode(DeviceType::Default).unwrap();

    let input = CompanionProcessTokenAuthInputFfi {
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut request = CompanionTokenAuthRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionProcessTokenAuthOutputFfi::default();
    let param = RequestParam::CompanionTokenAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_token_auth_request_begin_test_read_device_token_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_token_auth_request_begin_test_read_device_token_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(HostDeviceSk { sk: [0u8; SHARE_KEY_LEN] }));
    mock_companion_db_manager
        .expect_read_device_token()
        .returning(|| Err(ErrorCode::NotFound));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let sec_message = create_valid_auth_request_message(0);
    let input = CompanionProcessTokenAuthInputFfi {
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut request = CompanionTokenAuthRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionProcessTokenAuthOutputFfi::default();
    let param = RequestParam::CompanionTokenAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn companion_token_auth_request_begin_test_hmac_sha256_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_token_auth_request_begin_test_hmac_sha256_fail start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(HostDeviceSk { sk: [0u8; SHARE_KEY_LEN] }));
    mock_companion_db_manager
        .expect_read_device_token()
        .returning(|| Ok(HostTokenInfo { token: [0u8; TOKEN_KEY_LEN], atl: AuthTrustLevel::Atl3 }));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine
        .expect_hmac_sha256()
        .returning(|_, _| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let sec_message = create_valid_auth_request_message(0);
    let input = CompanionProcessTokenAuthInputFfi {
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut request = CompanionTokenAuthRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionProcessTokenAuthOutputFfi::default();
    let param = RequestParam::CompanionTokenAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_token_auth_request_end_test_not_implemented() {
    let _guard = ut_registry_guard!();
    log_i!("companion_token_auth_request_end_test_not_implemented start");

    let input = CompanionProcessTokenAuthInputFfi {
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut request = CompanionTokenAuthRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionProcessTokenAuthOutputFfi::default();
    let param = RequestParam::CompanionTokenAuthBegin(&input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}
