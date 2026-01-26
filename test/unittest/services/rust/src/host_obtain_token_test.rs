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
    DataArray1024Ffi, HostProcessObtainTokenInputFfi, HostProcessObtainTokenOutputFfi,
    HostProcessPreObtainTokenInputFfi, HostProcessPreObtainTokenOutputFfi,
};
use crate::log_i;
use crate::request::jobs::common_message::SecCommonRequest;
use crate::request::token_obtain::host_obtain_token::HostDeviceObtainTokenRequest;
use crate::traits::crypto_engine::{AesGcmResult, CryptoEngineRegistry, MockCryptoEngine};
use crate::traits::db_manager::{CompanionDeviceCapability, CompanionDeviceSk};
use crate::traits::host_db_manager::{HostDbManagerRegistry, MockHostDbManager};
use crate::traits::request_manager::{Request, RequestParam};
use crate::traits::time_keeper::{MockTimeKeeper, TimeKeeperRegistry};
use crate::ut_registry_guard;
use crate::utils::{Attribute, AttributeKey};
use std::boxed::Box;

fn create_valid_obtain_token_request(challenge: u64, atl: i32) -> Vec<u8> {
    let mut encrypt_attribute = Attribute::new();
    encrypt_attribute.set_u64(AttributeKey::AttrChallenge, challenge);
    encrypt_attribute.set_i32(AttributeKey::AttrAuthTrustLevel, atl);

    let encrypt_data = encrypt_attribute.to_bytes().unwrap();
    let tag = [1u8; AES_GCM_TAG_SIZE];
    let iv = [2u8; AES_GCM_IV_SIZE];
    let salt = [3u8; HKDF_SALT_SIZE];

    let request = SecCommonRequest { salt, tag, iv, encrypt_data };
    request.encode(DeviceType::None).unwrap()
}

fn create_mock_companion_device_capability() -> CompanionDeviceCapability {
    CompanionDeviceCapability {
        device_type: DeviceType::None,
        esl: ExecutorSecurityLevel::Esl3,
        track_ability_level: 1,
    }
}

fn mock_set_crypto_engine() {
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
}

fn mock_set_host_db_manager() {
    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Ok(vec![create_mock_companion_device_capability()]));
    mock_host_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceSk { device_type: DeviceType::None, sk: Vec::new() }]));
    mock_host_db_manager.expect_add_token().returning(|| Ok(()));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));
}

fn mock_set_time_keeper() {
    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Ok(1000));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));
}

#[test]
fn host_obtain_token_request_new_test_secure_random_challenge_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_obtain_token_request_new_test_secure_random_challenge_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_secure_random()
        .returning(|_| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };

    let result = HostDeviceObtainTokenRequest::new(&input);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_obtain_token_request_get_request_id_test() {
    let _guard = ut_registry_guard!();
    log_i!("host_obtain_token_request_get_request_id_test start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };

    let request = HostDeviceObtainTokenRequest::new(&input).unwrap();
    assert_eq!(request.get_request_id(), 1);
}

#[test]
fn host_obtain_token_request_prepare_test_not_implemented() {
    let _guard = ut_registry_guard!();
    log_i!("host_obtain_token_request_prepare_test_not_implemented start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };

    let mut request = HostDeviceObtainTokenRequest::new(&input).unwrap();

    let mut output = HostProcessPreObtainTokenOutputFfi::default();
    let param = RequestParam::HostObtainTokenBegin(&input, &mut output);
    let result = request.prepare(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_obtain_token_request_begin_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("host_obtain_token_request_begin_test_wrong_input_type start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };

    let mut request = HostDeviceObtainTokenRequest::new(&input).unwrap();

    let wrong_input = HostProcessObtainTokenInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut output = HostProcessObtainTokenOutputFfi::default();
    let param = RequestParam::HostObtainTokenEnd(&wrong_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn host_obtain_token_request_begin_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_obtain_token_request_begin_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Ok(vec![create_mock_companion_device_capability()]));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };

    let mut request = HostDeviceObtainTokenRequest::new(&input).unwrap();

    let begin_input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };

    let mut output = HostProcessPreObtainTokenOutputFfi::default();
    let param = RequestParam::HostObtainTokenBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert!(result.is_ok());
}

#[test]
fn host_obtain_token_request_end_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("host_obtain_token_request_end_test_wrong_input_type start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };

    let mut request = HostDeviceObtainTokenRequest::new(&input).unwrap();

    let mut output = HostProcessPreObtainTokenOutputFfi::default();
    let param = RequestParam::HostObtainTokenBegin(&input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn host_obtain_token_request_end_test_read_device_capability_info_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_obtain_token_request_end_test_read_device_capability_info_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Err(ErrorCode::NotFound));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };

    let mut request = HostDeviceObtainTokenRequest::new(&input).unwrap();

    let end_input = HostProcessObtainTokenInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut output = HostProcessObtainTokenOutputFfi::default();
    let param = RequestParam::HostObtainTokenEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn host_obtain_token_request_end_test_decode_sec_message_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_obtain_token_request_end_test_decode_sec_message_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Ok(vec![create_mock_companion_device_capability()]));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };

    let mut request = HostDeviceObtainTokenRequest::new(&input).unwrap();

    let end_input = HostProcessObtainTokenInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut output = HostProcessObtainTokenOutputFfi::default();
    let param = RequestParam::HostObtainTokenEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_obtain_token_request_end_test_get_session_key_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_obtain_token_request_end_test_get_session_key_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Ok(vec![create_mock_companion_device_capability()]));
    mock_host_db_manager
        .expect_read_device_sk()
        .returning(|| Err(ErrorCode::NotFound));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };

    let mut request = HostDeviceObtainTokenRequest::new(&input).unwrap();

    let sec_message = create_valid_obtain_token_request(0, AuthTrustLevel::Atl3 as i32);
    let end_input = HostProcessObtainTokenInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostProcessObtainTokenOutputFfi::default();
    let param = RequestParam::HostObtainTokenEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_obtain_token_request_end_test_decrypt_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_obtain_token_request_end_test_decrypt_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    mock_set_host_db_manager();

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };

    let mut request = HostDeviceObtainTokenRequest::new(&input).unwrap();

    let sec_message = create_valid_obtain_token_request(0, AuthTrustLevel::Atl3 as i32);
    let end_input = HostProcessObtainTokenInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostProcessObtainTokenOutputFfi::default();
    let param = RequestParam::HostObtainTokenEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_obtain_token_request_end_test_challenge_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("host_obtain_token_request_end_test_challenge_mismatch start");

    mock_set_crypto_engine();
    mock_set_host_db_manager();

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };

    let mut request = HostDeviceObtainTokenRequest::new(&input).unwrap();
    request.challenge = 999;

    let sec_message = create_valid_obtain_token_request(0, AuthTrustLevel::Atl3 as i32);
    let end_input = HostProcessObtainTokenInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostProcessObtainTokenOutputFfi::default();
    let param = RequestParam::HostObtainTokenEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_obtain_token_request_end_test_atl_try_from_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_obtain_token_request_end_test_atl_try_from_fail start");

    mock_set_crypto_engine();
    mock_set_host_db_manager();

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };

    let mut request = HostDeviceObtainTokenRequest::new(&input).unwrap();
    request.challenge = 0;

    let sec_message = create_valid_obtain_token_request(0, 99999);
    let end_input = HostProcessObtainTokenInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostProcessObtainTokenOutputFfi::default();
    let param = RequestParam::HostObtainTokenEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_obtain_token_request_end_test_secure_random_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_obtain_token_request_end_test_secure_random_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_secure_random()
        .returning(|_| Err(ErrorCode::GeneralError));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    mock_set_host_db_manager();

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };

    let mut request = HostDeviceObtainTokenRequest::new(&input).unwrap();
    request.challenge = 0;

    let sec_message = create_valid_obtain_token_request(0, AuthTrustLevel::Atl3 as i32);
    let end_input = HostProcessObtainTokenInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostProcessObtainTokenOutputFfi::default();
    let param = RequestParam::HostObtainTokenEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_obtain_token_request_end_test_generate_token_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_obtain_token_request_end_test_generate_token_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_secure_random()
        .returning(|_| Err(ErrorCode::GeneralError));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    mock_set_host_db_manager();

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };

    let mut request = HostDeviceObtainTokenRequest::new(&input).unwrap();
    request.challenge = 0;

    let sec_message = create_valid_obtain_token_request(0, AuthTrustLevel::Atl3 as i32);
    let end_input = HostProcessObtainTokenInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostProcessObtainTokenOutputFfi::default();
    let param = RequestParam::HostObtainTokenEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_obtain_token_request_end_test_sec_message_get_session_key_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_obtain_token_request_end_test_sec_message_get_session_key_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Err(ErrorCode::GeneralError));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    mock_set_host_db_manager();

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };

    let mut request = HostDeviceObtainTokenRequest::new(&input).unwrap();
    request.challenge = 0;

    let sec_message = create_valid_obtain_token_request(0, AuthTrustLevel::Atl3 as i32);
    let end_input = HostProcessObtainTokenInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostProcessObtainTokenOutputFfi::default();
    let param = RequestParam::HostObtainTokenEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_obtain_token_request_end_test_sec_message_encrypt_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_obtain_token_request_end_test_sec_message_encrypt_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine
        .expect_aes_gcm_encrypt()
        .returning(|_, _| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    mock_set_host_db_manager();

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };

    let mut request = HostDeviceObtainTokenRequest::new(&input).unwrap();
    request.challenge = 0;

    let sec_message = create_valid_obtain_token_request(0, AuthTrustLevel::Atl3 as i32);
    let end_input = HostProcessObtainTokenInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostProcessObtainTokenOutputFfi::default();
    let param = RequestParam::HostObtainTokenEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_obtain_token_request_end_test_get_rtc_time_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_obtain_token_request_end_test_get_rtc_time_fail start");

    mock_set_crypto_engine();
    mock_set_host_db_manager();

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper
        .expect_get_rtc_time()
        .returning(|| Err(ErrorCode::GeneralError));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };

    let mut request = HostDeviceObtainTokenRequest::new(&input).unwrap();
    request.challenge = 0;

    let sec_message = create_valid_obtain_token_request(0, AuthTrustLevel::Atl3 as i32);
    let end_input = HostProcessObtainTokenInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostProcessObtainTokenOutputFfi::default();
    let param = RequestParam::HostObtainTokenEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_obtain_token_request_end_test_add_token_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_obtain_token_request_end_test_add_token_fail start");

    mock_set_crypto_engine();
    mock_set_time_keeper();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Ok(vec![create_mock_companion_device_capability()]));
    mock_host_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceSk { device_type: DeviceType::None, sk: Vec::new() }]));
    mock_host_db_manager
        .expect_add_token()
        .returning(|| Err(ErrorCode::GeneralError));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };

    let mut request = HostDeviceObtainTokenRequest::new(&input).unwrap();

    let sec_message = create_valid_obtain_token_request(0, AuthTrustLevel::Atl3 as i32);
    let end_input = HostProcessObtainTokenInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostProcessObtainTokenOutputFfi::default();
    let param = RequestParam::HostObtainTokenEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_obtain_token_request_end_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_obtain_token_request_end_test_success start");

    mock_set_crypto_engine();
    mock_set_host_db_manager();
    mock_set_time_keeper();

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };

    let mut request = HostDeviceObtainTokenRequest::new(&input).unwrap();

    let sec_message = create_valid_obtain_token_request(0, AuthTrustLevel::Atl3 as i32);
    let end_input = HostProcessObtainTokenInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostProcessObtainTokenOutputFfi::default();
    let param = RequestParam::HostObtainTokenEnd(&end_input, &mut output);
    let result = request.end(param);
    assert!(result.is_ok());
}
