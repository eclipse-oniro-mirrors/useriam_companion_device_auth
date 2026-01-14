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
    CompanionBeginAddHostBindingInputFfi, CompanionEndAddHostBindingInputFfi, CompanionInitKeyNegotiationInputFfi,
    DataArray1024Ffi, DeviceKeyFfi,
};
use crate::log_i;
use crate::request::enroll::companion_enroll::CompanionDeviceEnrollRequest;
use crate::request::enroll::enroll_message::{SecBindingRequest, SecKeyNegoRequest};
use crate::request::jobs::common_message::SecIssueToken;
use crate::traits::companion_db_manager::{CompanionDbManagerRegistry, MockCompanionDbManager};
use crate::traits::companion_request_manager::{CompanionRequest, CompanionRequestParam};
use crate::traits::crypto_engine::{AesGcmResult, CryptoEngineRegistry, KeyPair, MockCryptoEngine};
use crate::traits::db_manager::{DeviceKey, HostDeviceInfo, HostDeviceSk, UserInfo};
use crate::traits::time_keeper::{MockTimeKeeper, TimeKeeperRegistry};
use crate::ut_registry_guard;
use crate::utils::{Attribute, AttributeKey};
use std::boxed::Box;

fn create_mock_key_pair() -> KeyPair {
    KeyPair { pub_key: vec![1u8, 2, 3, 4, 5], pri_key: vec![4u8, 5, 6] }
}

fn genereate_companion_init_key_negotiation_input_ffi() -> CompanionInitKeyNegotiationInputFfi {
    CompanionInitKeyNegotiationInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        companion_device_key: DeviceKeyFfi::default(),
        host_device_key: DeviceKeyFfi::default(),
        sec_message: DataArray1024Ffi::default(),
    }
}

fn create_valid_key_nego_request() -> Vec<u8> {
    let request = SecKeyNegoRequest {
        algorithm_list: vec![AlgoType::X25519 as u16],
    };
    request.encode(DeviceType::None).unwrap()
}

fn create_valid_binding_request(pub_key: &[u8], challenge: u64) -> Vec<u8> {
    let mut encrypt_attribute = Attribute::new();
    encrypt_attribute.set_string(AttributeKey::AttrDeviceId, "host_device".to_string());
    encrypt_attribute.set_i32(AttributeKey::AttrUserId, 100);
    encrypt_attribute.set_u64(AttributeKey::AttrChallenge, challenge);

    let encrypt_data = encrypt_attribute.to_bytes().unwrap();
    let salt = [1u8; HKDF_SALT_SIZE];
    let tag = [2u8; AES_GCM_TAG_SIZE];
    let iv = [3u8; AES_GCM_IV_SIZE];

    let request = SecBindingRequest {
        pub_key: pub_key.to_vec(),
        salt,
        tag,
        iv,
        encrypt_data,
    };
    request.encode(DeviceType::None).unwrap()
}

fn create_valid_issue_token_message(challenge: u64, atl: i32) -> Vec<u8> {
    let issue_token = SecIssueToken {
        challenge,
        atl,
        token: vec![1u8; TOKEN_KEY_LEN],
    };
    issue_token.encrypt_issue_token(&[1u8; HKDF_SALT_SIZE], DeviceType::None, &[]).unwrap()
}

fn mock_set_crypto_engine() {
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Ok(Vec::new()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_decrypt().returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| Ok(AesGcmResult { ciphertext: data.to_vec(),
        authentication_tag: [0u8; AES_GCM_TAG_SIZE],
    }));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
}

#[test]
fn companion_enroll_request_prepare_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_prepare_test_wrong_input_type start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = genereate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();

    let wrong_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = CompanionRequestParam::EnrollBegin(&wrong_input, &mut output);
    let result = request.prepare(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn companion_enroll_request_prepare_test_algorithm_not_supported() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_prepare_test_algorithm_not_supported start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let request_no_x25519 = SecKeyNegoRequest {
        algorithm_list: vec![AlgoType::None as u16],
    };
    let sec_message = request_no_x25519.encode(DeviceType::None).unwrap();

    let input = CompanionInitKeyNegotiationInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        companion_device_key: DeviceKeyFfi::default(),
        host_device_key: DeviceKeyFfi::default(),
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };
    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionInitKeyNegotiationOutputFfi::default();
    let param = CompanionRequestParam::KeyNego(&input, &mut output);
    let result = request.prepare(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_prepare_test_generate_key_pair_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_prepare_test_generate_key_pair_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_generate_x25519_key_pair().returning(|| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
    
    let sec_message = create_valid_key_nego_request();
    let input = CompanionInitKeyNegotiationInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        companion_device_key: DeviceKeyFfi::default(),
        host_device_key: DeviceKeyFfi::default(),
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };
    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionInitKeyNegotiationOutputFfi::default();
    let param = CompanionRequestParam::KeyNego(&input, &mut output);
    let result = request.prepare(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_begin_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_wrong_input_type start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = genereate_companion_init_key_negotiation_input_ffi();
    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    
    let wrong_input = CompanionEndAddHostBindingInputFfi {
        request_id: 1,
        result: 0,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionEndAddHostBindingOutputFfi::default();
    let param = CompanionRequestParam::EnrollEnd(&wrong_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn companion_enroll_request_begin_test_get_key_pair_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_get_key_pair_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = genereate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = None;

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = CompanionRequestParam::EnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_begin_test_x25519_ecdh_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_x25519_ecdh_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = genereate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = CompanionRequestParam::EnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_begin_test_hkdf_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_hkdf_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Ok(Vec::new()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = genereate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = CompanionRequestParam::EnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_begin_test_decrypt_sec_message_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_decrypt_sec_message_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Ok(Vec::new()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_decrypt().returning(|_| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = genereate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = CompanionRequestParam::EnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_begin_test_device_id_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_device_id_mismatch start");

    mock_set_crypto_engine();

    let input = genereate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "mismatch-id".to_string();

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = CompanionRequestParam::EnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_begin_test_user_id_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_user_id_mismatch start");

    mock_set_crypto_engine();

    let input = genereate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "host_device".to_string();
    request.key_nego_param.host_device_key.user_id = -1;

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = CompanionRequestParam::EnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_begin_test_challenge_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_challenge_mismatch start");

    mock_set_crypto_engine();

    let input = genereate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "host_device".to_string();
    request.key_nego_param.host_device_key.user_id = 100;
    request.key_nego_param.challenge = 0;

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 999);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = CompanionRequestParam::EnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_begin_test_encrypt_sec_message_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_encrypt_sec_message_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Ok(Vec::new()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_decrypt().returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|_, _| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = genereate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "host_device".to_string();
    request.key_nego_param.host_device_key.user_id = 100;
    request.key_nego_param.challenge = 0;

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = CompanionRequestParam::EnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_begin_test_generate_unique_binding_id_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_generate_unique_binding_id_fail start");

    mock_set_crypto_engine();

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager.expect_generate_unique_binding_id().returning(|| Err(ErrorCode::GeneralError));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let input = genereate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "host_device".to_string();
    request.key_nego_param.host_device_key.user_id = 100;
    request.key_nego_param.challenge = 0;

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = CompanionRequestParam::EnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_begin_test_get_rtc_time_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_get_rtc_time_fail start");

    mock_set_crypto_engine();

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager.expect_generate_unique_binding_id().returning(|| Ok(1));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Err(ErrorCode::GeneralError));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let input = genereate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "host_device".to_string();
    request.key_nego_param.host_device_key.user_id = 100;
    request.key_nego_param.challenge = 0;

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = CompanionRequestParam::EnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_begin_test_add_host_device_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_add_host_device_fail start");

    mock_set_crypto_engine();

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager.expect_generate_unique_binding_id().returning(|| Ok(1));
    mock_companion_db_manager.expect_get_device_by_device_key().returning(|| Err(ErrorCode::NotFound));
    mock_companion_db_manager.expect_add_device().returning(|| Err(ErrorCode::GeneralError));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Ok(1000));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let input = genereate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "host_device".to_string();
    request.key_nego_param.host_device_key.user_id = 100;
    request.key_nego_param.challenge = 0;

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = CompanionRequestParam::EnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_begin_test_get_device_by_binding_id_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_get_device_by_binding_id_fail start");

    mock_set_crypto_engine();

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager.expect_generate_unique_binding_id().returning(|| Ok(1));
    mock_companion_db_manager.expect_get_device_by_device_key().returning(|| Err(ErrorCode::NotFound));
    mock_companion_db_manager.expect_add_device().returning(|| Ok(()));
    mock_companion_db_manager.expect_get_device_by_binding_id().returning(|| Err(ErrorCode::NotFound));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Ok(1000));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let input = genereate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "host_device".to_string();
    request.key_nego_param.host_device_key.user_id = 100;
    request.key_nego_param.challenge = 0;

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = CompanionRequestParam::EnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn companion_enroll_request_end_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_end_test_wrong_input_type start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = genereate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    
    let wrong_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = CompanionRequestParam::EnrollBegin(&wrong_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn companion_enroll_request_end_test_challenge_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_end_test_challenge_mismatch start");

    mock_set_crypto_engine();

    let input = genereate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.challenge = 1;

    let sec_message = create_valid_issue_token_message(0, AuthTrustLevel::Atl2 as i32);
    let end_input = CompanionEndAddHostBindingInputFfi {
        request_id: 1,
        result: 0,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionEndAddHostBindingOutputFfi::default();
    let param = CompanionRequestParam::EnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_end_test_atl_try_from_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_end_test_atl_try_from_fail start");

    mock_set_crypto_engine();

    let input = genereate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.challenge = 0;

    let sec_message = create_valid_issue_token_message(0, 99999);
    let end_input = CompanionEndAddHostBindingInputFfi {
        request_id: 1,
        result: 0,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionEndAddHostBindingOutputFfi::default();
    let param = CompanionRequestParam::EnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_end_test_store_token_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_end_test_store_token_fail start");

    mock_set_crypto_engine();

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager.expect_write_device_token().returning(|| Err(ErrorCode::GeneralError));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let input = genereate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.challenge = 0;

    let sec_message = create_valid_issue_token_message(0, AuthTrustLevel::Atl2 as i32);
    let end_input = CompanionEndAddHostBindingInputFfi {
        request_id: 1,
        result: 0,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionEndAddHostBindingOutputFfi::default();
    let param = CompanionRequestParam::EnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}
