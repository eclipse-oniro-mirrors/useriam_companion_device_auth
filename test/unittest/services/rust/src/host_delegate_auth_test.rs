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
    DataArray1024Ffi, HostBeginDelegateAuthInputFfi, HostBeginDelegateAuthOutputFfi, HostEndDelegateAuthInputFfi,
    HostEndDelegateAuthOutputFfi,
};
use crate::log_i;
use crate::request::delegate_auth::host_delegate_auth::HostDelegateAuthRequest;
use crate::request::jobs::common_message::SecCommonReply;
use crate::traits::crypto_engine::{AesGcmResult, CryptoEngineRegistry, KeyPair, MockCryptoEngine};
use crate::traits::db_manager::{
    CompanionDeviceCapability, CompanionDeviceInfo, CompanionDeviceSk, DeviceKey, UserInfo,
};
use crate::traits::host_db_manager::{HostDbManagerRegistry, MockHostDbManager};
use crate::traits::misc_manager::{MiscManagerRegistry, MockMiscManager};
use crate::traits::request_manager::{Request, RequestParam};
use crate::ut_registry_guard;
use crate::utils::message_codec::{MessageCodec, MessageSignParam};
use crate::utils::{Attribute, AttributeKey};
use crate::String;
use crate::Vec;
use std::boxed::Box;

fn create_mock_key_pair() -> KeyPair {
    KeyPair { pub_key: vec![1u8, 2, 3], pri_key: vec![4u8, 5, 6] }
}

fn create_valid_fwk_message(schedule_id: u64, atl: i32) -> Vec<u8> {
    let mut attribute = Attribute::new();
    attribute.set_u64(AttributeKey::AttrScheduleId, schedule_id);
    attribute.set_i32(AttributeKey::AttrAuthTrustLevel, atl);

    let message_codec = MessageCodec::new(MessageSignParam::Executor(create_mock_key_pair()));
    message_codec.serialize_attribute(&attribute).unwrap()
}

fn create_valid_sec_reply_message(challenge: u64, atl: i32, auth_type: i32) -> Vec<u8> {
    let mut encrypt_attribute = Attribute::new();
    encrypt_attribute.set_u64(AttributeKey::AttrChallenge, challenge);
    encrypt_attribute.set_i32(AttributeKey::AttrType, auth_type);
    encrypt_attribute.set_i32(AttributeKey::AttrAuthTrustLevel, atl);

    let encrypt_data = encrypt_attribute.to_bytes().unwrap();
    let tag = [1u8; AES_GCM_TAG_SIZE];
    let iv = [2u8; AES_GCM_IV_SIZE];

    let reply = SecCommonReply { tag, iv, encrypt_data };
    reply.encode(DeviceType::Default).unwrap()
}

fn mock_set_crypto_engine() {
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    mock_crypto_engine
        .expect_generate_x25519_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    mock_crypto_engine
        .expect_x25519_ecdh()
        .returning(|| Ok([0u8; SHARE_KEY_LEN].to_vec()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
}

fn mock_set_misc_manager() {
    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager
        .expect_get_fwk_pub_key()
        .returning(|| Ok(create_mock_key_pair().pub_key.clone()));
    mock_misc_manager
        .expect_get_local_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));
}

fn mock_set_host_db_manager() {
    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_read_device_capability_info().returning(|| {
        Ok(vec![CompanionDeviceCapability {
            device_type: DeviceType::Default,
            esl: ExecutorSecurityLevel::Esl3,
            track_ability_level: TrackAbilityLevel::Tal1,
        }])
    });
    mock_host_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceSk { device_type: DeviceType::Default, sk: [0u8; SHARE_KEY_LEN] }]));
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));
}

fn create_mock_companion_device_info(template_id: u64) -> CompanionDeviceInfo {
    CompanionDeviceInfo {
        template_id,
        device_key: DeviceKey { device_id: String::from("test_device"), device_id_type: 1, user_id: 100 },
        user_info: UserInfo { user_id: 100, user_type: 0 },
        added_time: 123456,
        secure_protocol_id: 1,
        is_valid: true,
        capability_list: vec![1, 2, 3], // Includes both DelegateAuth(1) and TokenAuth(2)
    }
}

#[test]
fn host_delegate_auth_request_new_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_delegate_auth_request_new_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let result = HostDelegateAuthRequest::new(&input);
    assert!(result.is_ok());

    let request = result.unwrap();
    assert_eq!(request.get_request_id(), 1);
    assert_eq!(request.auth_param.schedule_id, 1);
    assert_eq!(request.auth_param.template_id, 123);
    assert_eq!(request.atl, AuthTrustLevel::Atl2);
    assert_eq!(request.acl, AuthCapabilityLevel::Acl0);
}

#[test]
fn host_delegate_auth_request_new_test_secure_random_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_delegate_auth_request_new_test_secure_random_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_secure_random()
        .returning(|_| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let result = HostDelegateAuthRequest::new(&input);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_delegate_auth_request_prepare_test_not_implemented() {
    let _guard = ut_registry_guard!();
    log_i!("host_delegate_auth_request_prepare_test_not_implemented start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let mut request = HostDelegateAuthRequest::new(&input).unwrap();

    let mut output = HostBeginDelegateAuthOutputFfi::default();
    let param = RequestParam::HostDelegateAuthBegin(&input, &mut output);
    let result = request.prepare(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_delegate_auth_request_begin_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("host_delegate_auth_request_begin_test_wrong_input_type start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let mut request = HostDelegateAuthRequest::new(&input).unwrap();

    let wrong_input =
        HostEndDelegateAuthInputFfi { request_id: 1, secure_protocol_id: 1, sec_message: DataArray1024Ffi::default() };

    let mut output = HostEndDelegateAuthOutputFfi::default();
    let param = RequestParam::HostDelegateAuthEnd(&wrong_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn host_delegate_auth_request_end_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("host_delegate_auth_request_end_test_wrong_input_type start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let mut request = HostDelegateAuthRequest::new(&input).unwrap();

    let mut output = HostBeginDelegateAuthOutputFfi::default();
    let param = RequestParam::HostDelegateAuthBegin(&input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn host_delegate_auth_request_begin_test_schedule_id_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("host_delegate_auth_request_begin_test_schedule_id_mismatch start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let fwk_message = create_valid_fwk_message(99999, AuthTrustLevel::Atl3 as i32);
    let input = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
    };

    let mut request = HostDelegateAuthRequest::new(&input).unwrap();

    let mut output = HostBeginDelegateAuthOutputFfi::default();
    let param = RequestParam::HostDelegateAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_delegate_auth_request_begin_test_atl_try_from_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_delegate_auth_request_begin_test_atl_try_from_fail start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let fwk_message = create_valid_fwk_message(1, 99999);
    let input = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
    };

    let mut request = HostDelegateAuthRequest::new(&input).unwrap();

    let mut output = HostBeginDelegateAuthOutputFfi::default();
    let param = RequestParam::HostDelegateAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_delegate_auth_request_begin_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_delegate_auth_request_begin_test_success start");

    mock_set_crypto_engine();
    mock_set_misc_manager();
    mock_set_host_db_manager();

    let fwk_message = create_valid_fwk_message(1, AuthTrustLevel::Atl3 as i32);
    let input = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
    };

    let mut request = HostDelegateAuthRequest::new(&input).unwrap();

    let mut output = HostBeginDelegateAuthOutputFfi::default();
    let param = RequestParam::HostDelegateAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert!(result.is_ok());
}

#[test]
fn host_delegate_auth_request_begin_test_read_device_capability_info_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_delegate_auth_request_begin_test_read_device_capability_info_fail start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123)));
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Err(ErrorCode::NotFound));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let fwk_message = create_valid_fwk_message(1, AuthTrustLevel::Atl3 as i32);
    let input = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
    };

    let mut request = HostDelegateAuthRequest::new(&input).unwrap();

    let mut output = HostBeginDelegateAuthOutputFfi::default();
    let param = RequestParam::HostDelegateAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn host_delegate_auth_request_begin_test_get_session_key_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_delegate_auth_request_begin_test_get_session_key_fail start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123)));
    mock_host_db_manager.expect_read_device_capability_info().returning(|| {
        Ok(vec![CompanionDeviceCapability {
            device_type: DeviceType::Default,
            esl: ExecutorSecurityLevel::Esl3,
            track_ability_level: TrackAbilityLevel::Tal1,
        }])
    });
    mock_host_db_manager
        .expect_read_device_sk()
        .returning(|| Err(ErrorCode::GeneralError));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let fwk_message = create_valid_fwk_message(1, AuthTrustLevel::Atl3 as i32);
    let input = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
    };

    let mut request = HostDelegateAuthRequest::new(&input).unwrap();

    let mut output = HostBeginDelegateAuthOutputFfi::default();
    let param = RequestParam::HostDelegateAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_delegate_auth_request_end_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_delegate_auth_request_end_test_success start");

    mock_set_crypto_engine();
    mock_set_misc_manager();
    mock_set_host_db_manager();

    let input_ffi = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let mut request = HostDelegateAuthRequest::new(&input_ffi).unwrap();
    request.challenge = 0;

    let sec_message = create_valid_sec_reply_message(0, AuthTrustLevel::Atl3 as i32, 64);
    let end_input = HostEndDelegateAuthInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndDelegateAuthOutputFfi::default();
    let param = RequestParam::HostDelegateAuthEnd(&end_input, &mut output);
    let result = request.end(param);
    assert!(result.is_ok());
}

#[test]
fn host_delegate_auth_request_end_test_challenge_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("host_delegate_auth_request_end_test_challenge_mismatch start");

    mock_set_crypto_engine();
    mock_set_misc_manager();
    mock_set_host_db_manager();

    let input_ffi = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let mut request = HostDelegateAuthRequest::new(&input_ffi).unwrap();
    request.challenge = 1;

    let sec_message = create_valid_sec_reply_message(0, AuthTrustLevel::Atl3 as i32, 64);
    let end_input = HostEndDelegateAuthInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndDelegateAuthOutputFfi::default();
    let param = RequestParam::HostDelegateAuthEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_delegate_auth_request_end_test_atl_try_from_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_delegate_auth_request_end_test_atl_try_from_fail start");

    mock_set_crypto_engine();
    mock_set_misc_manager();
    mock_set_host_db_manager();

    let input_ffi = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let mut request = HostDelegateAuthRequest::new(&input_ffi).unwrap();
    request.challenge = 0;

    let sec_message = create_valid_sec_reply_message(0, 99999, 64);
    let end_input = HostEndDelegateAuthInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndDelegateAuthOutputFfi::default();
    let param = RequestParam::HostDelegateAuthEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_delegate_auth_request_end_test_sec_message_decode_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_delegate_auth_request_end_test_sec_message_decode_fail start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123)));
    mock_host_db_manager.expect_read_device_capability_info().returning(|| {
        Ok(vec![CompanionDeviceCapability {
            device_type: DeviceType::Default,
            esl: ExecutorSecurityLevel::Esl3,
            track_ability_level: TrackAbilityLevel::Tal1,
        }])
    });
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input_ffi = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let mut request = HostDelegateAuthRequest::new(&input_ffi).unwrap();
    request.challenge = 0;

    let end_input =
        HostEndDelegateAuthInputFfi { request_id: 1, secure_protocol_id: 1, sec_message: DataArray1024Ffi::default() };

    let mut output = HostEndDelegateAuthOutputFfi::default();
    let param = RequestParam::HostDelegateAuthEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_delegate_auth_request_end_test_get_session_key_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_delegate_auth_request_end_test_get_session_key_fail start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123)));
    mock_host_db_manager.expect_read_device_capability_info().returning(|| {
        Ok(vec![CompanionDeviceCapability {
            device_type: DeviceType::Default,
            esl: ExecutorSecurityLevel::Esl3,
            track_ability_level: TrackAbilityLevel::Tal1,
        }])
    });
    mock_host_db_manager
        .expect_read_device_sk()
        .returning(|| Err(ErrorCode::GeneralError));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input_ffi = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let mut request = HostDelegateAuthRequest::new(&input_ffi).unwrap();
    request.challenge = 0;

    let sec_message = create_valid_sec_reply_message(0, AuthTrustLevel::Atl3 as i32, 64);
    let end_input = HostEndDelegateAuthInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndDelegateAuthOutputFfi::default();
    let param = RequestParam::HostDelegateAuthEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_delegate_auth_request_end_test_try_from_bytes_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_delegate_auth_request_end_test_try_from_bytes_fail start");

    mock_set_crypto_engine();
    mock_set_misc_manager();
    mock_set_host_db_manager();

    let input_ffi = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let mut request = HostDelegateAuthRequest::new(&input_ffi).unwrap();

    let tag = [1u8; AES_GCM_TAG_SIZE];
    let iv = [2u8; AES_GCM_IV_SIZE];
    let encrypt_data = Vec::new();

    let reply = SecCommonReply { tag, iv, encrypt_data };
    let sec_message = reply.encode(DeviceType::Default).unwrap();

    let end_input = HostEndDelegateAuthInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndDelegateAuthOutputFfi::default();
    let param = RequestParam::HostDelegateAuthEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_delegate_auth_request_end_test_get_type_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_delegate_auth_request_end_test_get_type_fail start");

    mock_set_crypto_engine();
    mock_set_misc_manager();
    mock_set_host_db_manager();

    let input_ffi = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let mut request = HostDelegateAuthRequest::new(&input_ffi).unwrap();

    let mut encrypt_attribute = Attribute::new();
    encrypt_attribute.set_u64(AttributeKey::AttrChallenge, 0);
    encrypt_attribute.set_i32(AttributeKey::AttrAuthTrustLevel, 30000);

    let encrypt_data = encrypt_attribute.to_bytes().unwrap();
    let tag = [1u8; AES_GCM_TAG_SIZE];
    let iv = [2u8; AES_GCM_IV_SIZE];

    let reply = SecCommonReply { tag, iv, encrypt_data };
    let sec_message = reply.encode(DeviceType::Default).unwrap();

    let end_input = HostEndDelegateAuthInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndDelegateAuthOutputFfi::default();
    let param = RequestParam::HostDelegateAuthEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_delegate_auth_request_end_test_get_atl_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_delegate_auth_request_end_test_get_atl_fail start");

    mock_set_crypto_engine();
    mock_set_misc_manager();
    mock_set_host_db_manager();

    let input_ffi = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let mut request = HostDelegateAuthRequest::new(&input_ffi).unwrap();

    let mut encrypt_attribute = Attribute::new();
    encrypt_attribute.set_u64(AttributeKey::AttrChallenge, 0);
    encrypt_attribute.set_i32(AttributeKey::AttrType, 64);

    let encrypt_data = encrypt_attribute.to_bytes().unwrap();
    let tag = [1u8; AES_GCM_TAG_SIZE];
    let iv = [2u8; AES_GCM_IV_SIZE];

    let reply = SecCommonReply { tag, iv, encrypt_data };
    let sec_message = reply.encode(DeviceType::Default).unwrap();

    let end_input = HostEndDelegateAuthInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndDelegateAuthOutputFfi::default();
    let param = RequestParam::HostDelegateAuthEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_delegate_auth_request_end_test_get_challenge_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_delegate_auth_request_end_test_get_challenge_fail start");

    mock_set_crypto_engine();
    mock_set_misc_manager();
    mock_set_host_db_manager();

    let input_ffi = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let mut request = HostDelegateAuthRequest::new(&input_ffi).unwrap();

    let mut encrypt_attribute = Attribute::new();
    encrypt_attribute.set_i32(AttributeKey::AttrType, 64);
    encrypt_attribute.set_i32(AttributeKey::AttrAuthTrustLevel, 30000);

    let encrypt_data = encrypt_attribute.to_bytes().unwrap();
    let tag = [1u8; AES_GCM_TAG_SIZE];
    let iv = [2u8; AES_GCM_IV_SIZE];

    let reply = SecCommonReply { tag, iv, encrypt_data };
    let sec_message = reply.encode(DeviceType::Default).unwrap();

    let end_input = HostEndDelegateAuthInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndDelegateAuthOutputFfi::default();
    let param = RequestParam::HostDelegateAuthEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}
