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
    DataArray1024Ffi, HostBeginIssueTokenInputFfi, HostBeginIssueTokenOutputFfi, HostEndIssueTokenInputFfi,
    HostEndIssueTokenOutputFfi, HostPreIssueTokenInputFfi, HostPreIssueTokenOutputFfi, PROPERTY_MODE_UNFREEZE,
};
use crate::log_i;
use crate::request::jobs::common_message::{SecCommonReply, SecIssueToken};
use crate::request::token_issue::host_issue_token::HostDeviceIssueTokenRequest;
use crate::request::token_issue::token_issue_message::SecIssueTokenReply;
use crate::traits::crypto_engine::{AesGcmResult, CryptoEngineRegistry, KeyPair, MockCryptoEngine};
use crate::traits::db_manager::{CompanionDeviceCapability, CompanionDeviceSk};
use crate::traits::host_db_manager::{HostDbManagerRegistry, MockHostDbManager};
use crate::traits::misc_manager::{MiscManagerRegistry, MockMiscManager};
use crate::traits::request_manager::{Request, RequestParam};
use crate::traits::time_keeper::{MockTimeKeeper, TimeKeeperRegistry};
use crate::ut_registry_guard;
use crate::utils::message_codec::{MessageCodec, MessageSignParam};
use crate::utils::{Attribute, AttributeKey};
use std::boxed::Box;

fn create_mock_key_pair() -> KeyPair {
    KeyPair { pub_key: vec![1u8, 2, 3], pri_key: vec![4u8, 5, 6] }
}

fn create_valid_fwk_issue_token_request(property_mode: u32, auth_type: u32, atl: i32, template_ids: &[u64]) -> Vec<u8> {
    let mut attribute = Attribute::new();
    attribute.set_u32(AttributeKey::AttrPropertyMode, property_mode);
    attribute.set_u32(AttributeKey::AttrType, auth_type);
    attribute.set_i32(AttributeKey::AttrAuthTrustLevel, atl);
    attribute.set_u64_slice(AttributeKey::AttrTemplateIdList, template_ids);

    let message_codec = MessageCodec::new(MessageSignParam::Executor(create_mock_key_pair()));
    message_codec.serialize_attribute(&attribute).unwrap()
}

fn create_valid_pre_issue_reply(challenge: u64) -> Vec<u8> {
    let mut encrypt_attribute = Attribute::new();
    encrypt_attribute.set_u64(AttributeKey::AttrChallenge, challenge);

    let encrypt_data = encrypt_attribute.to_bytes().unwrap();
    let tag = [1u8; AES_GCM_TAG_SIZE];
    let iv = [2u8; AES_GCM_IV_SIZE];

    let reply = SecCommonReply { tag, iv, encrypt_data };
    reply.encode(DeviceType::None).unwrap()
}

fn create_valid_issue_token_reply(result: i32) -> Vec<u8> {
    let reply = SecIssueTokenReply { result };
    reply.encode(DeviceType::None).unwrap()
}

fn mock_set_crypto_engine() {
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
}

fn mock_set_misc_manager() {
    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager
        .expect_get_fwk_pub_key()
        .returning(|| Ok(create_mock_key_pair().pub_key.clone()));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));
}

fn mock_set_host_db_manager() {
    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_read_device_capability_info().returning(|| {
        Ok(vec![CompanionDeviceCapability {
            device_type: DeviceType::None,
            esl: ExecutorSecurityLevel::Esl3,
            track_ability_level: 1,
        }])
    });
    mock_host_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceSk { device_type: DeviceType::None, sk: Vec::new() }]));
    mock_host_db_manager.expect_add_token().returning(|| Ok(()));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));
}

#[test]
fn host_issue_token_request_prepare_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_prepare_test_wrong_input_type start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };

    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();

    let wrong_input =
        HostBeginIssueTokenInputFfi { request_id: 1, secure_protocol_id: 1, sec_message: DataArray1024Ffi::default() };

    let mut output = HostBeginIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenBegin(&wrong_input, &mut output);
    let result = request.prepare(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn host_issue_token_request_prepare_test_property_mode_not_unfreeze() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_prepare_test_property_mode_not_unfreeze start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let fwk_message = create_valid_fwk_issue_token_request(
        999,
        AuthType::CompanionDevice as u32,
        AuthTrustLevel::Atl3 as i32,
        &[123u64],
    );

    let input = HostPreIssueTokenInputFfi {
        request_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
    };
    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();

    let mut output = HostPreIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenPrepare(&input, &mut output);
    let result = request.prepare(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_issue_token_request_prepare_test_auth_type_not_companion_device() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_prepare_test_auth_type_not_companion_device start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let fwk_message =
        create_valid_fwk_issue_token_request(PROPERTY_MODE_UNFREEZE, 999, AuthTrustLevel::Atl3 as i32, &[123u64]);

    let input = HostPreIssueTokenInputFfi {
        request_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
    };
    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();

    let mut output = HostPreIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenPrepare(&input, &mut output);
    let result = request.prepare(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_issue_token_request_prepare_test_template_id_not_found() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_prepare_test_template_id_not_found start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let fwk_message = create_valid_fwk_issue_token_request(
        PROPERTY_MODE_UNFREEZE,
        AuthType::CompanionDevice as u32,
        AuthTrustLevel::Atl3 as i32,
        &[456u64],
    );

    let input = HostPreIssueTokenInputFfi {
        request_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
    };
    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();

    let mut output = HostPreIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenPrepare(&input, &mut output);
    let result = request.prepare(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_issue_token_request_prepare_test_atl_try_from_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_prepare_test_atl_try_from_fail start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let fwk_message = create_valid_fwk_issue_token_request(
        PROPERTY_MODE_UNFREEZE,
        AuthType::CompanionDevice as u32,
        99999,
        &[123u64],
    );

    let input = HostPreIssueTokenInputFfi {
        request_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
    };
    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();

    let mut output = HostPreIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenPrepare(&input, &mut output);
    let result = request.prepare(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_issue_token_request_prepare_test_read_device_capability_info_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_prepare_test_read_device_capability_info_fail start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Err(ErrorCode::NotFound));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let fwk_message = create_valid_fwk_issue_token_request(
        PROPERTY_MODE_UNFREEZE,
        AuthType::CompanionDevice as u32,
        AuthTrustLevel::Atl3 as i32,
        &[123u64],
    );

    let input = HostPreIssueTokenInputFfi {
        request_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
    };
    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();

    let mut output = HostPreIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenPrepare(&input, &mut output);
    let result = request.prepare(param);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn host_issue_token_request_prepare_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_prepare_test_success start");

    mock_set_crypto_engine();
    mock_set_misc_manager();
    mock_set_host_db_manager();

    let fwk_message = create_valid_fwk_issue_token_request(
        PROPERTY_MODE_UNFREEZE,
        AuthType::CompanionDevice as u32,
        AuthTrustLevel::Atl3 as i32,
        &[123u64],
    );

    let input = HostPreIssueTokenInputFfi {
        request_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
    };
    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();

    let mut output = HostPreIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenPrepare(&input, &mut output);
    let result = request.prepare(param);
    assert!(result.is_ok());
}

#[test]
fn host_issue_token_request_begin_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_begin_test_wrong_input_type start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };

    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();

    let wrong_input =
        HostEndIssueTokenInputFfi { request_id: 1, secure_protocol_id: 1, sec_message: DataArray1024Ffi::default() };

    let mut output = HostEndIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenEnd(&wrong_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn host_issue_token_request_begin_test_decode_sec_message_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_begin_test_decode_sec_message_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    mock_set_host_db_manager();

    let input = HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };
    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();

    let begin_input =
        HostBeginIssueTokenInputFfi { request_id: 1, secure_protocol_id: 1, sec_message: DataArray1024Ffi::default() };

    let mut output = HostBeginIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_issue_token_request_begin_test_get_session_key_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_begin_test_token_infos_empty start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    mock_set_host_db_manager();

    let input = HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };
    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();

    let sec_message = create_valid_pre_issue_reply(0);
    let begin_input = HostBeginIssueTokenInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostBeginIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_issue_token_request_begin_test_decrypt_sec_message_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_begin_test_decrypt_sec_message_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    mock_set_host_db_manager();

    let input = HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };
    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();

    let sec_message = create_valid_pre_issue_reply(0);
    let begin_input = HostBeginIssueTokenInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostBeginIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_issue_token_request_begin_test_try_from_bytes_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_begin_test_try_from_bytes_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    mock_set_host_db_manager();

    let input = HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };
    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();

    let encrypt_attribute = Attribute::new();
    let encrypt_data = encrypt_attribute.to_bytes().unwrap();
    let tag = [1u8; AES_GCM_TAG_SIZE];
    let iv = [2u8; AES_GCM_IV_SIZE];

    let reply = SecCommonReply { tag, iv, encrypt_data };
    let sec_message = reply.encode(DeviceType::None).unwrap();

    let begin_input = HostBeginIssueTokenInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostBeginIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_issue_token_request_begin_test_miss_challenge() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_begin_test_miss_challenge start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    mock_set_host_db_manager();

    let input = HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };
    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();

    let mut encrypt_attribute = Attribute::new();
    encrypt_attribute.set_u32(AttributeKey::AttrResultCode, 0);

    let encrypt_data = encrypt_attribute.to_bytes().unwrap();
    let tag = [1u8; AES_GCM_TAG_SIZE];
    let iv = [2u8; AES_GCM_IV_SIZE];

    let reply = SecCommonReply { tag, iv, encrypt_data };
    let sec_message = reply.encode(DeviceType::None).unwrap();

    let begin_input = HostBeginIssueTokenInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostBeginIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_issue_token_request_begin_test_secure_random_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_begin_test_secure_random_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_secure_random()
        .returning(|_buf| Err(ErrorCode::GeneralError));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    mock_set_host_db_manager();

    let input = HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };
    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();

    let sec_message = create_valid_pre_issue_reply(0);
    let begin_input = HostBeginIssueTokenInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostBeginIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_issue_token_request_begin_test_generate_token_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_begin_test_secure_random_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_secure_random()
        .returning(|_buf| Err(ErrorCode::GeneralError));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    mock_set_host_db_manager();

    let input = HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };
    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();

    let sec_message = create_valid_pre_issue_reply(0);
    let begin_input = HostBeginIssueTokenInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostBeginIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_issue_token_request_begin_test_token_infos_empty() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_begin_test_token_infos_empty start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Ok(Vec::new()));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };
    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();

    let sec_message = create_valid_pre_issue_reply(0);
    let begin_input = HostBeginIssueTokenInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostBeginIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_issue_token_request_begin_test_sec_message_get_session_key_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_begin_test_sec_message_get_session_key_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Err(ErrorCode::GeneralError));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    mock_set_host_db_manager();

    let input = HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };
    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();

    let sec_message = create_valid_pre_issue_reply(0);
    let begin_input = HostBeginIssueTokenInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostBeginIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_issue_token_request_begin_test_sec_message_encrypt_issue_token_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_begin_test_sec_message_encrypt_issue_token_fail start");

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

    let input = HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };
    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();

    let sec_message = create_valid_pre_issue_reply(0);
    let begin_input = HostBeginIssueTokenInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostBeginIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_issue_token_request_end_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_end_test_wrong_input_type start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };
    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();

    let wrong_input =
        HostBeginIssueTokenInputFfi { request_id: 1, secure_protocol_id: 1, sec_message: DataArray1024Ffi::default() };

    let mut output = HostBeginIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenBegin(&wrong_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn host_issue_token_request_end_test_decode_sec_message_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_end_test_decode_sec_message_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };

    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();
    request.token_infos.push(crate::request::jobs::token_helper::DeviceTokenInfo {
        device_type: DeviceType::None,
        challenge: 0,
        token: vec![1u8; TOKEN_KEY_LEN],
        atl: AuthTrustLevel::Atl3,
    });

    let end_input =
        HostEndIssueTokenInputFfi { request_id: 1, secure_protocol_id: 1, sec_message: DataArray1024Ffi::default() };

    let mut output = HostEndIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_issue_token_request_end_test_result_not_zero() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_end_test_result_not_zero start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };

    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();
    request.token_infos.push(crate::request::jobs::token_helper::DeviceTokenInfo {
        device_type: DeviceType::None,
        challenge: 0,
        token: vec![1u8; TOKEN_KEY_LEN],
        atl: AuthTrustLevel::Atl3,
    });

    let mut attribute = Attribute::new();
    attribute.set_i32(AttributeKey::AttrResultCode, 1);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());

    let sec_message = final_attribute.to_bytes().unwrap();
    let end_input = HostEndIssueTokenInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_issue_token_request_end_test_get_rtc_time_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_end_test_get_rtc_time_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper
        .expect_get_rtc_time()
        .returning(|| Err(ErrorCode::GeneralError));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let input = HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };

    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();
    request.token_infos.push(crate::request::jobs::token_helper::DeviceTokenInfo {
        device_type: DeviceType::None,
        challenge: 0,
        token: vec![1u8; TOKEN_KEY_LEN],
        atl: AuthTrustLevel::Atl3,
    });

    let sec_message = create_valid_issue_token_reply(0);
    let end_input = HostEndIssueTokenInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_issue_token_request_end_test_add_token_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_end_test_add_token_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_add_token()
        .returning(|| Err(ErrorCode::GeneralError));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Ok(1000));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let input = HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };

    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();
    request.token_infos.push(crate::request::jobs::token_helper::DeviceTokenInfo {
        device_type: DeviceType::None,
        challenge: 0,
        token: vec![1u8; TOKEN_KEY_LEN],
        atl: AuthTrustLevel::Atl3,
    });

    let sec_message = create_valid_issue_token_reply(0);
    let end_input = HostEndIssueTokenInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_issue_token_request_end_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_issue_token_request_end_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Ok(1000));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    mock_set_host_db_manager();

    let input = HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };

    let mut request = HostDeviceIssueTokenRequest::new(&input).unwrap();
    request.atl = AuthTrustLevel::Atl3;
    request.token_infos.push(crate::request::jobs::token_helper::DeviceTokenInfo {
        device_type: DeviceType::None,
        challenge: 0,
        token: vec![1u8; TOKEN_KEY_LEN],
        atl: AuthTrustLevel::Atl3,
    });

    let sec_message = create_valid_issue_token_reply(0);
    let end_input = HostEndIssueTokenInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndIssueTokenOutputFfi::default();
    let param = RequestParam::HostIssueTokenEnd(&end_input, &mut output);
    let result = request.end(param);
    assert!(result.is_ok());
}
