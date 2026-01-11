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
    CompanionBeginObtainTokenInputFfi, CompanionEndObtainTokenInputFfi, CompanionProcessTokenAuthInputFfi,
    DataArray1024Ffi, PROPERTY_MODE_UNFREEZE,
};
use crate::log_i;
use crate::request::jobs::common_message::SecIssueToken;
use crate::request::token_obtain::companion_obtain_token::CompanionDeviceObtainTokenRequest;
use crate::request::token_obtain::token_obtain_message::{FwkObtainTokenRequest, SecPreObtainTokenRequest};
use crate::traits::companion_db_manager::{CompanionDbManagerRegistry, MockCompanionDbManager};
use crate::traits::companion_request_manager::{CompanionRequest, CompanionRequestInput};
use crate::traits::crypto_engine::{AesGcmResult, CryptoEngineRegistry, KeyPair, MockCryptoEngine};
use crate::traits::db_manager::{HostDeviceSk, HostTokenInfo};
use crate::traits::misc_manager::{MiscManagerRegistry, MockMiscManager};
use crate::ut_registry_guard;
use crate::utils::message_codec::{MessageCodec, MessageSignParam};
use crate::utils::{Attribute, AttributeKey};
use std::boxed::Box;

fn create_mock_key_pair() -> KeyPair {
    KeyPair { pub_key: vec![1u8, 2, 3], pri_key: vec![4u8, 5, 6] }
}

fn create_valid_fwk_obtain_token_request(property_mode: u32, auth_type: u32, atl: i32) -> Vec<u8> {
    let mut attribute = Attribute::new();
    attribute.set_u32(AttributeKey::AttrPropertyMode, property_mode);
    attribute.set_u32(AttributeKey::AttrType, auth_type);
    attribute.set_i32(AttributeKey::AttrAuthTrustLevel, atl);

    let message_codec = MessageCodec::new(MessageSignParam::Executor(create_mock_key_pair()));
    message_codec.serialize_attribute(&attribute).unwrap()
}

fn create_valid_pre_obtain_token_request(salt: &[u8; HKDF_SALT_SIZE], challenge: u64) -> Vec<u8> {
    let request = SecPreObtainTokenRequest {
        salt: *salt,
        challenge,
    };
    request.encode(DeviceType::None).unwrap()
}

fn create_valid_obtain_token_reply(challenge: u64, atl: i32, session_key: &[u8]) -> Vec<u8> {
    let issue_token = SecIssueToken {
        challenge,
        atl,
        token: vec![1u8; TOKEN_KEY_LEN],
    };
    issue_token.encrypt_issue_token(&[1u8; HKDF_SALT_SIZE], DeviceType::None, session_key).unwrap()
}

fn mock_set_crypto_engine_for_begin() {
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
}

fn mock_set_crypto_engine_for_end() {
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_aes_gcm_decrypt().returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| Ok(AesGcmResult { ciphertext: data.to_vec(),
        authentication_tag: [0u8; AES_GCM_TAG_SIZE],
    }));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
}

fn mock_set_misc_manager() {
    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_get_fwk_pub_key().returning(|| Ok(create_mock_key_pair().pub_key.clone()));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));
}

#[test]
fn companion_obtain_token_request_get_request_id_test() {
    let _guard = ut_registry_guard!();
    log_i!("companion_obtain_token_request_get_request_id_test start");

    let input = CompanionBeginObtainTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        fwk_message: DataArray1024Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let request = CompanionDeviceObtainTokenRequest::new(&input).unwrap();
    assert_eq!(request.get_request_id(), 1);
}

#[test]
fn companion_obtain_token_request_prepare_test_not_implemented() {
    let _guard = ut_registry_guard!();
    log_i!("companion_obtain_token_request_prepare_test_not_implemented start");

    let input = CompanionBeginObtainTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        fwk_message: DataArray1024Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut request = CompanionDeviceObtainTokenRequest::new(&input).unwrap();

    let result = request.prepare(CompanionRequestInput::ObtainTokenBegin(input));
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_obtain_token_request_begin_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("companion_obtain_token_request_begin_test_wrong_input_type start");

    let input = CompanionBeginObtainTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        fwk_message: DataArray1024Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut request = CompanionDeviceObtainTokenRequest::new(&input).unwrap();

    let wrong_input = CompanionProcessTokenAuthInputFfi {
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let result = request.begin(CompanionRequestInput::TokenAuthBegin(wrong_input));
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn companion_obtain_token_request_begin_test_property_mode_not_unfreeze() {
    let _guard = ut_registry_guard!();
    log_i!("companion_obtain_token_request_begin_test_property_mode_not_unfreeze start");

    mock_set_misc_manager();
    mock_set_crypto_engine_for_begin();

    let fwk_message = create_valid_fwk_obtain_token_request(
        999,
        AuthType::CompanionDevice as u32,
        AuthTrustLevel::Atl3 as i32,
    );

    let input = CompanionBeginObtainTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut request = CompanionDeviceObtainTokenRequest::new(&input).unwrap();

    let result = request.begin(CompanionRequestInput::ObtainTokenBegin(input));
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_obtain_token_request_begin_test_auth_type_not_companion_device() {
    let _guard = ut_registry_guard!();
    log_i!("companion_obtain_token_request_begin_test_auth_type_not_companion_device start");

    mock_set_misc_manager();
    mock_set_crypto_engine_for_begin();

    let fwk_message = create_valid_fwk_obtain_token_request(
        PROPERTY_MODE_UNFREEZE,
        999,
        AuthTrustLevel::Atl3 as i32,
    );

    let input = CompanionBeginObtainTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut request = CompanionDeviceObtainTokenRequest::new(&input).unwrap();

    let result = request.begin(CompanionRequestInput::ObtainTokenBegin(input));
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_obtain_token_request_begin_test_atl_try_from_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_obtain_token_request_begin_test_atl_try_from_fail start");

    mock_set_misc_manager();
    mock_set_crypto_engine_for_begin();

    let fwk_message = create_valid_fwk_obtain_token_request(
        PROPERTY_MODE_UNFREEZE,
        AuthType::CompanionDevice as u32,
        99999,
    );

    let input = CompanionBeginObtainTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut request = CompanionDeviceObtainTokenRequest::new(&input).unwrap();

    let result = request.begin(CompanionRequestInput::ObtainTokenBegin(input));
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_obtain_token_request_begin_test_decode_sec_message_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_obtain_token_request_begin_test_decode_sec_message_fail start");

    mock_set_misc_manager();
    mock_set_crypto_engine_for_begin();

    let fwk_message = create_valid_fwk_obtain_token_request(
        PROPERTY_MODE_UNFREEZE,
        AuthType::CompanionDevice as u32,
        AuthTrustLevel::Atl3 as i32,
    );

    let input = CompanionBeginObtainTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut request = CompanionDeviceObtainTokenRequest::new(&input).unwrap();

    let result = request.begin(CompanionRequestInput::ObtainTokenBegin(input));
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_obtain_token_request_begin_test_get_session_key_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_obtain_token_request_begin_test_get_session_key_fail start");

    mock_set_misc_manager();
    mock_set_crypto_engine_for_begin();

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager.expect_read_device_sk().returning(|| Err(ErrorCode::NotFound));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let fwk_message = create_valid_fwk_obtain_token_request(
        PROPERTY_MODE_UNFREEZE,
        AuthType::CompanionDevice as u32,
        AuthTrustLevel::Atl3 as i32,
    );

    let salt = [1u8; HKDF_SALT_SIZE];
    let sec_message = create_valid_pre_obtain_token_request(&salt, 0);

    let input = CompanionBeginObtainTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut request = CompanionDeviceObtainTokenRequest::new(&input).unwrap();

    let result = request.begin(CompanionRequestInput::ObtainTokenBegin(input));
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn companion_obtain_token_request_begin_test_aes_gcm_encrypt_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_obtain_token_request_begin_test_aes_gcm_encrypt_fail start");

    mock_set_misc_manager();

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager.expect_read_device_sk().returning(|| Ok(HostDeviceSk { sk: Vec::new() }));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|_, _| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let fwk_message = create_valid_fwk_obtain_token_request(
        PROPERTY_MODE_UNFREEZE,
        AuthType::CompanionDevice as u32,
        AuthTrustLevel::Atl3 as i32,
    );

    let salt = [1u8; HKDF_SALT_SIZE];
    let sec_message = create_valid_pre_obtain_token_request(&salt, 0);

    let input = CompanionBeginObtainTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut request = CompanionDeviceObtainTokenRequest::new(&input).unwrap();

    let result = request.begin(CompanionRequestInput::ObtainTokenBegin(input));
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_obtain_token_request_end_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("companion_obtain_token_request_end_test_wrong_input_type start");

    let input = CompanionBeginObtainTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        fwk_message: DataArray1024Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut request = CompanionDeviceObtainTokenRequest::new(&input).unwrap();

    let result = request.end(CompanionRequestInput::ObtainTokenBegin(input));
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn companion_obtain_token_request_end_test_challenge_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("companion_obtain_token_request_end_test_challenge_mismatch start");

    mock_set_crypto_engine_for_end();

    let input = CompanionBeginObtainTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        fwk_message: DataArray1024Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut request = CompanionDeviceObtainTokenRequest::new(&input).unwrap();
    request.obtain_param.challenge = 999;

    let sec_message = create_valid_obtain_token_reply(0, AuthTrustLevel::Atl3 as i32, &request.session_key);
    let end_input = CompanionEndObtainTokenInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let result = request.end(CompanionRequestInput::ObtainTokenEnd(end_input));
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_obtain_token_request_end_test_atl_try_from_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_obtain_token_request_end_test_atl_try_from_fail start");

    mock_set_crypto_engine_for_end();

    let input = CompanionBeginObtainTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        fwk_message: DataArray1024Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut request = CompanionDeviceObtainTokenRequest::new(&input).unwrap();
    request.obtain_param.challenge = 0;

    let sec_message = create_valid_obtain_token_reply(0, 99999, &request.session_key);
    let end_input = CompanionEndObtainTokenInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let result = request.end(CompanionRequestInput::ObtainTokenEnd(end_input));
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_obtain_token_request_end_test_store_token_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_obtain_token_request_end_test_store_token_fail start");

    mock_set_crypto_engine_for_end();

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager.expect_write_device_token().returning(|| Err(ErrorCode::GeneralError));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let input = CompanionBeginObtainTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        fwk_message: DataArray1024Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut request = CompanionDeviceObtainTokenRequest::new(&input).unwrap();
    request.obtain_param.challenge = 0;

    let sec_message = create_valid_obtain_token_reply(0, AuthTrustLevel::Atl3 as i32, &request.session_key);
    let end_input = CompanionEndObtainTokenInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let result = request.end(CompanionRequestInput::ObtainTokenEnd(end_input));
    assert_eq!(result, Err(ErrorCode::GeneralError));
}
