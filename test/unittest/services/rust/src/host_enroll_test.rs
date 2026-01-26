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
    DataArray1024Ffi, DataArray20000Ffi, DeviceKeyFfi, HostBeginAddCompanionInputFfi, HostBeginAddCompanionOutputFfi,
    HostBeginCompanionCheckOutputFfi, HostEndAddCompanionInputFfi, HostEndAddCompanionOutputFfi,
    HostEndCompanionCheckOutputFfi, HostGetInitKeyNegotiationInputFfi, HostGetInitKeyNegotiationOutputFfi,
    PersistedCompanionStatusFfi,
};
use crate::log_i;
use crate::request::enroll::enroll_message::{SecBindingReply, SecBindingReplyInfo, SecKeyNegoReply};
use crate::request::enroll::host_enroll::{HostDeviceEnrollRequest, KeyNegotialParam};
use crate::traits::crypto_engine::{AesGcmResult, CryptoEngineRegistry, KeyPair, MockCryptoEngine};
use crate::traits::db_manager::{CompanionDeviceCapability, CompanionDeviceSk, DeviceKey};
use crate::traits::host_db_manager::{HostDbManagerRegistry, MockHostDbManager};
use crate::traits::misc_manager::{MiscManagerRegistry, MockMiscManager};
use crate::traits::request_manager::{Request, RequestParam};
use crate::traits::time_keeper::{MockTimeKeeper, TimeKeeperRegistry};
use crate::ut_registry_guard;
use crate::utils::message_codec::{MessageCodec, MessageSignParam};
use crate::utils::{Attribute, AttributeKey};
use std::boxed::Box;

fn create_mock_key_pair() -> KeyPair {
    KeyPair { pub_key: vec![1u8, 2, 3, 4, 5], pri_key: vec![4u8, 5, 6] }
}

fn create_valid_fwk_enroll_message(schedule_id: u64, atl: i32) -> Vec<u8> {
    let mut attribute = Attribute::new();
    attribute.set_u64(AttributeKey::AttrScheduleId, schedule_id);
    attribute.set_i32(AttributeKey::AttrAuthTrustLevel, atl);

    let message_codec = MessageCodec::new(MessageSignParam::Executor(create_mock_key_pair()));
    message_codec.serialize_attribute(&attribute).unwrap()
}

fn create_valid_key_nego_reply(challenge: u64) -> Vec<u8> {
    let reply = SecKeyNegoReply { algorithm: AlgoType::X25519 as u16, challenge, pub_key: vec![1u8, 2, 3, 4, 5] };
    reply.encode(DeviceType::None).unwrap()
}

fn create_valid_binding_reply(
    device_id: &str,
    user_id: i32,
    protocol: &[u16],
    capability: &[u16],
    esl: i32,
) -> Vec<u8> {
    let reply_info = SecBindingReplyInfo {
        device_id: device_id.to_string(),
        user_id,
        esl,
        track_ability_level: 0,
        challenge: 0,
        protocol_list: protocol.to_vec(),
        capability_list: capability.to_vec(),
    };

    let encrypt_data = reply_info.encode().unwrap();
    let reply = SecBindingReply { tag: [2u8; AES_GCM_TAG_SIZE], iv: [3u8; AES_GCM_IV_SIZE], encrypt_data };
    reply.encode(DeviceType::None).unwrap()
}

fn create_key_negotial_param() -> KeyNegotialParam {
    KeyNegotialParam {
        device_type: DeviceType::None,
        algorithm: AlgoType::X25519 as u16,
        challenge: 0,
        key_pair: Some(create_mock_key_pair()),
        sk: vec![1u8; 32],
    }
}

fn create_device_key(device_id: &str, user_id: i32) -> DeviceKey {
    DeviceKey { device_id: device_id.to_string(), device_id_type: 1, user_id }
}

fn mock_set_crypto_engine() {
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
}

fn mock_set_time_keeper() {
    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Ok(1000));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));
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

#[test]
fn host_enroll_request_prepare_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_prepare_test_wrong_input_type start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let mut output = HostGetInitKeyNegotiationOutputFfi::default();
    let param = RequestParam::HostKeyNego(&input, &mut output);
    let result = request.prepare(param);
    assert!(result.is_ok());
}

#[test]
fn host_enroll_request_prepare_test_secure_protocol_id_try_from_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_prepare_test_secure_protocol_id_try_from_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 100 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let mut output = HostGetInitKeyNegotiationOutputFfi::default();
    let param = RequestParam::HostKeyNego(&input, &mut output);
    let result = request.prepare(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn host_enroll_request_prepare_test_secure_protocol_id_invalid() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_prepare_test_secure_protocol_id_invalid start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 0 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let mut output = HostGetInitKeyNegotiationOutputFfi::default();
    let param = RequestParam::HostKeyNego(&input, &mut output);
    let result = request.prepare(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_begin_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_begin_test_wrong_input_type start");

    mock_set_misc_manager();

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    mock_crypto_engine
        .expect_generate_x25519_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Ok(Vec::new()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_encrypt()
        .returning(|_, _| Ok(AesGcmResult { ciphertext: Vec::new(), authentication_tag: [0u8; 16] }));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let fwk_message = create_valid_fwk_enroll_message(1, AuthTrustLevel::Atl2 as i32);
    let sec_message = create_valid_key_nego_reply(0);
    let begin_input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi::default(),
        companion_device_key: DeviceKeyFfi::default(),
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostBeginAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert!(result.is_ok());
}

#[test]
fn host_enroll_request_begin_test_schedule_id_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_begin_test_schedule_id_mismatch start");

    mock_set_misc_manager();

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let fwk_message = create_valid_fwk_enroll_message(2, AuthTrustLevel::Atl2 as i32);
    let begin_input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi::default(),
        companion_device_key: DeviceKeyFfi::default(),
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::default(),
    };

    let mut output = HostBeginAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_begin_test_atl_try_from_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_begin_test_atl_try_from_fail start");

    mock_set_misc_manager();

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let fwk_message = create_valid_fwk_enroll_message(1, 99999);
    let begin_input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi::default(),
        companion_device_key: DeviceKeyFfi::default(),
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::default(),
    };

    let mut output = HostBeginAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_begin_test_secure_protocol_id_try_from_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_begin_test_secure_protocol_id_try_from_fail start");

    mock_set_misc_manager();

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 100 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let fwk_message = create_valid_fwk_enroll_message(1, AuthTrustLevel::Atl2 as i32);
    let begin_input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi::default(),
        companion_device_key: DeviceKeyFfi::default(),
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::default(),
    };

    let mut output = HostBeginAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn host_enroll_request_begin_test_secure_protocol_id_invalid() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_begin_test_secure_protocol_id_invalid start");

    mock_set_misc_manager();

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 0 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let fwk_message = create_valid_fwk_enroll_message(1, AuthTrustLevel::Atl2 as i32);
    let begin_input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi::default(),
        companion_device_key: DeviceKeyFfi::default(),
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::default(),
    };

    let mut output = HostBeginAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_begin_test_sec_message_decode_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_begin_test_sec_message_decode_fail start");

    mock_set_misc_manager();

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let fwk_message = create_valid_fwk_enroll_message(1, AuthTrustLevel::Atl2 as i32);
    let begin_input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi::default(),
        companion_device_key: DeviceKeyFfi::default(),
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::default(),
    };

    let mut output = HostBeginAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_begin_test_generate_key_pair_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_begin_test_generate_key_pair_fail start");

    mock_set_misc_manager();

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    mock_crypto_engine
        .expect_generate_x25519_key_pair()
        .returning(|| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let fwk_message = create_valid_fwk_enroll_message(1, AuthTrustLevel::Atl2 as i32);
    let sec_message = create_valid_key_nego_reply(0);

    let begin_input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi::default(),
        companion_device_key: DeviceKeyFfi::default(),
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostBeginAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_begin_test_x25519_ecdh_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_begin_test_x25519_ecdh_fail start");

    mock_set_misc_manager();

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
        .returning(|| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let fwk_message = create_valid_fwk_enroll_message(1, AuthTrustLevel::Atl2 as i32);
    let sec_message = create_valid_key_nego_reply(0);

    let begin_input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi::default(),
        companion_device_key: DeviceKeyFfi::default(),
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostBeginAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_begin_test_hkdf_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_begin_test_hkdf_fail start");

    mock_set_misc_manager();

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    mock_crypto_engine
        .expect_generate_x25519_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Ok(Vec::new()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let fwk_message = create_valid_fwk_enroll_message(1, AuthTrustLevel::Atl2 as i32);
    let sec_message = create_valid_key_nego_reply(0);

    let begin_input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi::default(),
        companion_device_key: DeviceKeyFfi::default(),
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostBeginAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_begin_test_encrypt_sec_message_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_begin_test_encrypt_sec_message_fail start");

    mock_set_misc_manager();

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    mock_crypto_engine
        .expect_generate_x25519_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Ok(Vec::new()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_encrypt()
        .returning(|_, _| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let fwk_message = create_valid_fwk_enroll_message(1, AuthTrustLevel::Atl2 as i32);
    let sec_message = create_valid_key_nego_reply(0);

    let begin_input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi::default(),
        companion_device_key: DeviceKeyFfi::default(),
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostBeginAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_end_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_wrong_input_type start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let wrong_input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi::default(),
        companion_device_key: DeviceKeyFfi::default(),
        fwk_message: DataArray1024Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::default(),
    };

    let mut output = HostBeginAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollBegin(&wrong_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn host_enroll_request_end_test_sec_message_decode_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_sec_message_decode_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.key_negotial_param.push(create_key_negotial_param());

    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_end_test_hkdf_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_hkdf_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.key_negotial_param.push(create_key_negotial_param());

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        PROTOCOL_VERSION,
        SUPPORT_CAPABILITY,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_end_test_decrypt_sec_message_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_decrypt_sec_message_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.key_negotial_param.push(create_key_negotial_param());

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        PROTOCOL_VERSION,
        SUPPORT_CAPABILITY,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_end_test_device_id_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_device_id_mismatch start");

    mock_set_crypto_engine();

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());

    let sec_message = create_valid_binding_reply(
        "wrong_device",
        100,
        PROTOCOL_VERSION,
        SUPPORT_CAPABILITY,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_end_test_user_id_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_user_id_mismatch start");

    mock_set_crypto_engine();

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());

    let sec_message = create_valid_binding_reply(
        "companion_device",
        -1,
        PROTOCOL_VERSION,
        SUPPORT_CAPABILITY,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_end_test_protocol_list_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_protocol_list_mismatch start");

    mock_set_crypto_engine();

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        &[],
        SUPPORT_CAPABILITY,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_end_test_capability_list_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_capability_list_mismatch start");

    mock_set_crypto_engine();

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());

    let sec_message =
        create_valid_binding_reply("companion_device", 100, PROTOCOL_VERSION, &[], ExecutorSecurityLevel::Esl2 as i32);
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_end_test_secure_random_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_secure_random_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());

    mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_secure_random()
        .returning(|_buf| Err(ErrorCode::GeneralError));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        PROTOCOL_VERSION,
        SUPPORT_CAPABILITY,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_end_test_get_rtc_time_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_get_rtc_time_fail start");

    mock_set_crypto_engine();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_generate_unique_template_id().returning(|| Ok(123));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper
        .expect_get_rtc_time()
        .returning(|| Err(ErrorCode::GeneralError));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.acl = AuthCapabilityLevel::Acl0;

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        PROTOCOL_VERSION,
        SUPPORT_CAPABILITY,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_end_test_add_device_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_add_device_fail start");

    mock_set_crypto_engine();
    mock_set_time_keeper();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_generate_unique_template_id().returning(|| Ok(123));
    mock_host_db_manager
        .expect_add_device()
        .returning(|| Err(ErrorCode::GeneralError));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.acl = AuthCapabilityLevel::Acl2;

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        PROTOCOL_VERSION,
        SUPPORT_CAPABILITY,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_end_test_add_token_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_add_token_fail start");

    mock_set_crypto_engine();
    mock_set_time_keeper();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_generate_unique_template_id().returning(|| Ok(123));
    mock_host_db_manager.expect_add_device().returning(|| Ok(()));
    mock_host_db_manager
        .expect_add_token()
        .returning(|| Err(ErrorCode::GeneralError));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.acl = AuthCapabilityLevel::Acl2;

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        PROTOCOL_VERSION,
        SUPPORT_CAPABILITY,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_end_test_fwk_message_encode_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_fwk_message_encode_fail start");

    mock_set_crypto_engine();
    mock_set_time_keeper();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_generate_unique_template_id().returning(|| Ok(123));
    mock_host_db_manager.expect_add_device().returning(|| Ok(()));
    mock_host_db_manager.expect_add_token().returning(|| Ok(()));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager
        .expect_get_local_key_pair()
        .returning(|| Err(ErrorCode::GeneralError));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.acl = AuthCapabilityLevel::Acl2;

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        PROTOCOL_VERSION,
        SUPPORT_CAPABILITY,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_end_test_get_session_key_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_get_session_key_fail start");

    mock_set_crypto_engine();
    mock_set_time_keeper();
    mock_set_misc_manager();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_generate_unique_template_id().returning(|| Ok(123));
    mock_host_db_manager.expect_add_device().returning(|| Ok(()));
    mock_host_db_manager.expect_add_token().returning(|| Ok(()));
    mock_host_db_manager
        .expect_read_device_sk()
        .returning(|| Err(ErrorCode::NotFound));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.acl = AuthCapabilityLevel::Acl2;

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        PROTOCOL_VERSION,
        SUPPORT_CAPABILITY,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn host_enroll_request_end_test_encrypt_issue_token_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_encrypt_issue_token_fail start");

    mock_set_time_keeper();
    mock_set_misc_manager();

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine
        .expect_aes_gcm_encrypt()
        .returning(|_, _| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_generate_unique_template_id().returning(|| Ok(123));
    mock_host_db_manager.expect_add_device().returning(|| Ok(()));
    mock_host_db_manager.expect_add_token().returning(|| Ok(()));
    mock_host_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceSk { device_type: DeviceType::None, sk: Vec::new() }]));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.acl = AuthCapabilityLevel::Acl2;

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        PROTOCOL_VERSION,
        SUPPORT_CAPABILITY,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}
