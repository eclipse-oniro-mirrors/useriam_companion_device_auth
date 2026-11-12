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
const FILE_ID: u16 = TestFileId::HostEnrollTest as u16;

// Values higher-version peers may advertise; this host either ignores or must reject them.
const HIGHER_PROTOCOL_VERSION: u16 = 2;
const UNOFFERED_ALGORITHM: u16 = 2;

use crate::common::constants::*;

const PROTOCOL_VERSION_1: u16 = 1;
const ALL_CAPABILITIES: &[u16] =
    &[Capability::DelegateAuth as u16, Capability::TokenAuth as u16, Capability::ObtainToken as u16];
use crate::entry::companion_device_auth_ffi::{
    DataArray1024Ffi, DataArray20000Ffi, DeviceKeyFfi, HostBeginAddCompanionInputFfi, HostBeginAddCompanionOutputFfi,
    HostEndAddCompanionInputFfi, HostEndAddCompanionOutputFfi, HostGetInitKeyNegotiationInputFfi,
    HostGetInitKeyNegotiationOutputFfi, Int32Array64Ffi, PersistedCompanionStatusFfi, Uint16Array64Ffi,
};
use crate::jobs::companion_device_db_helper;
use crate::log_i;
use crate::request::enroll::enroll_message::{SecBindingReply, SecBindingReplyInfo, SecKeyNegoReply};
use crate::request::enroll::host_enroll::{HostDeviceEnrollRequest, KeyNegotialParam};
use crate::traits::companion_device_db_manager::{CompanionDeviceDbManagerRegistry, MockCompanionDeviceDbManager};
use crate::traits::crypto_engine::{AesGcmResult, CryptoEngineRegistry, KeyPair, MockCryptoEngine};
use crate::common::algorithm::SelectedAlgorithms;
use crate::traits::db_manager::{CompanionDevice, CompanionDeviceKeyMaterial, DeviceKey, UserInfo, UserKey};
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
    let reply = SecKeyNegoReply {
        selected_algorithms: SelectedAlgorithms {
            ka_algorithm: KaAlgoType::X25519 as u16,
            kdf_algorithm: 1,
            aead_algorithm: 1,
            mac_algorithm: 1,
        },
        challenge,
        pub_key: vec![1u8, 2, 3, 4, 5],
    };
    reply.encode(ProcessorType::Default).unwrap()
}

fn create_binding_reply_with_selected_algorithms(
    device_id: &str,
    user_id: i32,
    protocol: &[u16],
    capability: &[u16],
    esl: i32,
    selected_algorithms: SelectedAlgorithms,
) -> Vec<u8> {
    create_binding_reply_with_companion_algorithms(
        device_id,
        user_id,
        protocol,
        capability,
        esl,
        selected_algorithms,
        crate::common::algorithm::get_supported_algorithms(),
    )
}

fn create_binding_reply_with_companion_algorithms(
    device_id: &str,
    user_id: i32,
    protocol: &[u16],
    capability: &[u16],
    esl: i32,
    selected_algorithms: SelectedAlgorithms,
    companion_supported_algorithms: crate::common::algorithm::CryptoAlgorithms,
) -> Vec<u8> {
    let reply_info = SecBindingReplyInfo {
        device_id: device_id.to_string(),
        user_key: UserKey { user_id, sub_profile_id: 0 },
        esl,
        track_ability_level: 0,
        challenge: 0,
        protocol_list: protocol.to_vec(),
        capability_list: capability.to_vec(),
        selected_algorithms,
        companion_supported_algorithms,
    };

    let encrypt_data = reply_info.encode().unwrap();
    let reply =
        SecBindingReply { challenge: 0, tag: [2u8; AES_GCM_TAG_SIZE], iv: [3u8; AES_GCM_IV_SIZE], encrypt_data };
    reply.encode(ProcessorType::Default).unwrap()
}

// Selected algorithms must equal the selection recomputed from the negotiated
// sections, i.e. the first entry of each supported list (the v1 algorithm set).
fn create_valid_binding_reply(
    device_id: &str,
    user_id: i32,
    protocol: &[u16],
    capability: &[u16],
    esl: i32,
) -> Vec<u8> {
    create_binding_reply_with_selected_algorithms(
        device_id,
        user_id,
        protocol,
        capability,
        esl,
        SelectedAlgorithms {
            ka_algorithm: KaAlgoType::X25519 as u16,
            kdf_algorithm: KdfAlgoType::HkdfSha256 as u16,
            aead_algorithm: AeadAlgoType::Aes256Gcm as u16,
            mac_algorithm: MacAlgoType::HmacSha256 as u16,
        },
    )
}

// Malformed reply: the binding reply carries no capability attribute at all.
fn create_binding_reply_without_capability(device_id: &str, user_id: i32, protocol: &[u16], esl: i32) -> Vec<u8> {
    let mut attribute = Attribute::new();
    attribute.set_string(AttributeKey::AttrDeviceId, device_id.to_string());
    attribute.set_i32(AttributeKey::AttrUserId, user_id);
    attribute.set_i32(AttributeKey::AttrSubProfileId, 0);
    attribute.set_i32(AttributeKey::AttrEsl, esl);
    attribute.set_i32(AttributeKey::AttrTrackAbilityLevel, 0);
    attribute.set_u64(AttributeKey::AttrHostChallenge, 0);
    attribute.set_u16_slice(AttributeKey::AttrProtocolList, protocol);

    let encrypt_data = attribute.to_bytes().unwrap();
    let reply =
        SecBindingReply { challenge: 0, tag: [2u8; AES_GCM_TAG_SIZE], iv: [3u8; AES_GCM_IV_SIZE], encrypt_data };
    reply.encode(ProcessorType::Default).unwrap()
}

fn create_key_negotial_param() -> KeyNegotialParam {
    KeyNegotialParam {
        processor_type: ProcessorType::Default,
        selected_algorithms: SelectedAlgorithms {
            ka_algorithm: KaAlgoType::X25519 as u16,
            kdf_algorithm: 1,
            aead_algorithm: 1,
            mac_algorithm: 1,
        },
        companion_challenge: 0,
        key_pair: Some(create_mock_key_pair()),
        sk: vec![1u8; 32],
    }
}

// Host protocol list (priority-ordered) announced inside the encrypted binding
// request; begin() rejects an empty list.
fn create_host_protocol_list_ffi() -> Uint16Array64Ffi {
    let mut list = Uint16Array64Ffi::default();
    list.data[0] = PROTOCOL_VERSION_1;
    list.len = 1;
    list
}

fn create_device_key(device_id: &str, user_id: i32) -> DeviceKey {
    DeviceKey { device_id: device_id.to_string(), device_id_type: 1, user_id, sub_profile_id: 0 }
}

fn mock_set_crypto_engine() {
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_decrypt().returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
}

fn mock_set_time_keeper() {
    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Ok(1000));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));
}

fn mock_set_misc_manager() {
    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_get_fwk_pub_key().returning(|| Ok(create_mock_key_pair().pub_key.clone()));
    mock_misc_manager.expect_get_local_key_pair().returning(|| Ok(create_mock_key_pair()));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));
}

fn mock_enrolled_device() -> CompanionDevice {
    CompanionDevice {
        template_id: 123,
        device_key: DeviceKey::default(),
        user_info: UserInfo { user_key: UserKey::default(), user_type: 0 },
        added_time: 0,
        is_valid: true,
        capability_list: vec![1, 2, 3],
        protocol_id: 1,
        secure_protocol_id: 0,
    }
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
    assert_eq!(result, Err(ErrorCode::SecureProtocolNotSupported));
}

#[test]
fn host_enroll_request_begin_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_begin_test_wrong_input_type start");

    mock_set_misc_manager();

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    mock_crypto_engine.expect_generate_x25519_key_pair().returning(|| Ok(create_mock_key_pair()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Ok([0u8; SHARE_KEY_LEN].to_vec()));
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
        host_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        companion_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
        secure_protocol_id: 1,
        host_capability_list: Uint16Array64Ffi::default(),
        host_protocol_list: create_host_protocol_list_ffi(),
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
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let fwk_message = create_valid_fwk_enroll_message(2, AuthTrustLevel::Atl2 as i32);
    let begin_input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        companion_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
        secure_protocol_id: 1,
        host_capability_list: Uint16Array64Ffi::default(),
        host_protocol_list: create_host_protocol_list_ffi(),
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
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let fwk_message = create_valid_fwk_enroll_message(1, 99999);
    let begin_input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        companion_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
        secure_protocol_id: 1,
        host_capability_list: Uint16Array64Ffi::default(),
        host_protocol_list: create_host_protocol_list_ffi(),
        sec_message: DataArray20000Ffi::default(),
    };

    let mut output = HostBeginAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_begin_test_capability_value_not_support() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_begin_test_capability_value_not_support start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    // Boundary check: a host capability value outside the Capability enum fails the
    // FFI-boundary validation before the fwk message is even decoded.
    let mut host_capability_list = Uint16Array64Ffi::default();
    host_capability_list.data[0] = 99;
    host_capability_list.len = 1;
    let begin_input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        companion_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        fwk_message: DataArray1024Ffi::default(),
        secure_protocol_id: 1,
        host_capability_list,
        host_protocol_list: create_host_protocol_list_ffi(),
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
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 100 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let fwk_message = create_valid_fwk_enroll_message(1, AuthTrustLevel::Atl2 as i32);
    let begin_input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        companion_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
        secure_protocol_id: 1,
        host_capability_list: Uint16Array64Ffi::default(),
        host_protocol_list: create_host_protocol_list_ffi(),
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
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 0 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let fwk_message = create_valid_fwk_enroll_message(1, AuthTrustLevel::Atl2 as i32);
    let begin_input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        companion_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
        secure_protocol_id: 1,
        host_capability_list: Uint16Array64Ffi::default(),
        host_protocol_list: create_host_protocol_list_ffi(),
        sec_message: DataArray20000Ffi::default(),
    };

    let mut output = HostBeginAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::SecureProtocolNotSupported));
}

#[test]
fn host_enroll_request_begin_test_sec_message_decode_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_begin_test_sec_message_decode_fail start");

    mock_set_misc_manager();

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let fwk_message = create_valid_fwk_enroll_message(1, AuthTrustLevel::Atl2 as i32);
    let begin_input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        companion_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
        secure_protocol_id: 1,
        host_capability_list: Uint16Array64Ffi::default(),
        host_protocol_list: create_host_protocol_list_ffi(),
        sec_message: DataArray20000Ffi::default(),
    };

    let mut output = HostBeginAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn host_enroll_request_begin_test_generate_key_pair_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_begin_test_generate_key_pair_fail start");

    mock_set_misc_manager();

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    mock_crypto_engine.expect_generate_x25519_key_pair().returning(|| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let fwk_message = create_valid_fwk_enroll_message(1, AuthTrustLevel::Atl2 as i32);
    let sec_message = create_valid_key_nego_reply(0);

    let begin_input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        companion_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
        secure_protocol_id: 1,
        host_capability_list: Uint16Array64Ffi::default(),
        host_protocol_list: create_host_protocol_list_ffi(),
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
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    mock_crypto_engine.expect_generate_x25519_key_pair().returning(|| Ok(create_mock_key_pair()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let fwk_message = create_valid_fwk_enroll_message(1, AuthTrustLevel::Atl2 as i32);
    let sec_message = create_valid_key_nego_reply(0);

    let begin_input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        companion_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
        secure_protocol_id: 1,
        host_capability_list: Uint16Array64Ffi::default(),
        host_protocol_list: create_host_protocol_list_ffi(),
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
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    mock_crypto_engine.expect_generate_x25519_key_pair().returning(|| Ok(create_mock_key_pair()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Ok([0u8; SHARE_KEY_LEN].to_vec()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let fwk_message = create_valid_fwk_enroll_message(1, AuthTrustLevel::Atl2 as i32);
    let sec_message = create_valid_key_nego_reply(0);

    let begin_input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        companion_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
        secure_protocol_id: 1,
        host_capability_list: Uint16Array64Ffi::default(),
        host_protocol_list: create_host_protocol_list_ffi(),
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
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    mock_crypto_engine.expect_generate_x25519_key_pair().returning(|| Ok(create_mock_key_pair()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Ok([0u8; SHARE_KEY_LEN].to_vec()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|_, _| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let fwk_message = create_valid_fwk_enroll_message(1, AuthTrustLevel::Atl2 as i32);
    let sec_message = create_valid_key_nego_reply(0);

    let begin_input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        companion_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
        secure_protocol_id: 1,
        host_capability_list: Uint16Array64Ffi::default(),
        host_protocol_list: create_host_protocol_list_ffi(),
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
        host_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        companion_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        fwk_message: DataArray1024Ffi::default(),
        secure_protocol_id: 1,
        host_capability_list: Uint16Array64Ffi::default(),
        host_protocol_list: create_host_protocol_list_ffi(),
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
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];

    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
        sec_message: DataArray1024Ffi::default(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
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
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        &[PROTOCOL_VERSION_1],
        ALL_CAPABILITIES,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
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
    mock_crypto_engine.expect_aes_gcm_decrypt().returning(|_| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.key_negotial_param.push(create_key_negotial_param());
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        &[PROTOCOL_VERSION_1],
        ALL_CAPABILITIES,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
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
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];

    let sec_message = create_valid_binding_reply(
        "wrong_device",
        100,
        &[PROTOCOL_VERSION_1],
        ALL_CAPABILITIES,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
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
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];

    let sec_message = create_valid_binding_reply(
        "companion_device",
        -1,
        &[PROTOCOL_VERSION_1],
        ALL_CAPABILITIES,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
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
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        &[2u16],
        ALL_CAPABILITIES,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::ProtocolNegotiationFailed));
}

// The reply covers the pinned selection, yet a higher-priority protocol in the
// companion set wins the recompute: the pinned selection diverges from the
// encrypted-announced offer, i.e. C++/TA preference drift. The old membership
// check accepted this; the unified-exchange recompute must reject it with 20011.
#[test]
fn host_enroll_request_end_test_protocol_recompute_divergence_rejected() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_protocol_recompute_divergence_rejected start");

    mock_set_crypto_engine();

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];
    // Host priority order prefers protocol 2; the pinned selection is protocol 1.
    request.host_protocol_list = vec![2u16, PROTOCOL_VERSION_1];

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        &[2u16, PROTOCOL_VERSION_1],
        ALL_CAPABILITIES,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::ProtocolNegotiationFailed));
}

// A tampered selected-algorithms echo (not matching the plaintext key nego reply) fails with 20015.
#[test]
fn host_enroll_request_end_test_selected_algorithms_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_selected_algorithms_mismatch start");

    mock_set_crypto_engine();

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];

    let sec_message = create_binding_reply_with_selected_algorithms(
        "companion_device",
        100,
        &[PROTOCOL_VERSION_1],
        ALL_CAPABILITIES,
        ExecutorSecurityLevel::Esl2 as i32,
        SelectedAlgorithms {
            ka_algorithm: UNOFFERED_ALGORITHM,
            kdf_algorithm: KdfAlgoType::HkdfSha256 as u16,
            aead_algorithm: AeadAlgoType::Aes256Gcm as u16,
            mac_algorithm: MacAlgoType::HmacSha256 as u16,
        },
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::AlgorithmNegotiationFailed));
}

// The recompute candidate set is host ∩ companion: an announced set with no overlap fails with 20015.
#[test]
fn host_enroll_request_end_test_companion_support_set_without_intersection_rejected() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_companion_support_set_without_intersection_rejected start");

    mock_set_crypto_engine();

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];

    let sec_message = create_binding_reply_with_companion_algorithms(
        "companion_device",
        100,
        &[PROTOCOL_VERSION_1],
        ALL_CAPABILITIES,
        ExecutorSecurityLevel::Esl2 as i32,
        SelectedAlgorithms {
            ka_algorithm: KaAlgoType::X25519 as u16,
            kdf_algorithm: KdfAlgoType::HkdfSha256 as u16,
            aead_algorithm: AeadAlgoType::Aes256Gcm as u16,
            mac_algorithm: MacAlgoType::HmacSha256 as u16,
        },
        crate::common::algorithm::CryptoAlgorithms {
            ka_algorithms: vec![UNOFFERED_ALGORITHM],
            kdf_algorithms: vec![KdfAlgoType::HkdfSha256 as u16],
            aead_algorithms: vec![AeadAlgoType::Aes256Gcm as u16],
            mac_algorithms: vec![MacAlgoType::HmacSha256 as u16],
        },
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::AlgorithmNegotiationFailed));
}

// The companion announces its local set as-is; values beyond the host offer are cut by the
// host-side convergence, the round succeeds and the pin is the intersection.
#[test]
fn host_enroll_request_end_test_capability_beyond_offer_clamped() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_capability_beyond_offer_clamped start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
    mock_set_misc_manager();
    mock_set_time_keeper();

    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager.expect_generate_unique_template_id().returning(|| Ok(123));
    mock_companion_device_db_manager.expect_add_device().returning(|| Ok(()));
    mock_companion_device_db_manager.expect_add_token().returning(|| Ok(()));
    mock_companion_device_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceKeyMaterial {
            processor_type: ProcessorType::Default,
            sk: [0u8; SHARE_KEY_LEN],
            selected_algorithms: SelectedAlgorithms {
                ka_algorithm: 1,
                kdf_algorithm: 1,
                aead_algorithm: 1,
                mac_algorithm: 1,
            },
        }]));
    let added_devices = mock_companion_device_db_manager.added_devices();
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];
    request.acl = AuthCapabilityLevel::Acl2;

    // TokenAuth is covered by the offer, Invalid is not: the pin keeps only TokenAuth.
    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        &[PROTOCOL_VERSION_1],
        &[Capability::TokenAuth as u16, Capability::Invalid as u16],
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Ok(()));
    assert_eq!(added_devices.borrow().len(), 1);
    assert_eq!(added_devices.borrow()[0].capability_list, vec![Capability::TokenAuth as u16]);
    assert_eq!(output.capability_list.data[..output.capability_list.len as usize], [Capability::TokenAuth as u16][..]);
}

#[test]
fn host_enroll_request_end_test_unsupported_selected_protocol() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_unsupported_selected_protocol start");

    mock_set_crypto_engine();

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        &[],
        ALL_CAPABILITIES,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi { enrolled_protocol_id: 0, ..Default::default() },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::SecureProtocolNotSupported));
}

// §5.2 invariant 4: an empty intersection is a legal result — the binding completes and
// an empty list is persisted ("no usable capability"), it never fails the round.
#[test]
fn host_enroll_request_end_test_empty_capability_list() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_empty_capability_list start");

    // Full-success end path: key nego reply decrypt + token issue encrypt + fwk reply sign.
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
    mock_set_misc_manager();
    mock_set_time_keeper();

    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager.expect_generate_unique_template_id().returning(|| Ok(123));
    mock_companion_device_db_manager.expect_add_device().returning(|| Ok(()));
    mock_companion_device_db_manager.expect_add_token().returning(|| Ok(()));
    mock_companion_device_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceKeyMaterial {
            processor_type: ProcessorType::Default,
            sk: [0u8; SHARE_KEY_LEN],
            selected_algorithms: SelectedAlgorithms {
                ka_algorithm: 1,
                kdf_algorithm: 1,
                aead_algorithm: 1,
                mac_algorithm: 1,
            },
        }]));
    let added_devices = mock_companion_device_db_manager.added_devices();
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];
    request.acl = AuthCapabilityLevel::Acl2;

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        &[PROTOCOL_VERSION_1],
        &[],
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Ok(()));
    // Empty intersection is persisted as an empty pin and returned for the Companion image.
    assert_eq!(added_devices.borrow().len(), 1);
    assert!(added_devices.borrow()[0].capability_list.is_empty());
    assert_eq!(output.capability_list.len, 0);
}

// A proper subset (order-insensitive, duplicates ignored) passes and the persisted value
// is the canonicalized intersection.
#[test]
fn host_enroll_request_end_test_capability_strict_subset_passes() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_capability_strict_subset_passes start");

    // Full-success end path: key nego reply decrypt + token issue encrypt + fwk reply sign.
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
    mock_set_misc_manager();
    mock_set_time_keeper();

    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager.expect_generate_unique_template_id().returning(|| Ok(123));
    mock_companion_device_db_manager.expect_add_device().returning(|| Ok(()));
    mock_companion_device_db_manager.expect_add_token().returning(|| Ok(()));
    mock_companion_device_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceKeyMaterial {
            processor_type: ProcessorType::Default,
            sk: [0u8; SHARE_KEY_LEN],
            selected_algorithms: SelectedAlgorithms {
                ka_algorithm: 1,
                kdf_algorithm: 1,
                aead_algorithm: 1,
                mac_algorithm: 1,
            },
        }]));
    let added_devices = mock_companion_device_db_manager.added_devices();
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];
    request.acl = AuthCapabilityLevel::Acl2;

    // Unordered subset of the offer with a duplicate entry.
    let negotiated = [Capability::TokenAuth as u16, Capability::DelegateAuth as u16,
        Capability::TokenAuth as u16];
    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        &[PROTOCOL_VERSION_1],
        &negotiated,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Ok(()));
    // Canonicalized intersection: sorted, deduplicated; persisted and returned in lockstep.
    assert_eq!(added_devices.borrow().len(), 1);
    assert_eq!(added_devices.borrow()[0].capability_list,
        vec![Capability::DelegateAuth as u16, Capability::TokenAuth as u16]);
    assert_eq!(
        output.capability_list.data[..output.capability_list.len as usize],
        [Capability::DelegateAuth as u16, Capability::TokenAuth as u16][..]
    );
}

// The capability attribute is mandatory: a reply without it fails to decode.
#[test]
fn host_enroll_request_end_test_capability_absent_fails() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_capability_absent_fails start");

    mock_set_crypto_engine();
    mock_set_misc_manager();
    mock_set_time_keeper();

    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager.expect_generate_unique_template_id().returning(|| Ok(123));
    mock_companion_device_db_manager.expect_add_device().returning(|| Ok(()));
    mock_companion_device_db_manager.expect_add_token().returning(|| Ok(()));
    mock_companion_device_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceKeyMaterial {
            processor_type: ProcessorType::Default,
            sk: [0u8; SHARE_KEY_LEN],
            selected_algorithms: SelectedAlgorithms {
                ka_algorithm: 1,
                kdf_algorithm: 1,
                aead_algorithm: 1,
                mac_algorithm: 1,
            },
        }]));
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];
    request.acl = AuthCapabilityLevel::Acl2;

    let sec_message =
        create_binding_reply_without_capability("companion_device", 100, &[PROTOCOL_VERSION_1],
            ExecutorSecurityLevel::Esl2 as i32);
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

// Replies across processor types must agree on the negotiated capability set. Only
// ProcessorType::Default exists today, so the "earlier processor already negotiated"
// state is seeded directly, exactly like the legacy divergence test did.
#[test]
fn host_enroll_request_end_test_capability_diverges_across_processor_types() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_capability_diverges_across_processor_types start");

    mock_set_crypto_engine();

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];
    // Simulate what an earlier processor type already negotiated.
    request.negotiated_capability_list = Some(vec![Capability::DelegateAuth as u16]);

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        &[PROTOCOL_VERSION_1],
        &[Capability::TokenAuth as u16],
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::CapabilityNegotiationFailed));
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
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];

    mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Err(ErrorCode::GeneralError));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_decrypt().returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        &[PROTOCOL_VERSION_1],
        ALL_CAPABILITIES,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
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

    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager.expect_generate_unique_template_id().returning(|| Ok(123));
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Err(ErrorCode::GeneralError));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];
    request.acl = AuthCapabilityLevel::Acl0;

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        &[PROTOCOL_VERSION_1],
        ALL_CAPABILITIES,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
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

    // Full-success end path: key nego reply decrypt + token issue encrypt + fwk reply sign.
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
    mock_set_misc_manager();
    mock_set_time_keeper();

    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager.expect_generate_unique_template_id().returning(|| Ok(123));
    mock_companion_device_db_manager.expect_add_device().returning(|| Err(ErrorCode::GeneralError));
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];
    request.acl = AuthCapabilityLevel::Acl2;

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        &[PROTOCOL_VERSION_1],
        ALL_CAPABILITIES,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
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

    // Full-success end path: key nego reply decrypt + token issue encrypt + fwk reply sign.
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
    mock_set_misc_manager();
    mock_set_time_keeper();

    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager.expect_generate_unique_template_id().returning(|| Ok(123));
    mock_companion_device_db_manager.expect_add_device().returning(|| Ok(()));
    mock_companion_device_db_manager.expect_add_token().returning(|| Err(ErrorCode::GeneralError));
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];
    request.acl = AuthCapabilityLevel::Acl2;

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        &[PROTOCOL_VERSION_1],
        ALL_CAPABILITIES,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
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

    // Full-success end path: key nego reply decrypt + token issue encrypt + fwk reply sign.
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
    mock_set_misc_manager();
    mock_set_time_keeper();

    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager.expect_generate_unique_template_id().returning(|| Ok(123));
    mock_companion_device_db_manager.expect_add_device().returning(|| Ok(()));
    mock_companion_device_db_manager.expect_add_token().returning(|| Ok(()));
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_get_local_key_pair().returning(|| Err(ErrorCode::GeneralError));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];
    request.acl = AuthCapabilityLevel::Acl2;

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        &[PROTOCOL_VERSION_1],
        ALL_CAPABILITIES,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
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

    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager.expect_get_device().returning(|| Ok(mock_enrolled_device()));
    mock_companion_device_db_manager.expect_generate_unique_template_id().returning(|| Ok(123));
    mock_companion_device_db_manager.expect_add_device().returning(|| Ok(()));
    mock_companion_device_db_manager.expect_add_token().returning(|| Ok(()));
    mock_companion_device_db_manager.expect_read_device_sk().returning(|| Err(ErrorCode::NotFound));
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];
    request.acl = AuthCapabilityLevel::Acl2;

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        &[PROTOCOL_VERSION_1],
        ALL_CAPABILITIES,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
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
    mock_crypto_engine.expect_aes_gcm_decrypt().returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|_, _| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    mock_companion_device_db_manager.expect_get_device().returning(|| Ok(mock_enrolled_device()));
    mock_companion_device_db_manager.expect_generate_unique_template_id().returning(|| Ok(123));
    mock_companion_device_db_manager.expect_add_device().returning(|| Ok(()));
    mock_companion_device_db_manager.expect_add_token().returning(|| Ok(()));
    mock_companion_device_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceKeyMaterial {
            processor_type: ProcessorType::Default,
            sk: [0u8; SHARE_KEY_LEN],
            selected_algorithms: SelectedAlgorithms {
                ka_algorithm: 1,
                kdf_algorithm: 1,
                aead_algorithm: 1,
                mac_algorithm: 1,
            },
        }]));
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];
    request.acl = AuthCapabilityLevel::Acl2;

    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        &[PROTOCOL_VERSION_1],
        ALL_CAPABILITIES,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_enroll_request_end_test_higher_version_companion_accepted() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_higher_version_companion_accepted start");

    mock_set_crypto_engine();
    mock_set_time_keeper();

    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    // A distinctive error code proves the flow got past list verification and reached template-id
    // generation; if verification rejected the higher-version lists, end() would return
    // GeneralError before touching the database.
    mock_companion_device_db_manager
        .expect_generate_unique_template_id()
        .returning(|| Err(ErrorCode::NotFound));
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];
    request.acl = AuthCapabilityLevel::Acl2;

    // The companion advertises a newer protocol version on top of the one this host
    // negotiated; the protocol check only requires the selected version, so it is
    // accepted. The capability pin is the announced set intersected with our own offer —
    // values beyond the offer are cut (see the beyond-offer test).
    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        &[PROTOCOL_VERSION_1, HIGHER_PROTOCOL_VERSION],
        ALL_CAPABILITIES,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    // NotFound is the distinctive probe from generate_unique_template_id: reaching it proves the
    // higher-version lists passed verification.
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn host_enroll_request_end_test_capability_echo_subset_persists_intersection() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_capability_echo_subset_persists_intersection start");

    const TEMPLATE_ID: u64 = 123;
    const COMPANION_USER_ID: i32 = 100;

    mock_set_time_keeper();
    mock_set_misc_manager();

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_decrypt().returning(|result| Ok(result.ciphertext.clone()));
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine
        .expect_aes_gcm_encrypt()
        .returning(|bytes, _| Ok(AesGcmResult::new(bytes.to_vec(), [0u8; AES_GCM_TAG_SIZE])));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_companion_device_db_manager = MockCompanionDeviceDbManager::new();
    let added_devices = mock_companion_device_db_manager.added_devices();
    let devices_for_read = added_devices.clone();
    mock_companion_device_db_manager
        .expect_generate_unique_template_id()
        .returning(|| Ok(TEMPLATE_ID));
    mock_companion_device_db_manager.expect_add_device().returning(|| Ok(()));
    mock_companion_device_db_manager.expect_add_token().returning(|| Ok(()));
    mock_companion_device_db_manager
        .expect_get_device()
        .returning(move || devices_for_read.borrow().last().cloned().ok_or(ErrorCode::NotFound));
    mock_companion_device_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceKeyMaterial {
            processor_type: ProcessorType::Default,
            sk: [0u8; SHARE_KEY_LEN],
            selected_algorithms: SelectedAlgorithms {
                ka_algorithm: 1,
                kdf_algorithm: 1,
                aead_algorithm: 1,
                mac_algorithm: 1,
            },
        }]));
    CompanionDeviceDbManagerRegistry::set(Box::new(mock_companion_device_db_manager));

    let input = HostGetInitKeyNegotiationInputFfi {
        request_id: 1,
        secure_protocol_id: SecureProtocolId::Default as u16,
    };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", COMPANION_USER_ID);
    request.key_negotial_param.push(create_key_negotial_param());
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];
    request.acl = AuthCapabilityLevel::Acl2;

    // Discovery offered all capabilities, but the authenticated reply grants only token auth.
    let sec_message = create_valid_binding_reply(
        "companion_device",
        COMPANION_USER_ID,
        &[PROTOCOL_VERSION_1],
        &[Capability::TokenAuth as u16],
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: SecureProtocolId::Default as u16,
        supported_business_ids: Int32Array64Ffi::default(),
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Ok(()));
    assert_eq!(added_devices.borrow().len(), 1);
    let persisted_device = added_devices.borrow()[0].clone();
    assert_eq!(persisted_device.template_id, TEMPLATE_ID);
    assert_eq!(output.template_id, TEMPLATE_ID);
    assert!(!output.fwk_message.as_slice().unwrap().is_empty());
    assert!(!output.sec_message.as_slice().unwrap().is_empty());

    // Authorization must use the written row even after the enrollment request is gone.
    drop(request);
    let mut reloaded_db_manager = MockCompanionDeviceDbManager::new();
    reloaded_db_manager.expect_get_device().returning(move || Ok(persisted_device.clone()));
    CompanionDeviceDbManagerRegistry::set(Box::new(reloaded_db_manager));
}

#[test]
fn host_enroll_request_begin_test_selected_algorithm_not_offered() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_begin_test_selected_algorithm_not_offered start");

    mock_set_misc_manager();

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();

    let fwk_message = create_valid_fwk_enroll_message(1, AuthTrustLevel::Atl2 as i32);
    let reply = SecKeyNegoReply {
        selected_algorithms: SelectedAlgorithms {
            ka_algorithm: UNOFFERED_ALGORITHM,
            kdf_algorithm: 1,
            aead_algorithm: 1,
            mac_algorithm: 1,
        },
        challenge: 0,
        pub_key: vec![1u8, 2, 3, 4, 5],
    };
    let sec_message = reply.encode(ProcessorType::Default).unwrap();
    let begin_input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        companion_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
        secure_protocol_id: 1,
        host_capability_list: Uint16Array64Ffi::default(),
        host_protocol_list: create_host_protocol_list_ffi(),
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostBeginAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::AlgorithmNegotiationFailed));
}

#[test]
fn host_enroll_request_end_test_empty_reply_protocol_list_rejected() {
    let _guard = ut_registry_guard!();
    log_i!("host_enroll_request_end_test_empty_reply_protocol_list_rejected start");

    mock_set_crypto_engine();

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };

    let mut request = HostDeviceEnrollRequest::new(&input).unwrap();
    request.enroll_param.companion_device_key = create_device_key("companion_device", 100);
    request.key_negotial_param.push(create_key_negotial_param());
    request.host_capability_list = ALL_CAPABILITIES.to_vec();
    request.host_protocol_list = vec![PROTOCOL_VERSION_1];

    // A higher-version or degenerate companion replying with no protocol at all must be rejected;
    // the host's expected list can never be covered by an empty offer.
    let sec_message = create_valid_binding_reply(
        "companion_device",
        100,
        &[],
        ALL_CAPABILITIES,
        ExecutorSecurityLevel::Esl2 as i32,
    );
    let end_input = HostEndAddCompanionInputFfi {
        request_id: 1,
        companion_status: PersistedCompanionStatusFfi {
            enrolled_protocol_id: PROTOCOL_VERSION_1,
            ..Default::default()
        },
        secure_protocol_id: 1,
        supported_business_ids: Int32Array64Ffi::default(),
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndAddCompanionOutputFfi::default();
    let param = RequestParam::HostEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::ProtocolNegotiationFailed));
}
