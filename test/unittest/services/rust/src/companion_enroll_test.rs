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
const FILE_ID: u16 = TestFileId::CompanionEnrollTest as u16;

use crate::common::constants::*;

const PROTOCOL_VERSION_1: u16 = 1;
use crate::entry::companion_device_auth_ffi::{
    CompanionBeginAddHostBindingInputFfi, CompanionEndAddHostBindingInputFfi, CompanionInitKeyNegotiationInputFfi,
    DataArray1024Ffi, DataArray20000Ffi, DeviceKeyFfi, Uint16Array64Ffi,
};
use crate::log_i;
use crate::request::enroll::companion_enroll::CompanionDeviceEnrollRequest;
use crate::request::enroll::enroll_message::{SecBindingReply, SecBindingRequest, SecKeyNegoRequest};
use crate::common::algorithm::CryptoAlgorithms;
use crate::request::jobs::common_message::SecIssueToken;
use crate::traits::crypto_engine::{AesGcmResult, CryptoEngineRegistry, KeyPair, MockCryptoEngine};
use crate::traits::db_manager::{DeviceKey, HostBinding, UserInfo, UserKey};
use crate::traits::host_binding_db_manager::{HostBindingDbManagerRegistry, MockHostBindingDbManager};
use crate::traits::request_manager::{Request, RequestParam};
use crate::traits::time_keeper::{MockTimeKeeper, TimeKeeperRegistry};
use crate::ut_registry_guard;
use crate::utils::{Attribute, AttributeKey};
use std::boxed::Box;

fn create_mock_key_pair() -> KeyPair {
    KeyPair { pub_key: vec![1u8, 2, 3, 4, 5], pri_key: vec![4u8, 5, 6] }
}

fn generate_companion_init_key_negotiation_input_ffi() -> CompanionInitKeyNegotiationInputFfi {
    let mut companion_protocol_list = Uint16Array64Ffi::default();
    companion_protocol_list.data[0] = PROTOCOL_VERSION_1;
    companion_protocol_list.len = 1;

    CompanionInitKeyNegotiationInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        companion_protocol_list,
        companion_capability_list: Uint16Array64Ffi::default(),
        selected_protocol_id: PROTOCOL_VERSION_1,
        companion_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        host_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        sec_message: DataArray1024Ffi::default(),
    }
}

fn create_valid_key_nego_request() -> Vec<u8> {
    let request = SecKeyNegoRequest {
        crypto_algorithms: CryptoAlgorithms {
            ka_algorithms: vec![KaAlgoType::X25519 as u16],
            kdf_algorithms: vec![1],
            aead_algorithms: vec![1],
            mac_algorithms: vec![1],
        },
    };
    request.encode(ProcessorType::Default).unwrap()
}

fn create_valid_binding_request(pub_key: &[u8], challenge: u64) -> Vec<u8> {
    let mut encrypt_attribute = Attribute::new();
    encrypt_attribute.set_string(AttributeKey::AttrDeviceId, "host_device".to_string());
    encrypt_attribute.set_i32(AttributeKey::AttrUserId, 100);
    encrypt_attribute.set_u64(AttributeKey::AttrHostChallenge, challenge);
    // Default (empty) algorithm table, so the echoed lists stay empty; the
    // protocol priority [1] recomputes to the selected protocol.
    encrypt_attribute.set_u16_slice(AttributeKey::AttrKaAlgoList, &[]);
    encrypt_attribute.set_u16_slice(AttributeKey::AttrKdfAlgoList, &[]);
    encrypt_attribute.set_u16_slice(AttributeKey::AttrAeadAlgoList, &[]);
    encrypt_attribute.set_u16_slice(AttributeKey::AttrMacAlgoList, &[]);
    encrypt_attribute.set_u16_slice(AttributeKey::AttrProtocolList, &[PROTOCOL_VERSION_1]);

    let encrypt_data = encrypt_attribute.to_bytes().unwrap();
    let salt = [1u8; HKDF_SALT_SIZE];
    let tag = [2u8; AES_GCM_TAG_SIZE];
    let iv = [3u8; AES_GCM_IV_SIZE];

    let request = SecBindingRequest { pub_key: pub_key.to_vec(), challenge: 0, salt, tag, iv, encrypt_data };
    request.encode(ProcessorType::Default).unwrap()
}

fn create_valid_issue_token_message(challenge: u64, atl: i32) -> Vec<u8> {
    let issue_token = SecIssueToken { challenge, atl, token: vec![1u8; TOKEN_KEY_LEN] };
    issue_token.encrypt_issue_token(&[1u8; HKDF_SALT_SIZE], ProcessorType::Default, &[], 1).unwrap()
}

fn mock_set_crypto_engine() {
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Ok([0u8; SHARE_KEY_LEN].to_vec()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_decrypt().returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
}

#[test]
fn companion_enroll_request_new_test_selected_protocol_not_negotiated() {
    let _guard = ut_registry_guard!();
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| panic!("invalid protocol must be rejected first"));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut input = generate_companion_init_key_negotiation_input_ffi();
    input.selected_protocol_id = PROTOCOL_VERSION_1;
    input.companion_protocol_list = Uint16Array64Ffi::default();
    assert_eq!(CompanionDeviceEnrollRequest::new(&input).unwrap_err(), ErrorCode::GeneralError);

    input = generate_companion_init_key_negotiation_input_ffi();
    input.selected_protocol_id = u16::MAX;
    assert_eq!(CompanionDeviceEnrollRequest::new(&input).unwrap_err(), ErrorCode::GeneralError);
}

#[test]
fn companion_enroll_request_new_test_selected_protocol_not_supported() {
    let _guard = ut_registry_guard!();
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| panic!("invalid protocol must be rejected first"));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut input = generate_companion_init_key_negotiation_input_ffi();
    input.selected_protocol_id = u16::MAX;
    input.companion_protocol_list.data[0] = input.selected_protocol_id;
    assert_eq!(CompanionDeviceEnrollRequest::new(&input).unwrap_err(), ErrorCode::GeneralError);
}

#[test]
fn companion_enroll_request_new_test_unsupported_capability() {
    let _guard = ut_registry_guard!();
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| panic!("invalid capability must be rejected first"));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut input = generate_companion_init_key_negotiation_input_ffi();
    input.companion_capability_list = Uint16Array64Ffi::try_from(vec![u16::MAX]).unwrap();
    assert_eq!(CompanionDeviceEnrollRequest::new(&input).unwrap_err(), ErrorCode::GeneralError);
}

#[test]
fn companion_enroll_request_new_test_selected_protocol_invalid_rejected() {
    let _guard = ut_registry_guard!();
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut input = generate_companion_init_key_negotiation_input_ffi();
    let request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    assert_eq!(request.selected_protocol_id, PROTOCOL_VERSION_1);
    assert_eq!(request.companion_protocol_list, vec![PROTOCOL_VERSION_1]);

    input.selected_protocol_id = PROTOCOL_ID_INVALID;
    assert_eq!(CompanionDeviceEnrollRequest::new(&input).unwrap_err(), ErrorCode::GeneralError);
}

#[test]
fn companion_enroll_request_prepare_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_prepare_test_wrong_input_type start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = generate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();

    let wrong_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::default(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&wrong_input, &mut output);
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
        crypto_algorithms: CryptoAlgorithms {
            ka_algorithms: vec![KaAlgoType::None as u16],
            kdf_algorithms: vec![1],
            aead_algorithms: vec![1],
            mac_algorithms: vec![1],
        },
    };
    let sec_message = request_no_x25519.encode(ProcessorType::Default).unwrap();

    let input = CompanionInitKeyNegotiationInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        companion_protocol_list: Uint16Array64Ffi::try_from(vec![PROTOCOL_VERSION_1]).unwrap(),
        companion_capability_list: Uint16Array64Ffi::default(),
        selected_protocol_id: PROTOCOL_VERSION_1,
        companion_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        host_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };
    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionInitKeyNegotiationOutputFfi::default();
    let param = RequestParam::CompanionKeyNego(&input, &mut output);
    let result = request.prepare(param);
    assert_eq!(result, Err(ErrorCode::AlgorithmNegotiationFailed));
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
        companion_protocol_list: Uint16Array64Ffi::try_from(vec![PROTOCOL_VERSION_1]).unwrap(),
        companion_capability_list: Uint16Array64Ffi::default(),
        selected_protocol_id: PROTOCOL_VERSION_1,
        companion_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        host_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };
    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionInitKeyNegotiationOutputFfi::default();
    let param = RequestParam::CompanionKeyNego(&input, &mut output);
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

    let input = generate_companion_init_key_negotiation_input_ffi();
    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();

    let wrong_input =
        CompanionEndAddHostBindingInputFfi { request_id: 1, result: 0, sec_message: DataArray1024Ffi::default() };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionEndAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollEnd(&wrong_input, &mut output);
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

    let input = generate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = None;

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&begin_input, &mut output);
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

    let input = generate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_begin_test_hkdf_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_hkdf_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Ok([0u8; SHARE_KEY_LEN].to_vec()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = generate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_begin_test_decrypt_sec_message_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_decrypt_sec_message_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Ok([0u8; SHARE_KEY_LEN].to_vec()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_decrypt().returning(|_| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = generate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_begin_test_device_id_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_device_id_mismatch start");

    mock_set_crypto_engine();

    let input = generate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "mismatch-id".to_string();

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_begin_test_user_id_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_user_id_mismatch start");

    mock_set_crypto_engine();

    let input = generate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "host_device".to_string();
    request.key_nego_param.host_device_key.user_id = -1;

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_begin_test_challenge_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_challenge_mismatch start");

    mock_set_crypto_engine();

    let input = generate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "host_device".to_string();
    request.key_nego_param.host_device_key.user_id = 100;
    request.key_nego_param.companion_challenge = 0;
    request.selected_algorithms.ka_algorithm = KaAlgoType::X25519 as u16;
    request.selected_algorithms.kdf_algorithm = 1;
    request.selected_algorithms.aead_algorithm = 1;
    request.selected_algorithms.mac_algorithm = 1;

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 999);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_begin_test_encrypt_sec_message_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_encrypt_sec_message_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Ok([0u8; SHARE_KEY_LEN].to_vec()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_decrypt().returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|_, _| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = generate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "host_device".to_string();
    request.key_nego_param.host_device_key.user_id = 100;
    request.key_nego_param.companion_challenge = 0;
    request.selected_algorithms.ka_algorithm = KaAlgoType::X25519 as u16;
    request.selected_algorithms.kdf_algorithm = 1;
    request.selected_algorithms.aead_algorithm = 1;
    request.selected_algorithms.mac_algorithm = 1;

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_begin_test_generate_unique_binding_id_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_generate_unique_binding_id_fail start");

    mock_set_crypto_engine();

    let mut mock_host_binding_db_manager = MockHostBindingDbManager::new();
    mock_host_binding_db_manager.expect_generate_unique_binding_id().returning(|| Err(ErrorCode::GeneralError));
    HostBindingDbManagerRegistry::set(Box::new(mock_host_binding_db_manager));

    let input = generate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "host_device".to_string();
    request.key_nego_param.host_device_key.user_id = 100;
    request.key_nego_param.companion_challenge = 0;
    request.selected_algorithms.ka_algorithm = KaAlgoType::X25519 as u16;
    request.selected_algorithms.kdf_algorithm = 1;
    request.selected_algorithms.aead_algorithm = 1;
    request.selected_algorithms.mac_algorithm = 1;

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_begin_test_get_rtc_time_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_get_rtc_time_fail start");

    mock_set_crypto_engine();

    let mut mock_host_binding_db_manager = MockHostBindingDbManager::new();
    mock_host_binding_db_manager.expect_generate_unique_binding_id().returning(|| Ok(1));
    HostBindingDbManagerRegistry::set(Box::new(mock_host_binding_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Err(ErrorCode::GeneralError));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let input = generate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "host_device".to_string();
    request.key_nego_param.host_device_key.user_id = 100;
    request.key_nego_param.companion_challenge = 0;
    request.selected_algorithms.ka_algorithm = KaAlgoType::X25519 as u16;
    request.selected_algorithms.kdf_algorithm = 1;
    request.selected_algorithms.aead_algorithm = 1;
    request.selected_algorithms.mac_algorithm = 1;

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_begin_test_add_host_binding_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_add_host_binding_fail start");

    mock_set_crypto_engine();

    let mut mock_host_binding_db_manager = MockHostBindingDbManager::new();
    mock_host_binding_db_manager.expect_generate_unique_binding_id().returning(|| Ok(1));
    mock_host_binding_db_manager.expect_get_device_by_device_key().returning(|| Err(ErrorCode::NotFound));
    mock_host_binding_db_manager.expect_add_device().returning(|| Err(ErrorCode::GeneralError));

    let input = generate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "host_device".to_string();
    request.key_nego_param.host_device_key.user_id = 100;
    request.key_nego_param.companion_challenge = 0;
    request.selected_algorithms.ka_algorithm = KaAlgoType::X25519 as u16;
    request.selected_algorithms.kdf_algorithm = 1;
    request.selected_algorithms.aead_algorithm = 1;
    request.selected_algorithms.mac_algorithm = 1;

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_begin_test_get_device_by_binding_id_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_get_device_by_binding_id_fail start");

    mock_set_crypto_engine();

    let mut mock_host_binding_db_manager = MockHostBindingDbManager::new();
    mock_host_binding_db_manager.expect_generate_unique_binding_id().returning(|| Ok(1));
    mock_host_binding_db_manager.expect_get_device_by_device_key().returning(|| Err(ErrorCode::NotFound));
    mock_host_binding_db_manager.expect_add_device().returning(|| Ok(None));
    mock_host_binding_db_manager.expect_get_device_by_binding_id().returning(|| Err(ErrorCode::NotFound));
    HostBindingDbManagerRegistry::set(Box::new(mock_host_binding_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Ok(1000));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let input = generate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "host_device".to_string();
    request.key_nego_param.host_device_key.user_id = 100;
    request.key_nego_param.companion_challenge = 0;
    request.selected_algorithms.ka_algorithm = KaAlgoType::X25519 as u16;
    request.selected_algorithms.kdf_algorithm = 1;
    request.selected_algorithms.aead_algorithm = 1;
    request.selected_algorithms.mac_algorithm = 1;

    let sec_message = create_valid_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_end_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_end_test_wrong_input_type start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = generate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();

    let wrong_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::default(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&wrong_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn companion_enroll_request_end_test_challenge_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_end_test_challenge_mismatch start");

    mock_set_crypto_engine();

    let input = generate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.companion_challenge = 1;

    request.selected_algorithms.aead_algorithm = 1;
    let sec_message = create_valid_issue_token_message(0, AuthTrustLevel::Atl2 as i32);
    let end_input = CompanionEndAddHostBindingInputFfi {
        request_id: 1,
        result: 0,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionEndAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_end_test_atl_try_from_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_end_test_atl_try_from_fail start");

    mock_set_crypto_engine();

    let input = generate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.companion_challenge = 0;

    request.selected_algorithms.aead_algorithm = 1;
    let sec_message = create_valid_issue_token_message(0, 99999);
    let end_input = CompanionEndAddHostBindingInputFfi {
        request_id: 1,
        result: 0,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionEndAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_enroll_request_end_test_store_token_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_end_test_store_token_fail start");

    mock_set_crypto_engine();

    let mut mock_host_binding_db_manager = MockHostBindingDbManager::new();
    mock_host_binding_db_manager.expect_write_device_token().returning(|| Err(ErrorCode::GeneralError));
    HostBindingDbManagerRegistry::set(Box::new(mock_host_binding_db_manager));

    let input = generate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.companion_challenge = 0;

    request.selected_algorithms.aead_algorithm = 1;
    let sec_message = create_valid_issue_token_message(0, AuthTrustLevel::Atl2 as i32);
    let end_input = CompanionEndAddHostBindingInputFfi {
        request_id: 1,
        result: 0,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionEndAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

// The binding reply announces the local capability set as-is (convergence is host-side
// business) and echoes the host algorithm sets exactly as received over the plaintext
// nego channel.
fn create_host_algorithms() -> CryptoAlgorithms {
    CryptoAlgorithms {
        ka_algorithms: vec![KaAlgoType::X25519 as u16],
        kdf_algorithms: vec![1],
        aead_algorithms: vec![1],
        mac_algorithms: vec![1],
    }
}

// None omits the echoed algorithm keys entirely (legacy-format request).
fn create_full_binding_request(
    pub_key: &[u8],
    stray_capability_attr: bool,
    host_algorithms: Option<&CryptoAlgorithms>,
) -> Vec<u8> {
    let mut encrypt_attribute = Attribute::new();
    encrypt_attribute.set_string(AttributeKey::AttrDeviceId, "host_device".to_string());
    encrypt_attribute.set_i32(AttributeKey::AttrUserId, 100);
    encrypt_attribute.set_i32(AttributeKey::AttrSubProfileId, 0);
    encrypt_attribute.set_u64(AttributeKey::AttrCompanionChallenge, 0);
    if stray_capability_attr {
        encrypt_attribute.set_u16_slice(AttributeKey::AttrCapabilityList, &[Capability::TokenAuth as u16]);
    }
    if let Some(host_algorithms) = host_algorithms {
        // The encrypted request echoes the host algorithms received in plaintext.
        encrypt_attribute.set_u16_slice(AttributeKey::AttrKaAlgoList, &host_algorithms.ka_algorithms);
        encrypt_attribute.set_u16_slice(AttributeKey::AttrKdfAlgoList, &host_algorithms.kdf_algorithms);
        encrypt_attribute.set_u16_slice(AttributeKey::AttrAeadAlgoList, &host_algorithms.aead_algorithms);
        encrypt_attribute.set_u16_slice(AttributeKey::AttrMacAlgoList, &host_algorithms.mac_algorithms);
    }
    // Unified exchange leg: the host announces its protocol priority list
    // inside the encrypted request; [1] recomputes to the selected protocol.
    encrypt_attribute.set_u16_slice(AttributeKey::AttrProtocolList, &[PROTOCOL_VERSION_1]);

    let encrypt_data = encrypt_attribute.to_bytes().unwrap();
    let request = SecBindingRequest {
        pub_key: pub_key.to_vec(),
        challenge: 0,
        salt: [1u8; HKDF_SALT_SIZE],
        tag: [2u8; AES_GCM_TAG_SIZE],
        iv: [3u8; AES_GCM_IV_SIZE],
        encrypt_data,
    };
    request.encode(ProcessorType::Default).unwrap()
}

fn run_companion_binding_begin(stray_capability_attr: bool) -> Vec<u8> {
    mock_set_crypto_engine();

    let mut mock_host_binding_db_manager = MockHostBindingDbManager::new();
    mock_host_binding_db_manager.expect_generate_unique_binding_id().returning(|| Ok(1));
    mock_host_binding_db_manager.expect_get_device_by_device_key().returning(|| Err(ErrorCode::NotFound));
    mock_host_binding_db_manager.expect_add_device().returning(|| Ok(None));
    HostBindingDbManagerRegistry::set(Box::new(mock_host_binding_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Ok(1000));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    // Local product capabilities B.
    let mut input = generate_companion_init_key_negotiation_input_ffi();
    input.companion_capability_list = Uint16Array64Ffi::try_from(vec![Capability::DelegateAuth as u16,
        Capability::TokenAuth as u16]).unwrap();
    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "host_device".to_string();
    request.key_nego_param.host_device_key.user_id = 100;
    request.key_nego_param.companion_challenge = 0;
    request.host_algorithms = create_host_algorithms();
    request.selected_algorithms.ka_algorithm = KaAlgoType::X25519 as u16;
    request.selected_algorithms.kdf_algorithm = 1;
    request.selected_algorithms.aead_algorithm = 1;
    request.selected_algorithms.mac_algorithm = 1;

    let host_algorithms = create_host_algorithms();
    let sec_message = create_full_binding_request(
        &create_mock_key_pair().pub_key,
        stray_capability_attr,
        Some(&host_algorithms),
    );
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&begin_input, &mut output);
    assert_eq!(request.begin(param), Ok(()));
    output.sec_message.as_slice().unwrap().to_vec()
}

fn binding_reply_capability_list(sec_message: &[u8]) -> Vec<u16> {
    let reply = SecBindingReply::decode(sec_message, ProcessorType::Default).unwrap();
    let attribute = Attribute::try_from_bytes(&reply.encrypt_data).unwrap();
    attribute.get_u16_vec(AttributeKey::AttrCapabilityList).unwrap()
}

#[test]
fn companion_enroll_request_begin_test_replies_with_local_set() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_replies_with_local_set start");

    // B is announced as-is; a stray capability attribute in the request (no endpoint sends
    // one anymore) must not change the reply.
    let sec_message = run_companion_binding_begin(false);
    assert_eq!(binding_reply_capability_list(&sec_message),
        vec![Capability::DelegateAuth as u16, Capability::TokenAuth as u16]);

    let sec_message = run_companion_binding_begin(true);
    assert_eq!(binding_reply_capability_list(&sec_message),
        vec![Capability::DelegateAuth as u16, Capability::TokenAuth as u16]);
}

// A binding request whose encrypted offer confirmation differs from the offer received over
// the plaintext nego channel (e.g. an in-transit strip) fails the round with 20015.
#[test]
fn companion_enroll_request_begin_test_host_algorithms_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_host_algorithms_mismatch start");

    mock_set_crypto_engine();

    let input = generate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "host_device".to_string();
    request.key_nego_param.host_device_key.user_id = 100;
    request.key_nego_param.companion_challenge = 0;
    request.host_algorithms = create_host_algorithms();
    request.selected_algorithms.ka_algorithm = KaAlgoType::X25519 as u16;
    request.selected_algorithms.kdf_algorithm = 1;
    request.selected_algorithms.aead_algorithm = 1;
    request.selected_algorithms.mac_algorithm = 1;

    // Stripped offer: the confirmation claims one KDF value was never offered locally.
    let mut stripped_host_algorithms = create_host_algorithms();
    stripped_host_algorithms.kdf_algorithms = vec![];
    let sec_message =
        create_full_binding_request(&create_mock_key_pair().pub_key, false, Some(&stripped_host_algorithms));
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::AlgorithmNegotiationFailed));
}

// The echoed algorithm keys are mandatory: a legacy-format request without them fails to decode.
#[test]
fn companion_enroll_request_begin_test_binding_request_without_host_algorithms_fails() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_binding_request_without_host_algorithms_fails start");

    mock_set_crypto_engine();

    let input = generate_companion_init_key_negotiation_input_ffi();

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "host_device".to_string();
    request.key_nego_param.host_device_key.user_id = 100;
    request.key_nego_param.companion_challenge = 0;
    request.host_algorithms = create_host_algorithms();
    request.selected_algorithms.ka_algorithm = KaAlgoType::X25519 as u16;
    request.selected_algorithms.kdf_algorithm = 1;
    request.selected_algorithms.aead_algorithm = 1;
    request.selected_algorithms.mac_algorithm = 1;

    let sec_message = create_full_binding_request(&create_mock_key_pair().pub_key, false, None);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}
