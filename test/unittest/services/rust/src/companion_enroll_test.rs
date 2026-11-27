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
use crate::request::enroll::enroll_message::{SecBindingReply, SecBindingRequest, SecKeyNegoReply, SecKeyNegoRequest};
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

fn create_mock_host_binding(binding_id: i32) -> HostBinding {
    HostBinding {
        device_key: DeviceKey {
            device_id: String::from("host_device"),
            device_id_type: 1,
            user_id: 100,
            sub_profile_id: 0,
        },
        binding_id,
        user_info: UserInfo { user_key: UserKey { user_id: 100, sub_profile_id: 0 }, user_type: 0 },
        binding_time: 123456,
        last_used_time: 123456,
        enrolled_protocol_id: PROTOCOL_VERSION_1,
        secure_protocol_id: 1,
    }
}

fn generate_companion_init_key_negotiation_input_ffi() -> CompanionInitKeyNegotiationInputFfi {
    let mut companion_supported_protocol_list = Uint16Array64Ffi::default();
    companion_supported_protocol_list.data[0] = PROTOCOL_VERSION_1;
    companion_supported_protocol_list.len = 1;

    CompanionInitKeyNegotiationInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        companion_supported_protocol_list,
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
        binding_signature_algorithm_list: Vec::new(),
    };
    request.encode(ProcessorType::Default).unwrap()
}

fn create_key_nego_request_with_binding_signature_list(binding_signature_algorithm_list: &[u16]) -> Vec<u8> {
    let request = SecKeyNegoRequest {
        crypto_algorithms: CryptoAlgorithms {
            ka_algorithms: vec![KaAlgoType::X25519 as u16],
            kdf_algorithms: vec![1],
            aead_algorithms: vec![1],
            mac_algorithms: vec![1],
        },
        binding_signature_algorithm_list: binding_signature_algorithm_list.to_vec(),
    };
    request.encode(ProcessorType::Default).unwrap()
}

fn create_binding_request_with_binding_signature(
    pub_key: &[u8],
    challenge: u64,
    binding_signature_param: Option<(&[u8], u16)>,
    protocol: &[u16],
) -> Vec<u8> {
    let mut encrypt_attribute = Attribute::new();
    encrypt_attribute.set_string(AttributeKey::AttrDeviceId, "host_device".to_string());
    encrypt_attribute.set_i32(AttributeKey::AttrUserId, 100);
    // Default (empty) algorithm table, so the echoed lists stay empty; the
    // protocol priority list recomputes to the selected protocol.
    encrypt_attribute.set_i32(AttributeKey::AttrSubProfileId, 0);
    encrypt_attribute.set_u64(AttributeKey::AttrCompanionChallenge, challenge);
    if let Some((binding_signature_pub_key, alg_id)) = binding_signature_param {
        encrypt_attribute.set_u8_slice(AttributeKey::AttrBindingSignaturePublicKey, binding_signature_pub_key);
        encrypt_attribute.set_u16(AttributeKey::AttrBindingSignatureAlgoId, alg_id);
    }
    encrypt_attribute.set_u16_slice(AttributeKey::AttrKaAlgoList, &[]);
    encrypt_attribute.set_u16_slice(AttributeKey::AttrKdfAlgoList, &[]);
    encrypt_attribute.set_u16_slice(AttributeKey::AttrAeadAlgoList, &[]);
    encrypt_attribute.set_u16_slice(AttributeKey::AttrMacAlgoList, &[]);
    encrypt_attribute.set_u16_slice(AttributeKey::AttrProtocolList, protocol);

    let encrypt_data = encrypt_attribute.to_bytes().unwrap();
    let salt = [1u8; HKDF_SALT_SIZE];
    let tag = [2u8; AES_GCM_TAG_SIZE];
    let iv = [3u8; AES_GCM_IV_SIZE];

    let request = SecBindingRequest { pub_key: pub_key.to_vec(), challenge: 0, salt, tag, iv, encrypt_data };
    request.encode(ProcessorType::Default).unwrap()
}

fn create_valid_binding_request(pub_key: &[u8], challenge: u64) -> Vec<u8> {
    create_binding_request_with_binding_signature(pub_key, challenge, None, &[PROTOCOL_VERSION_1])
}

fn create_valid_issue_token_message(challenge: u64, atl: i32) -> Vec<u8> {
    let issue_token = SecIssueToken { challenge, atl, token: vec![1u8; TOKEN_KEY_LEN] };
    issue_token.encrypt_issue_token(&[1u8; HKDF_SALT_SIZE], ProcessorType::Default, &[], 1).unwrap()
}

fn mock_set_crypto_engine() {
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_p256_check_pub_key().returning(|pub_key| {
        if pub_key.len() == BINDING_SIGNATURE_PUB_KEY_LEN && pub_key.first() == Some(&0x04) {
            Ok(())
        } else {
            Err(ErrorCode::GeneralError)
        }
    });
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
    input.companion_supported_protocol_list = Uint16Array64Ffi::default();
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
    input.companion_supported_protocol_list.data[0] = input.selected_protocol_id;
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
    assert_eq!(request.companion_supported_protocol_list, vec![PROTOCOL_VERSION_1]);

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
        binding_signature_algorithm_list: Vec::new(),
    };
    let sec_message = request_no_x25519.encode(ProcessorType::Default).unwrap();

    let input = CompanionInitKeyNegotiationInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        companion_supported_protocol_list: Uint16Array64Ffi::try_from(vec![PROTOCOL_VERSION_1]).unwrap(),
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
        companion_supported_protocol_list: Uint16Array64Ffi::try_from(vec![PROTOCOL_VERSION_1]).unwrap(),
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
fn companion_enroll_request_begin_test_same_device_replaced() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_same_device_replaced start");

    mock_set_crypto_engine();

    let existing = create_mock_host_binding(42);

    let mut mock_host_binding_db_manager = MockHostBindingDbManager::new();
    mock_host_binding_db_manager.expect_generate_unique_binding_id().returning(|| Ok(1));
    mock_host_binding_db_manager.expect_get_device_by_device_key().returning(move || Ok(existing.clone()));
    mock_host_binding_db_manager.expect_remove_device().returning(|| Ok(create_mock_host_binding(42)));
    mock_host_binding_db_manager.expect_add_device().returning(|| Ok(None));
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
    assert!(result.is_ok());
    assert_eq!(output.replaced_binding_id, 42);
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

// Legacy layout (2026-10-14 baseline host) 0x0303 encrypted inner payload: the attributes every
// host sends, the sub-profile id (`sub_profile_id` None leaves it out) and whatever `edit` adds,
// such as a protocol list in any shape. No algorithm echo, no binding signature.
fn create_legacy_binding_request(
    pub_key: &[u8],
    challenge: u64,
    sub_profile_id: Option<i32>,
    edit: impl FnOnce(&mut Attribute),
) -> Vec<u8> {
    let mut encrypt_attribute = Attribute::new();
    encrypt_attribute.set_string(AttributeKey::AttrDeviceId, "host_device".to_string());
    encrypt_attribute.set_i32(AttributeKey::AttrUserId, 100);
    encrypt_attribute.set_u64(AttributeKey::AttrCompanionChallenge, challenge);
    if let Some(sub_profile_id) = sub_profile_id {
        encrypt_attribute.set_i32(AttributeKey::AttrSubProfileId, sub_profile_id);
    }
    edit(&mut encrypt_attribute);

    let request = SecBindingRequest {
        pub_key: pub_key.to_vec(),
        challenge: 0,
        salt: [1u8; HKDF_SALT_SIZE],
        tag: [2u8; AES_GCM_TAG_SIZE],
        iv: [3u8; AES_GCM_IV_SIZE],
        encrypt_data: encrypt_attribute.to_bytes().unwrap(),
    };
    request.encode(ProcessorType::Default).unwrap()
}

// The four legacy attributes a baseline host carries, sub-profile id included.
fn create_old_format_binding_request(pub_key: &[u8], challenge: u64) -> Vec<u8> {
    create_legacy_binding_request(pub_key, challenge, Some(0), |_| {})
}

// Mock registries for the companion binding leg: a fresh binding is created and stored.
fn install_binding_mocks() {
    mock_set_crypto_engine();

    let mut mock_host_binding_db_manager = MockHostBindingDbManager::new();
    mock_host_binding_db_manager.expect_generate_unique_binding_id().returning(|| Ok(1));
    mock_host_binding_db_manager.expect_get_device_by_device_key().returning(|| Err(ErrorCode::NotFound));
    mock_host_binding_db_manager.expect_add_device().returning(|| Ok(None));
    HostBindingDbManagerRegistry::set(Box::new(mock_host_binding_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Ok(1000));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));
}

// Installs the mock registries and returns the companion binding leg's request for `input`.
fn make_binding_request(input: &CompanionInitKeyNegotiationInputFfi) -> CompanionDeviceEnrollRequest {
    install_binding_mocks();

    let mut request = CompanionDeviceEnrollRequest::new(input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "host_device".to_string();
    request.key_nego_param.host_device_key.user_id = 100;
    request.key_nego_param.companion_challenge = 0;
    request.host_algorithms = create_host_algorithms();
    request.selected_algorithms.ka_algorithm = KaAlgoType::X25519 as u16;
    request.selected_algorithms.kdf_algorithm = 1;
    request.selected_algorithms.aead_algorithm = 1;
    request.selected_algorithms.mac_algorithm = 1;
    request
}

fn run_binding_begin(mut request: CompanionDeviceEnrollRequest, sec_message: Vec<u8>) -> Result<Vec<u8>, ErrorCode> {
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };
    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&begin_input, &mut output);
    request.begin(param)?;
    Ok(output.sec_message.as_slice().unwrap().to_vec())
}

// The companion binding leg with local product capabilities B and a full-layout request.
fn run_companion_binding_begin(stray_capability_attr: bool) -> Vec<u8> {
    let mut input = generate_companion_init_key_negotiation_input_ffi();
    input.companion_capability_list = Uint16Array64Ffi::try_from(vec![Capability::DelegateAuth as u16,
        Capability::TokenAuth as u16]).unwrap();
    let sec_message = create_full_binding_request(
        &create_mock_key_pair().pub_key,
        stray_capability_attr,
        Some(&create_host_algorithms()),
    );
    run_binding_begin(make_binding_request(&input), sec_message).unwrap()
}

// One u16 list of the binding reply's encrypted payload.
fn binding_reply_list(sec_message: &[u8], key: AttributeKey) -> Vec<u16> {
    let reply = SecBindingReply::decode(sec_message, ProcessorType::Default).unwrap();
    let attribute = Attribute::try_from_bytes(&reply.encrypt_data).unwrap();
    attribute.get_u16_vec(key).unwrap()
}

#[test]
fn companion_enroll_request_begin_test_replies_with_local_set() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_replies_with_local_set start");

    // B is announced as-is; a stray capability attribute in the request (no endpoint sends
    // one anymore) must not change the reply.
    let sec_message = run_companion_binding_begin(false);
    assert_eq!(binding_reply_list(&sec_message, AttributeKey::AttrCapabilityList),
        vec![Capability::DelegateAuth as u16, Capability::TokenAuth as u16]);

    let sec_message = run_companion_binding_begin(true);
    assert_eq!(binding_reply_list(&sec_message, AttributeKey::AttrCapabilityList),
        vec![Capability::DelegateAuth as u16, Capability::TokenAuth as u16]);
}

#[test]
fn companion_enroll_request_begin_test_host_algorithms_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_host_algorithms_mismatch start");

    mock_set_crypto_engine();

    let mut input = generate_companion_init_key_negotiation_input_ffi();
    input.companion_supported_protocol_list = Uint16Array64Ffi::try_from(vec![PROTOCOL_VERSION_2]).unwrap();
    input.selected_protocol_id = PROTOCOL_VERSION_2;

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

    // Stripped offer: the confirmation claims one KDF value was never offered locally. The echo
    // check fires before the protocol list recomputation, so the [V1] list below is unreached.
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

// Legacy layout (2026-10-14 baseline host) 0x0303 encrypted inner payload carries only the four
// legacy attributes: with negotiated protocol V1 the algorithm-echo and protocol-list checks
// are skipped and the binding completes under legacy behavior (AGENTS.md rules 2/12).
#[test]
fn companion_enroll_request_begin_test_old_format_v1_tolerated() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_old_format_v1_tolerated start");

    mock_set_crypto_engine();

    let mut mock_host_binding_db_manager = MockHostBindingDbManager::new();
    mock_host_binding_db_manager.expect_generate_unique_binding_id().returning(|| Ok(1));
    mock_host_binding_db_manager.expect_get_device_by_device_key().returning(|| Err(ErrorCode::NotFound));
    mock_host_binding_db_manager.expect_add_device().returning(|| Ok(None));
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
    request.host_algorithms = create_host_algorithms();
    request.selected_algorithms.ka_algorithm = KaAlgoType::X25519 as u16;
    request.selected_algorithms.kdf_algorithm = 1;
    request.selected_algorithms.aead_algorithm = 1;
    request.selected_algorithms.mac_algorithm = 1;

    let sec_message = create_old_format_binding_request(&create_mock_key_pair().pub_key, 0);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&begin_input, &mut output);
    assert_eq!(request.begin(param), Ok(()));
}

// Runs the V1 binding leg for a companion supporting `companion_supported_protocol_list` and returns the
// protocol list of its reply.
fn reply_protocol_list(companion_supported_protocol_list: &[u16], sec_message: Vec<u8>) -> Vec<u16> {
    let mut input = generate_companion_init_key_negotiation_input_ffi();
    input.companion_supported_protocol_list = Uint16Array64Ffi::try_from(companion_supported_protocol_list.to_vec()).unwrap();
    let reply = run_binding_begin(make_binding_request(&input), sec_message).unwrap();
    binding_reply_list(&reply, AttributeKey::AttrProtocolList)
}

// A legacy host accepts only a reply list equal to its own: without the host protocol list on the
// wire the reply announces VERSION_1 alone even though the companion supports V2.
#[test]
fn companion_enroll_request_begin_test_reply_narrows_to_v1_for_legacy_host() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_reply_narrows_to_v1_for_legacy_host start");

    let support_set = [PROTOCOL_VERSION_2, PROTOCOL_VERSION_1];

    let sec_message = create_old_format_binding_request(&create_mock_key_pair().pub_key, 0);
    assert_eq!(reply_protocol_list(&support_set, sec_message), vec![PROTOCOL_VERSION_1]);

    // ...and with VERSION_1 alone carried explicitly.
    let sec_message = create_legacy_binding_request(&create_mock_key_pair().pub_key, 0, Some(0), |attribute| {
        attribute.set_u16_slice(AttributeKey::AttrProtocolList, &[PROTOCOL_VERSION_1])
    });
    assert_eq!(reply_protocol_list(&support_set, sec_message), vec![PROTOCOL_VERSION_1]);
}

// A present but malformed host protocol list decodes as the legacy layout: it falls back to the
// VERSION_1 default the same as when the list is absent, and the reply narrows to VERSION_1.
#[test]
fn companion_enroll_request_begin_test_malformed_host_protocol_list_falls_back_to_legacy() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_malformed_host_protocol_list_falls_back_to_legacy start");

    // One byte: not a whole number of u16 values.
    let sec_message = create_legacy_binding_request(&create_mock_key_pair().pub_key, 0, Some(0), |attribute| {
        attribute.set_u8_slice(AttributeKey::AttrProtocolList, &[0x01])
    });
    assert_eq!(reply_protocol_list(&[PROTOCOL_VERSION_1], sec_message), vec![PROTOCOL_VERSION_1]);
}

// The binding leg does not need the host to carry a sub-profile id: the SA hands in none for the
// host device, and an absent key means none.
#[test]
fn companion_enroll_request_begin_test_sub_profile_id_absent_tolerated() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_sub_profile_id_absent_tolerated start");

    let mut request = make_binding_request(&generate_companion_init_key_negotiation_input_ffi());
    request.key_nego_param.host_device_key.sub_profile_id = INVALID_SUB_PROFILE_ID;
    let sec_message = create_legacy_binding_request(&create_mock_key_pair().pub_key, 0, None, |_| {});
    assert!(run_binding_begin(request, sec_message).is_ok());
}

// A carried sub-profile id must decode cleanly: present is not absent (AGENTS.md rule 6).
#[test]
fn companion_enroll_request_begin_test_malformed_sub_profile_id_fails() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_malformed_sub_profile_id_fails start");

    let mut request = make_binding_request(&generate_companion_init_key_negotiation_input_ffi());
    request.key_nego_param.host_device_key.sub_profile_id = INVALID_SUB_PROFILE_ID;
    // One byte: not an i32.
    let sec_message = create_legacy_binding_request(&create_mock_key_pair().pub_key, 0, None, |attribute| {
        attribute.set_u8_slice(AttributeKey::AttrSubProfileId, &[0x01])
    });
    assert!(run_binding_begin(request, sec_message).is_err());
}

// The echoed algorithm keys stay mandatory for V2 peers: a request without them fails to decode.
#[test]
fn companion_enroll_request_begin_test_binding_request_without_host_algorithms_fails() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_binding_request_without_host_algorithms_fails start");

    mock_set_crypto_engine();

    let mut input = generate_companion_init_key_negotiation_input_ffi();
    input.companion_supported_protocol_list = Uint16Array64Ffi::try_from(vec![PROTOCOL_VERSION_2]).unwrap();
    input.selected_protocol_id = PROTOCOL_VERSION_2;

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
#[test]
fn companion_enroll_request_prepare_test_no_binding_signature_list_v1() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_prepare_test_no_binding_signature_list_v1 start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_generate_x25519_key_pair().returning(|| Ok(create_mock_key_pair()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let sec_message = create_valid_key_nego_request();
    let input = CompanionInitKeyNegotiationInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        companion_supported_protocol_list: Uint16Array64Ffi::try_from(vec![PROTOCOL_VERSION_1]).unwrap(),
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
    assert!(result.is_ok());
    // A V1 host gets a V1 reply: no binding-signature selection (disabled, None).
    let reply = SecKeyNegoReply::decode(output.sec_message.as_slice().unwrap(), ProcessorType::Default).unwrap();
    assert_eq!(reply.selected_algorithms.binding_signature_algorithm, None);
}

#[test]
fn companion_enroll_request_prepare_test_binding_signature_list_v2() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_prepare_test_binding_signature_list_v2 start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_generate_x25519_key_pair().returning(|| Ok(create_mock_key_pair()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let sec_message = create_key_nego_request_with_binding_signature_list(&[P256]);
    let input = CompanionInitKeyNegotiationInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        companion_supported_protocol_list: Uint16Array64Ffi::try_from(vec![PROTOCOL_VERSION_1]).unwrap(),
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
    assert!(result.is_ok());
    assert_eq!(request.host_binding_signature_algo_list, vec![P256]);
    // The companion makes the selection: the reply carries it in the fifth field.
    let reply = SecKeyNegoReply::decode(output.sec_message.as_slice().unwrap(), ProcessorType::Default).unwrap();
    assert_eq!(reply.selected_algorithms.binding_signature_algorithm, Some(P256));
    assert_eq!(request.selected_algorithms.binding_signature_algorithm, Some(P256));
}

// A host list whose values are all outside the shared support table leaves no intersection:
// the enroll fails (no default algorithm, no V1 fallback), mirroring the four-role 20015.
#[test]
fn companion_enroll_request_prepare_test_binding_signature_no_intersection() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_prepare_test_binding_signature_no_intersection start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_generate_x25519_key_pair().returning(|| Ok(create_mock_key_pair()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let sec_message = create_key_nego_request_with_binding_signature_list(&[P256 + 1]);
    let input = CompanionInitKeyNegotiationInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        companion_supported_protocol_list: Uint16Array64Ffi::try_from(vec![PROTOCOL_VERSION_1]).unwrap(),
        companion_capability_list: Uint16Array64Ffi::default(),
        selected_protocol_id: PROTOCOL_VERSION_1,
        companion_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        host_device_key: DeviceKeyFfi { device_id_type: 1, ..Default::default() },
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };
    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();

    let mut output = crate::entry::companion_device_auth_ffi::CompanionInitKeyNegotiationOutputFfi::default();
    let param = RequestParam::CompanionKeyNego(&input, &mut output);
    assert_eq!(request.prepare(param), Err(ErrorCode::AlgorithmNegotiationFailed));
}

#[test]
fn companion_enroll_request_begin_test_binding_signature_algo_not_negotiated() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_binding_signature_algo_not_negotiated start");

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
    // The 0x0301 selection was never made (empty host list selects 0), so any echoed
    // algorithm ID in the binding request is a violation.
    request.host_binding_signature_algo_list = Vec::new();

    let sec_message = create_binding_request_with_binding_signature(
        &create_mock_key_pair().pub_key,
        0,
        Some((&[7u8; BINDING_SIGNATURE_PUB_KEY_LEN], P256)),
        &[PROTOCOL_VERSION_1],
    );
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

// The mirror direction: an algorithm was selected in 0x0301, so the binding
// request must carry the host public key.
#[test]
fn companion_enroll_request_begin_test_binding_signature_pub_key_absent() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_binding_signature_pub_key_absent start");

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
    request.host_binding_signature_algo_list = vec![P256];
    request.selected_algorithms.binding_signature_algorithm = Some(P256);

    let sec_message = create_binding_request_with_binding_signature(
        &create_mock_key_pair().pub_key,
        0,
        None,
        &[PROTOCOL_VERSION_1],
    );
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

#[test]
fn companion_enroll_request_begin_test_binding_signature_pub_key_len_invalid() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_binding_signature_pub_key_len_invalid start");

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
    request.host_binding_signature_algo_list = vec![P256];
    request.selected_algorithms.binding_signature_algorithm = Some(P256);

    let sec_message = create_binding_request_with_binding_signature(
        &create_mock_key_pair().pub_key,
        0,
        Some((&[7u8; 5], P256)),
        &[PROTOCOL_VERSION_1],
    );
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

// A P-256 public key must be a 65B SEC1 uncompressed point: right length but a
// first byte other than 0x04 is rejected.
#[test]
fn companion_enroll_request_begin_test_binding_signature_pub_key_prefix_invalid() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_binding_signature_pub_key_prefix_invalid start");

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
    request.host_binding_signature_algo_list = vec![P256];
    request.selected_algorithms.binding_signature_algorithm = Some(P256);

    let sec_message = create_binding_request_with_binding_signature(
        &create_mock_key_pair().pub_key,
        0,
        Some((&[7u8; BINDING_SIGNATURE_PUB_KEY_LEN], P256)),
        &[PROTOCOL_VERSION_1],
    );
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
fn companion_enroll_request_begin_test_binding_signature_success() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_binding_signature_success start");

    mock_set_crypto_engine();

    let mut mock_host_binding_db_manager = MockHostBindingDbManager::new();
    mock_host_binding_db_manager.expect_generate_unique_binding_id().returning(|| Ok(1));
    mock_host_binding_db_manager.expect_get_device_by_device_key().returning(|| Err(ErrorCode::NotFound));
    mock_host_binding_db_manager.expect_add_device().returning(|| Ok(None));
    mock_host_binding_db_manager.expect_write_binding_signature_key().returning(|| Ok(()));
    HostBindingDbManagerRegistry::set(Box::new(mock_host_binding_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Ok(1000));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let mut input = generate_companion_init_key_negotiation_input_ffi();
    input.companion_supported_protocol_list = Uint16Array64Ffi::try_from(vec![PROTOCOL_VERSION_2]).unwrap();
    input.selected_protocol_id = PROTOCOL_VERSION_2;

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "host_device".to_string();
    request.key_nego_param.host_device_key.user_id = 100;
    request.key_nego_param.companion_challenge = 0;
    request.selected_algorithms.ka_algorithm = KaAlgoType::X25519 as u16;
    request.selected_algorithms.kdf_algorithm = 1;
    request.selected_algorithms.aead_algorithm = 1;
    request.selected_algorithms.mac_algorithm = 1;
    request.host_binding_signature_algo_list = vec![P256];
    request.selected_algorithms.binding_signature_algorithm = Some(P256);

    // 65B SEC1 uncompressed point: 0x04 prefix followed by the point coordinates.
    let binding_signature_pub_key = [0x04u8; BINDING_SIGNATURE_PUB_KEY_LEN];
    let sec_message = create_binding_request_with_binding_signature(
        &create_mock_key_pair().pub_key,
        0,
        Some((&binding_signature_pub_key, P256)),
        &[PROTOCOL_VERSION_2],
    );
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&begin_input, &mut output);
    let result = request.begin(param);
    assert!(result.is_ok());
}

#[test]
fn companion_enroll_request_begin_test_binding_signature_key_write_fail_rolls_back() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_binding_signature_key_write_fail_rolls_back start");

    mock_set_crypto_engine();

    let mut mock_host_binding_db_manager = MockHostBindingDbManager::new();
    mock_host_binding_db_manager.expect_generate_unique_binding_id().returning(|| Ok(1));
    mock_host_binding_db_manager.expect_get_device_by_device_key().returning(|| Err(ErrorCode::NotFound));
    mock_host_binding_db_manager.expect_add_device().returning(|| Ok(None));
    mock_host_binding_db_manager.expect_write_binding_signature_key().returning(|| Err(ErrorCode::GeneralError));
    // the half-written binding record must be removed again (fail-closed, no V1 ghost)
    mock_host_binding_db_manager.expect_remove_device().returning(|| Err(ErrorCode::GeneralError));
    HostBindingDbManagerRegistry::set(Box::new(mock_host_binding_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Ok(1000));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let mut input = generate_companion_init_key_negotiation_input_ffi();
    input.companion_supported_protocol_list = Uint16Array64Ffi::try_from(vec![PROTOCOL_VERSION_2]).unwrap();
    input.selected_protocol_id = PROTOCOL_VERSION_2;

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "host_device".to_string();
    request.key_nego_param.host_device_key.user_id = 100;
    request.key_nego_param.companion_challenge = 0;
    request.selected_algorithms.ka_algorithm = KaAlgoType::X25519 as u16;
    request.selected_algorithms.kdf_algorithm = 1;
    request.selected_algorithms.aead_algorithm = 1;
    request.selected_algorithms.mac_algorithm = 1;
    request.host_binding_signature_algo_list = vec![P256];
    request.selected_algorithms.binding_signature_algorithm = Some(P256);

    let binding_signature_pub_key = [0x04u8; BINDING_SIGNATURE_PUB_KEY_LEN];
    let sec_message = create_binding_request_with_binding_signature(
        &create_mock_key_pair().pub_key,
        0,
        Some((&binding_signature_pub_key, P256)),
        &[PROTOCOL_VERSION_2],
    );
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&begin_input, &mut output);
    // the original write error surfaces even though the rollback removal itself failed
    assert_eq!(request.begin(param), Err(ErrorCode::GeneralError));
}

// A V2 enroll must carry the host sign key pair: persisting a V2 binding without
// sign material would leave it permanently unusable, so the mismatch fails closed.
#[test]
fn companion_enroll_request_begin_test_v2_protocol_without_binding_signature_rejected() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_v2_protocol_without_binding_signature_rejected start");

    mock_set_crypto_engine();

    let mut input = generate_companion_init_key_negotiation_input_ffi();
    input.companion_supported_protocol_list = Uint16Array64Ffi::try_from(vec![PROTOCOL_VERSION_2]).unwrap();
    input.selected_protocol_id = PROTOCOL_VERSION_2;

    let mut request = CompanionDeviceEnrollRequest::new(&input).unwrap();
    request.key_nego_param.key_pair = Some(create_mock_key_pair());
    request.key_nego_param.host_device_key.device_id = "host_device".to_string();
    request.key_nego_param.host_device_key.user_id = 100;
    request.key_nego_param.companion_challenge = 0;
    request.selected_algorithms.ka_algorithm = KaAlgoType::X25519 as u16;
    request.selected_algorithms.kdf_algorithm = 1;
    request.selected_algorithms.aead_algorithm = 1;
    request.selected_algorithms.mac_algorithm = 1;

    let sec_message =
        create_binding_request_with_binding_signature(&create_mock_key_pair().pub_key, 0, None, &[PROTOCOL_VERSION_2]);
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&begin_input, &mut output);
    assert_eq!(request.begin(param), Err(ErrorCode::AlgorithmNegotiationFailed));
}

// Mirror invariant: a V1 binding never carries a sign key pair.
#[test]
fn companion_enroll_request_begin_test_v1_protocol_with_binding_signature_rejected() {
    let _guard = ut_registry_guard!();
    log_i!("companion_enroll_request_begin_test_v1_protocol_with_binding_signature_rejected start");

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
    request.host_binding_signature_algo_list = vec![P256];
    request.selected_algorithms.binding_signature_algorithm = Some(P256);

    let binding_signature_pub_key = [0x04u8; BINDING_SIGNATURE_PUB_KEY_LEN];
    let sec_message = create_binding_request_with_binding_signature(
        &create_mock_key_pair().pub_key,
        0,
        Some((&binding_signature_pub_key, P256)),
        &[PROTOCOL_VERSION_1],
    );
    let begin_input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = crate::entry::companion_device_auth_ffi::CompanionBeginAddHostBindingOutputFfi::default();
    let param = RequestParam::CompanionEnrollBegin(&begin_input, &mut output);
    assert_eq!(request.begin(param), Err(ErrorCode::AlgorithmNegotiationFailed));
}
