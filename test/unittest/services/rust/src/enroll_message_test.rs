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
const FILE_ID: u16 = TestFileId::EnrollMessageTest as u16;

use crate::common::constants::*;
use crate::log_i;
use crate::request::enroll::enroll_message::{
    FwkEnrollRequest, SecBindingReply, SecBindingReplyInfo, SecBindingRequest, SecKeyNegoReply, SecKeyNegoRequest,
};
use crate::traits::crypto_engine::{CryptoEngineRegistry, KeyPair, MockCryptoEngine};
use crate::common::algorithm::{CryptoAlgorithms, SelectedAlgorithms};
use crate::traits::db_manager::UserKey;
use crate::traits::misc_manager::{MiscManagerRegistry, MockMiscManager};
use crate::ut_registry_guard;
use crate::utils::message_codec::{MessageCodec, MessageSignParam};
use crate::utils::{Attribute, AttributeKey};
use std::boxed::Box;

fn create_mock_key_pair() -> KeyPair {
    KeyPair { pub_key: vec![1u8, 2, 3], pri_key: vec![4u8, 5, 6] }
}

#[test]
fn fwk_enroll_request_decode_test_invalid_message() {
    let _guard = ut_registry_guard!();
    log_i!("fwk_enroll_request_decode_test_invalid_message start");

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_get_fwk_pub_key().returning(|| Ok(create_mock_key_pair().pub_key.clone()));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let invalid_message = vec![1, 2, 3];
    let result = FwkEnrollRequest::decode(&invalid_message);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn fwk_enroll_request_decode_test_miss_schedule_id() {
    let _guard = ut_registry_guard!();
    log_i!("fwk_enroll_request_decode_test_miss_schedule_id start");

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_get_fwk_pub_key().returning(|| Ok(create_mock_key_pair().pub_key.clone()));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut attribute = Attribute::new();
    attribute.set_i32(AttributeKey::AttrAuthTrustLevel, 20000);

    let message_codec = MessageCodec::new(MessageSignParam::Executor(create_mock_key_pair()));
    let message = message_codec.serialize_attribute(&attribute).unwrap();

    let result = FwkEnrollRequest::decode(&message);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn fwk_enroll_request_decode_test_miss_atl() {
    let _guard = ut_registry_guard!();
    log_i!("fwk_enroll_request_decode_test_miss_atl start");

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_get_fwk_pub_key().returning(|| Ok(create_mock_key_pair().pub_key.clone()));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut attribute = Attribute::new();
    attribute.set_u64(AttributeKey::AttrScheduleId, 1);

    let message_codec = MessageCodec::new(MessageSignParam::Executor(create_mock_key_pair()));
    let message = message_codec.serialize_attribute(&attribute).unwrap();

    let result = FwkEnrollRequest::decode(&message);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_key_nego_request_decode_test_miss_message() {
    let _guard = ut_registry_guard!();
    log_i!("sec_key_nego_request_decode_test_miss_message start");

    let mut attribute = Attribute::new();
    attribute.set_u16_slice(AttributeKey::AttrKaAlgoList, &Vec::new());
    let message = attribute.to_bytes().unwrap();

    let result = SecKeyNegoRequest::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_key_nego_request_decode_test_try_from_bytes_fail() {
    let _guard = ut_registry_guard!();
    log_i!("sec_key_nego_request_decode_test_try_from_bytes_fail start");

    let attribute = Attribute::new();
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecKeyNegoRequest::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

// When every algorithm field (including the KA list) is absent, decoding falls back to the
// legacy hardcoded set; only absent key material fields hard-fail.
#[test]
fn sec_key_nego_request_decode_test_miss_algo_list() {
    let _guard = ut_registry_guard!();
    log_i!("sec_key_nego_request_decode_test_miss_algo_list start");

    let mut attribute = Attribute::new();
    attribute.set_u32(AttributeKey::AttrResultCode, 0);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let decoded = SecKeyNegoRequest::decode(&message, ProcessorType::Default).unwrap();
    assert_eq!(decoded.crypto_algorithms.ka_algorithms, vec![KaAlgoType::X25519 as u16]);
    assert_eq!(decoded.crypto_algorithms.kdf_algorithms, vec![KdfAlgoType::HkdfSha256 as u16]);
    assert_eq!(decoded.crypto_algorithms.aead_algorithms, vec![AeadAlgoType::Aes256Gcm as u16]);
    assert_eq!(decoded.crypto_algorithms.mac_algorithms, vec![MacAlgoType::HmacSha256 as u16]);
    assert!(decoded.binding_signature_algorithm_list.is_empty());
}

#[test]
fn sec_key_nego_reply_decode_test_miss_message() {
    let _guard = ut_registry_guard!();
    log_i!("sec_key_nego_reply_decode_test_miss_message start");

    let mut attribute = Attribute::new();
    attribute.set_u16_slice(AttributeKey::AttrKaAlgoList, &Vec::new());
    let message = attribute.to_bytes().unwrap();

    let result = SecKeyNegoReply::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_key_nego_reply_decode_test_try_from_bytes_fail() {
    let _guard = ut_registry_guard!();
    log_i!("sec_key_nego_reply_decode_test_try_from_bytes_fail start");

    let attribute = Attribute::new();
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecKeyNegoReply::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

// An absent selected KA falls back to the legacy hardcoded X25519; absent challenge/pubkey
// (key/session material) still hard-fails.
#[test]
fn sec_key_nego_reply_decode_test_miss_algorithm() {
    let _guard = ut_registry_guard!();
    log_i!("sec_key_nego_reply_decode_test_miss_algorithm start");

    let mut attribute = Attribute::new();
    attribute.set_u64(AttributeKey::AttrCompanionChallenge, 1);
    attribute.set_u8_slice(AttributeKey::AttrPublicKey, &[1, 2, 3]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let decoded = SecKeyNegoReply::decode(&message, ProcessorType::Default).unwrap();
    assert_eq!(decoded.selected_algorithms.ka_algorithm, KaAlgoType::X25519 as u16);
    assert_eq!(decoded.selected_algorithms.kdf_algorithm, KdfAlgoType::HkdfSha256 as u16);
    assert_eq!(decoded.selected_algorithms.binding_signature_algorithm, None);
    assert_eq!(decoded.challenge, 1);
    assert_eq!(decoded.pub_key, vec![1, 2, 3]);
}

#[test]
fn sec_key_nego_reply_decode_test_miss_challenge() {
    let _guard = ut_registry_guard!();
    log_i!("sec_key_nego_reply_decode_test_miss_challenge start");

    let mut attribute = Attribute::new();
    attribute.set_u16(AttributeKey::AttrKaAlgoList, 0);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecKeyNegoReply::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_key_nego_reply_decode_test_miss_public_key() {
    let _guard = ut_registry_guard!();
    log_i!("sec_key_nego_reply_decode_test_miss_public_key start");

    let mut attribute = Attribute::new();
    attribute.set_u16(AttributeKey::AttrKaAlgoList, 0);
    attribute.set_u64(AttributeKey::AttrHostChallenge, 0);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecKeyNegoReply::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

// Legacy layout (2026-10-14 baseline host): the 0x0301 inner payload carries only the KA list
// (300003 reuses the legacy key); absent KDF/AEAD/MAC lists default to the legacy hardcoded
// algorithms and an absent binding-signature list stays empty (AGENTS.md rules 1/2).
#[test]
fn sec_key_nego_request_decode_old_format_legacy_defaults() {
    let _guard = ut_registry_guard!();
    log_i!("sec_key_nego_request_decode_old_format_legacy_defaults start");

    let mut attribute = Attribute::new();
    attribute.set_u16_slice(AttributeKey::AttrKaAlgoList, &[1]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let decoded = SecKeyNegoRequest::decode(&message, ProcessorType::Default).unwrap();
    assert_eq!(decoded.crypto_algorithms.ka_algorithms, vec![1]);
    assert_eq!(decoded.crypto_algorithms.kdf_algorithms, vec![KdfAlgoType::HkdfSha256 as u16]);
    assert_eq!(decoded.crypto_algorithms.aead_algorithms, vec![AeadAlgoType::Aes256Gcm as u16]);
    assert_eq!(decoded.crypto_algorithms.mac_algorithms, vec![MacAlgoType::HmacSha256 as u16]);
    assert!(decoded.binding_signature_algorithm_list.is_empty());
}

// Legacy layout (2026-10-14 baseline companion): the 0x0301 reply carries only the selected
// ka/challenge/pubkey; absent kdf/aead/mac selections default to the legacy hardcoded
// algorithms and an absent binding-signature choice stays None.
#[test]
fn sec_key_nego_reply_decode_old_format_legacy_defaults() {
    let _guard = ut_registry_guard!();
    log_i!("sec_key_nego_reply_decode_old_format_legacy_defaults start");

    let mut attribute = Attribute::new();
    attribute.set_u16(AttributeKey::AttrKaAlgoList, 1);
    attribute.set_u64(AttributeKey::AttrCompanionChallenge, 1);
    attribute.set_u8_slice(AttributeKey::AttrPublicKey, &[1, 2, 3]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let decoded = SecKeyNegoReply::decode(&message, ProcessorType::Default).unwrap();
    assert_eq!(decoded.selected_algorithms.ka_algorithm, 1);
    assert_eq!(decoded.selected_algorithms.kdf_algorithm, KdfAlgoType::HkdfSha256 as u16);
    assert_eq!(decoded.selected_algorithms.aead_algorithm, AeadAlgoType::Aes256Gcm as u16);
    assert_eq!(decoded.selected_algorithms.mac_algorithm, MacAlgoType::HmacSha256 as u16);
    assert_eq!(decoded.selected_algorithms.binding_signature_algorithm, None);
    assert_eq!(decoded.challenge, 1);
    assert_eq!(decoded.pub_key, vec![1, 2, 3]);
}

#[test]
fn sec_key_nego_request_four_role_algorithms_round_trip() {
    let _guard = ut_registry_guard!();
    log_i!("sec_key_nego_request_four_role_algorithms_round_trip start");

    let request = SecKeyNegoRequest {
        crypto_algorithms: CryptoAlgorithms {
            ka_algorithms: vec![1],
            kdf_algorithms: vec![1],
            aead_algorithms: vec![1],
            mac_algorithms: vec![1],
        },
        binding_signature_algorithm_list: Vec::new(),
    };
    let message = request.encode(ProcessorType::Default).unwrap();
    let decoded = SecKeyNegoRequest::decode(&message, ProcessorType::Default).unwrap();
    assert_eq!(decoded.crypto_algorithms.ka_algorithms, vec![1]);
    assert_eq!(decoded.crypto_algorithms.kdf_algorithms, vec![1]);
    assert_eq!(decoded.crypto_algorithms.aead_algorithms, vec![1]);
    assert_eq!(decoded.crypto_algorithms.mac_algorithms, vec![1]);
}

#[test]
fn sec_key_nego_reply_four_role_algorithms_round_trip() {
    let _guard = ut_registry_guard!();
    log_i!("sec_key_nego_reply_four_role_algorithms_round_trip start");

    let reply = SecKeyNegoReply {
        selected_algorithms: SelectedAlgorithms {
            ka_algorithm: 1,
            kdf_algorithm: 1,
            aead_algorithm: 1,
            mac_algorithm: 1,
            binding_signature_algorithm: None,
        },
        challenge: 1,
        pub_key: vec![1, 2, 3],
    };
    let message = reply.encode(ProcessorType::Default).unwrap();
    let decoded = SecKeyNegoReply::decode(&message, ProcessorType::Default).unwrap();
    assert_eq!(decoded.selected_algorithms.ka_algorithm, 1);
    assert_eq!(decoded.selected_algorithms.kdf_algorithm, 1);
    assert_eq!(decoded.selected_algorithms.aead_algorithm, 1);
    assert_eq!(decoded.selected_algorithms.mac_algorithm, 1);
    assert_eq!(decoded.challenge, 1);
    assert_eq!(decoded.pub_key, vec![1, 2, 3]);
}

#[test]
fn sec_binding_request_decode_test_miss_message() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_request_decode_test_miss_message start");

    let mut attribute = Attribute::new();
    attribute.set_u16_slice(AttributeKey::AttrKaAlgoList, &Vec::new());
    let message = attribute.to_bytes().unwrap();

    let result = SecBindingRequest::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_binding_request_decode_test_try_from_bytes_fail() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_request_decode_test_try_from_bytes_fail start");

    let attribute = Attribute::new();
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecBindingRequest::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn sec_binding_request_decode_test_miss_public_key() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_request_decode_test_miss_public_key start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrIv, &[0u8; AES_GCM_IV_SIZE]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecBindingRequest::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_binding_request_decode_test_miss_salt() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_request_decode_test_miss_salt start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrPublicKey, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecBindingRequest::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_binding_request_decode_test_miss_tag() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_request_decode_test_miss_tag start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrPublicKey, &[]);
    attribute.set_u8_slice(AttributeKey::AttrSalt, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecBindingRequest::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_binding_request_decode_test_miss_iv() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_request_decode_test_miss_iv start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrPublicKey, &[]);
    attribute.set_u8_slice(AttributeKey::AttrSalt, &[]);
    attribute.set_u8_slice(AttributeKey::AttrTag, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecBindingRequest::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_binding_request_decode_test_miss_encrypt_data() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_request_decode_test_miss_encrypt_data start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrPublicKey, &[]);
    attribute.set_u8_slice(AttributeKey::AttrSalt, &[]);
    attribute.set_u8_slice(AttributeKey::AttrTag, &[]);
    attribute.set_u8_slice(AttributeKey::AttrIv, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecBindingRequest::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_binding_request_decode_test_salt_try_into_fail() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_request_decode_test_salt_try_into_fail start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrPublicKey, &[]);
    attribute.set_u8_slice(AttributeKey::AttrSalt, &[]);
    attribute.set_u8_slice(AttributeKey::AttrTag, &[]);
    attribute.set_u8_slice(AttributeKey::AttrIv, &[]);
    attribute.set_u8_slice(AttributeKey::AttrEncryptData, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecBindingRequest::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_binding_request_decode_test_tag_try_into_fail() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_request_decode_test_tag_try_into_fail start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrPublicKey, &[]);
    attribute.set_u8_slice(AttributeKey::AttrSalt, &[0u8; HKDF_SALT_SIZE]);
    attribute.set_u8_slice(AttributeKey::AttrTag, &[]);
    attribute.set_u8_slice(AttributeKey::AttrIv, &[]);
    attribute.set_u8_slice(AttributeKey::AttrEncryptData, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecBindingRequest::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_binding_request_decode_test_iv_try_into_fail() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_request_decode_test_iv_try_into_fail start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrPublicKey, &[]);
    attribute.set_u8_slice(AttributeKey::AttrSalt, &[0u8; HKDF_SALT_SIZE]);
    attribute.set_u8_slice(AttributeKey::AttrTag, &[0u8; AES_GCM_TAG_SIZE]);
    attribute.set_u8_slice(AttributeKey::AttrIv, &[]);
    attribute.set_u8_slice(AttributeKey::AttrEncryptData, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecBindingRequest::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_binding_reply_decode_test_miss_message() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_reply_decode_test_miss_message start");

    let mut attribute = Attribute::new();
    attribute.set_u16_slice(AttributeKey::AttrKaAlgoList, &Vec::new());
    let message = attribute.to_bytes().unwrap();

    let result = SecBindingReply::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_binding_reply_decode_test_try_from_bytes_fail() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_reply_decode_test_try_from_bytes_fail start");

    let attribute = Attribute::new();
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecBindingReply::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn sec_binding_reply_decode_test_miss_tag() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_reply_decode_test_miss_tag start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrSalt, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecBindingReply::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_binding_reply_decode_test_miss_iv() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_reply_decode_test_miss_iv start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrTag, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecBindingReply::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_binding_reply_decode_test_miss_encrypt_data() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_reply_decode_test_miss_encrypt_data start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrTag, &[]);
    attribute.set_u8_slice(AttributeKey::AttrIv, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecBindingReply::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_binding_reply_decode_test_tag_try_into_fail() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_reply_decode_test_tag_try_into_fail start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrTag, &[]);
    attribute.set_u8_slice(AttributeKey::AttrIv, &[]);
    attribute.set_u8_slice(AttributeKey::AttrEncryptData, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecBindingReply::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_binding_reply_decode_test_iv_try_into_fail() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_reply_decode_test_iv_try_into_fail start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrTag, &[0u8; AES_GCM_TAG_SIZE]);
    attribute.set_u8_slice(AttributeKey::AttrIv, &[]);
    attribute.set_u8_slice(AttributeKey::AttrEncryptData, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecBindingReply::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_key_nego_request_binding_signature_list_roundtrip_test() {
    let _guard = ut_registry_guard!();
    log_i!("sec_key_nego_request_binding_signature_list_roundtrip_test start");

    let request = SecKeyNegoRequest {
        crypto_algorithms: CryptoAlgorithms {
            ka_algorithms: vec![1],
            kdf_algorithms: vec![2],
            aead_algorithms: vec![3],
            mac_algorithms: vec![4],
        },
        binding_signature_algorithm_list: vec![1, 2],
    };
    let message = request.encode(ProcessorType::Default).unwrap();
    let decoded = SecKeyNegoRequest::decode(&message, ProcessorType::Default).unwrap();
    assert_eq!(decoded.crypto_algorithms.ka_algorithms, vec![1]);
    assert_eq!(decoded.binding_signature_algorithm_list, vec![1, 2]);
}

#[test]
fn sec_key_nego_request_no_binding_signature_list_v1_test() {
    let _guard = ut_registry_guard!();
    log_i!("sec_key_nego_request_no_binding_signature_list_v1_test start");

    // A V1 host sends no binding-signature list; absence decodes to empty.
    let request = SecKeyNegoRequest {
        crypto_algorithms: CryptoAlgorithms {
            ka_algorithms: vec![1],
            kdf_algorithms: vec![2],
            aead_algorithms: vec![3],
            mac_algorithms: vec![4],
        },
        binding_signature_algorithm_list: Vec::new(),
    };
    let message = request.encode(ProcessorType::Default).unwrap();
    let decoded = SecKeyNegoRequest::decode(&message, ProcessorType::Default).unwrap();
    assert!(decoded.binding_signature_algorithm_list.is_empty());
}

#[test]
fn sec_key_nego_reply_binding_signature_selection_roundtrip_test() {
    let _guard = ut_registry_guard!();
    log_i!("sec_key_nego_reply_binding_signature_selection_roundtrip_test start");

    // The reply carries the companion's selection (request list / reply selected value on the
    // same key, like the four roles); it lands in the fifth field of the decoded struct.
    let reply = SecKeyNegoReply {
        selected_algorithms: SelectedAlgorithms { ka_algorithm: 1, kdf_algorithm: 1, aead_algorithm: 1, mac_algorithm: 1, binding_signature_algorithm: Some(P256) },
        challenge: 7,
        pub_key: vec![1u8, 2, 3],
    };
    let message = reply.encode(ProcessorType::Default).unwrap();
    let decoded = SecKeyNegoReply::decode(&message, ProcessorType::Default).unwrap();
    assert_eq!(decoded.challenge, 7);
    assert_eq!(decoded.selected_algorithms.binding_signature_algorithm, Some(P256));
}

#[test]
fn sec_key_nego_reply_no_binding_signature_v1_test() {
    let _guard = ut_registry_guard!();
    log_i!("sec_key_nego_reply_no_binding_signature_v1_test start");

    // A V1 companion attaches no binding-signature attribute; absence decodes to None (an
    // enabled host rejects None as a stripped-reply downgrade). An explicit wire 0 stays
    // distinguishable from absence: it decodes to Some(0), which the membership validation
    // rejects (0 is never a table member).
    let reply = SecKeyNegoReply {
        selected_algorithms: SelectedAlgorithms { ka_algorithm: 1, kdf_algorithm: 1, aead_algorithm: 1, mac_algorithm: 1, binding_signature_algorithm: None },
        challenge: 7,
        pub_key: vec![1u8, 2, 3],
    };
    let message = reply.encode(ProcessorType::Default).unwrap();
    let attribute = Attribute::try_from_bytes(&message).unwrap();
    let inner = Attribute::try_from_bytes(attribute.get_u8_slice(AttributeKey::AttrMessage).unwrap()).unwrap();
    assert!(inner.get_u16(AttributeKey::AttrBindingSignatureAlgoList).is_err());
    let decoded = SecKeyNegoReply::decode(&message, ProcessorType::Default).unwrap();
    assert_eq!(decoded.selected_algorithms.binding_signature_algorithm, None);

    // An explicit wire 0 stays distinguishable from absence: it decodes to Some(0), which the
    // membership validation rejects (0 is never a table member).
    let reply = SecKeyNegoReply {
        selected_algorithms: SelectedAlgorithms { ka_algorithm: 1, kdf_algorithm: 1, aead_algorithm: 1, mac_algorithm: 1, binding_signature_algorithm: Some(0) },
        challenge: 7,
        pub_key: vec![1u8, 2, 3],
    };
    let message = reply.encode(ProcessorType::Default).unwrap();
    let attribute = Attribute::try_from_bytes(&message).unwrap();
    let inner = Attribute::try_from_bytes(attribute.get_u8_slice(AttributeKey::AttrMessage).unwrap()).unwrap();
    assert_eq!(inner.get_u16(AttributeKey::AttrBindingSignatureAlgoList).unwrap(), 0);
    let decoded = SecKeyNegoReply::decode(&message, ProcessorType::Default).unwrap();
    assert_eq!(decoded.selected_algorithms.binding_signature_algorithm, Some(0));
}

// The binding-signature restatement of the binding reply is optional: a None selection (V1)
// encodes without the key and decodes back to None; a carried selection round-trips.
#[test]
fn sec_binding_reply_info_binding_signature_round_trip() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_reply_info_binding_signature_round_trip start");

    let make_info = |binding_signature_algorithm: Option<u16>| SecBindingReplyInfo {
        device_id: "device".to_string(),
        user_key: UserKey { user_id: 100, sub_profile_id: 0 },
        esl: 0,
        track_ability_level: 0,
        challenge: 42,
        companion_protocol_list: vec![1],
        companion_capability_list: vec![1],
        selected_algorithms: SelectedAlgorithms { ka_algorithm: 1, kdf_algorithm: 1, aead_algorithm: 1, mac_algorithm: 1, binding_signature_algorithm },
        companion_supported_algorithms: CryptoAlgorithms {
            ka_algorithms: vec![1],
            kdf_algorithms: vec![1],
            aead_algorithms: vec![1],
            mac_algorithms: vec![1],
        },
    };

    // Legacy format: None selection (V1) puts no AttrBindingSignatureAlgoId on the wire.
    let message = make_info(None).encode().unwrap();
    let attribute = Attribute::try_from_bytes(&message).unwrap();
    assert!(attribute.get_u16(AttributeKey::AttrBindingSignatureAlgoId).is_err());
    let decoded = SecBindingReplyInfo::decode(&message).unwrap();
    assert_eq!(*decoded, make_info(None));

    // A carried selection round-trips like the four roles.
    let message = make_info(Some(P256)).encode().unwrap();
    let attribute = Attribute::try_from_bytes(&message).unwrap();
    assert_eq!(attribute.get_u16(AttributeKey::AttrBindingSignatureAlgoId).unwrap(), P256);
    let decoded = SecBindingReplyInfo::decode(&message).unwrap();
    assert_eq!(*decoded, make_info(Some(P256)));
}

#[test]
fn sec_binding_reply_info_capability_list_round_trip() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_reply_info_capability_list_round_trip start");

    let make_info = |companion_capability_list: Vec<u16>| {
        crate::request::enroll::enroll_message::SecBindingReplyInfo {
            device_id: crate::String::from("device"),
            user_key: crate::traits::db_manager::UserKey { user_id: 1, sub_profile_id: 0 },
            esl: 3,
            track_ability_level: 4,
            challenge: 5,
            companion_protocol_list: vec![1],
            companion_capability_list,
            selected_algorithms: crate::common::algorithm::SelectedAlgorithms {
                ka_algorithm: 1,
                kdf_algorithm: 1,
                aead_algorithm: 1,
                mac_algorithm: 1,
                binding_signature_algorithm: None,
            },
            companion_supported_algorithms: crate::common::algorithm::CryptoAlgorithms {
                ka_algorithms: vec![1],
                kdf_algorithms: vec![1],
                aead_algorithms: vec![1],
                mac_algorithms: vec![1],
            },
        }
    };

    let encoded = make_info(vec![]).encode().unwrap();
    let decoded = crate::request::enroll::enroll_message::SecBindingReplyInfo::decode(&encoded).unwrap();
    assert_eq!(decoded.companion_capability_list, vec![]);
    assert_eq!(decoded.selected_algorithms, crate::common::algorithm::SelectedAlgorithms {
        ka_algorithm: 1,
        kdf_algorithm: 1,
        aead_algorithm: 1,
        mac_algorithm: 1,
        binding_signature_algorithm: None,
    });

    let encoded = make_info(vec![2, 1, 2]).encode().unwrap();
    let decoded = crate::request::enroll::enroll_message::SecBindingReplyInfo::decode(&encoded).unwrap();
    assert_eq!(decoded.companion_capability_list, vec![2, 1, 2]);

    // Capability present, confirmation keys omitted: the legacy (2026-10-14 baseline) format
    // decodes with the legacy hardcoded algorithm set as defaults.
    let mut attribute = crate::utils::Attribute::new();
    attribute.set_string(crate::utils::AttributeKey::AttrDeviceId, crate::String::from("device"));
    attribute.set_i32(crate::utils::AttributeKey::AttrUserId, 1);
    attribute.set_i32(crate::utils::AttributeKey::AttrSubProfileId, 0);
    attribute.set_i32(crate::utils::AttributeKey::AttrEsl, 3);
    attribute.set_i32(crate::utils::AttributeKey::AttrTrackAbilityLevel, 4);
    attribute.set_u64(crate::utils::AttributeKey::AttrHostChallenge, 5);
    attribute.set_u16_slice(crate::utils::AttributeKey::AttrProtocolList, &[1]);
    attribute.set_u16_slice(crate::utils::AttributeKey::AttrCapabilityList, &[1]);
    let decoded = crate::request::enroll::enroll_message::SecBindingReplyInfo::decode(
        attribute.to_bytes().unwrap().as_slice()).unwrap();
    assert_eq!(decoded.selected_algorithms, crate::common::algorithm::SelectedAlgorithms {
        ka_algorithm: 1,
        kdf_algorithm: 1,
        aead_algorithm: 1,
        mac_algorithm: 1,
        binding_signature_algorithm: None,
    });
    assert_eq!(decoded.companion_supported_algorithms, crate::common::algorithm::CryptoAlgorithms {
        ka_algorithms: vec![1],
        kdf_algorithms: vec![1],
        aead_algorithms: vec![1],
        mac_algorithms: vec![1],
    });

    // Capability omitted: still fails to decode.
    let mut attribute = crate::utils::Attribute::new();
    attribute.set_string(crate::utils::AttributeKey::AttrDeviceId, crate::String::from("device"));
    attribute.set_i32(crate::utils::AttributeKey::AttrUserId, 1);
    attribute.set_i32(crate::utils::AttributeKey::AttrSubProfileId, 0);
    attribute.set_i32(crate::utils::AttributeKey::AttrEsl, 3);
    attribute.set_i32(crate::utils::AttributeKey::AttrTrackAbilityLevel, 4);
    attribute.set_u64(crate::utils::AttributeKey::AttrHostChallenge, 5);
    attribute.set_u16_slice(crate::utils::AttributeKey::AttrProtocolList, &[1]);
    let result = crate::request::enroll::enroll_message::SecBindingReplyInfo::decode(
        attribute.to_bytes().unwrap().as_slice());
    assert_eq!(result, Err(crate::common::constants::ErrorCode::GeneralError));
}

// The algorithm restatement and support lists are optional (new fields of the 2026-11 format):
// the legacy 2026-10-14 baseline inner carries none of them and decodes with the legacy
// hardcoded algorithm set as defaults (AGENTS rule 12: old-format decode case).
#[test]
fn sec_binding_reply_info_old_format_algorithm_fields_optional() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_reply_info_old_format_algorithm_fields_optional start");

    let mut attribute = Attribute::new();
    attribute.set_string(AttributeKey::AttrDeviceId, crate::String::from("device"));
    attribute.set_i32(AttributeKey::AttrUserId, 1);
    attribute.set_i32(AttributeKey::AttrSubProfileId, 0);
    attribute.set_i32(AttributeKey::AttrEsl, 3);
    attribute.set_i32(AttributeKey::AttrTrackAbilityLevel, 4);
    attribute.set_u64(AttributeKey::AttrHostChallenge, 5);
    attribute.set_u16_slice(AttributeKey::AttrProtocolList, &[1]);
    attribute.set_u16_slice(AttributeKey::AttrCapabilityList, &[1]);
    let decoded = crate::request::enroll::enroll_message::SecBindingReplyInfo::decode(
        attribute.to_bytes().unwrap().as_slice()).unwrap();
    assert_eq!(decoded.selected_algorithms, crate::common::algorithm::SelectedAlgorithms {
        ka_algorithm: 1,
        kdf_algorithm: 1,
        aead_algorithm: 1,
        mac_algorithm: 1,
        binding_signature_algorithm: None,
    });
    assert_eq!(decoded.companion_supported_algorithms, crate::common::algorithm::CryptoAlgorithms {
        ka_algorithms: vec![1],
        kdf_algorithms: vec![1],
        aead_algorithms: vec![1],
        mac_algorithms: vec![1],
    });
}

// Optional fields fall back to legacy defaults only when ABSENT: a present attribute with a
// malformed length must fail the decode instead of silently restoring the old value.
#[test]
fn sec_binding_reply_info_selected_algorithm_present_with_wrong_length_fails() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_reply_info_selected_algorithm_present_with_wrong_length_fails start");

    let mut attribute = Attribute::new();
    attribute.set_string(AttributeKey::AttrDeviceId, crate::String::from("device"));
    attribute.set_i32(AttributeKey::AttrUserId, 1);
    attribute.set_i32(AttributeKey::AttrSubProfileId, 0);
    attribute.set_i32(AttributeKey::AttrEsl, 3);
    attribute.set_i32(AttributeKey::AttrTrackAbilityLevel, 4);
    attribute.set_u64(AttributeKey::AttrHostChallenge, 5);
    attribute.set_u16_slice(AttributeKey::AttrProtocolList, &[1]);
    attribute.set_u16_slice(AttributeKey::AttrCapabilityList, &[1]);
    // Odd-length buffer cannot be a u16.
    attribute.set_u8_slice(AttributeKey::AttrKaAlgoList, &[1u8, 2u8, 3u8]);
    let result = crate::request::enroll::enroll_message::SecBindingReplyInfo::decode(
        attribute.to_bytes().unwrap().as_slice());
    assert!(result.is_err());
}

#[test]
fn sec_binding_reply_info_support_list_present_with_wrong_length_fails() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_reply_info_support_list_present_with_wrong_length_fails start");

    let mut attribute = Attribute::new();
    attribute.set_string(AttributeKey::AttrDeviceId, crate::String::from("device"));
    attribute.set_i32(AttributeKey::AttrUserId, 1);
    attribute.set_i32(AttributeKey::AttrSubProfileId, 0);
    attribute.set_i32(AttributeKey::AttrEsl, 3);
    attribute.set_i32(AttributeKey::AttrTrackAbilityLevel, 4);
    attribute.set_u64(AttributeKey::AttrHostChallenge, 5);
    attribute.set_u16_slice(AttributeKey::AttrProtocolList, &[1]);
    attribute.set_u16_slice(AttributeKey::AttrCapabilityList, &[1]);
    attribute.set_u8_slice(AttributeKey::AttrKdfAlgoSupportList, &[9u8]);
    let result = crate::request::enroll::enroll_message::SecBindingReplyInfo::decode(
        attribute.to_bytes().unwrap().as_slice());
    assert!(result.is_err());
}

// The binding signature algorithm id keeps the absent-vs-explicit-zero distinction on the wire.
#[test]
fn sec_binding_reply_info_binding_signature_absent_vs_explicit_zero() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_reply_info_binding_signature_absent_vs_explicit_zero start");

    let make_message = |algo: Option<u16>| {
        let mut attribute = Attribute::new();
        attribute.set_string(AttributeKey::AttrDeviceId, crate::String::from("device"));
        attribute.set_i32(AttributeKey::AttrUserId, 1);
        attribute.set_i32(AttributeKey::AttrSubProfileId, 0);
        attribute.set_i32(AttributeKey::AttrEsl, 3);
        attribute.set_i32(AttributeKey::AttrTrackAbilityLevel, 4);
        attribute.set_u64(AttributeKey::AttrHostChallenge, 5);
        attribute.set_u16_slice(AttributeKey::AttrProtocolList, &[1]);
        attribute.set_u16_slice(AttributeKey::AttrCapabilityList, &[1]);
        if let Some(algo) = algo {
            attribute.set_u16(AttributeKey::AttrBindingSignatureAlgoId, algo);
        }
        attribute.to_bytes().unwrap()
    };

    let decoded =
        crate::request::enroll::enroll_message::SecBindingReplyInfo::decode(make_message(None).as_slice())
            .unwrap();
    assert_eq!(decoded.selected_algorithms.binding_signature_algorithm, None);

    let decoded =
        crate::request::enroll::enroll_message::SecBindingReplyInfo::decode(make_message(Some(0)).as_slice())
            .unwrap();
    assert_eq!(decoded.selected_algorithms.binding_signature_algorithm, Some(0));
}
