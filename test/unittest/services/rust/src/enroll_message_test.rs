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
use crate::log_i;
use crate::request::enroll::enroll_message::{
    FwkEnrollRequest, SecBindingReply, SecBindingRequest, SecKeyNegoReply, SecKeyNegoRequest,
};
use crate::traits::crypto_engine::{CryptoEngineRegistry, KeyPair, MockCryptoEngine};
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
    mock_misc_manager
        .expect_get_fwk_pub_key()
        .returning(|| Ok(create_mock_key_pair().pub_key.clone()));
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
    mock_misc_manager
        .expect_get_fwk_pub_key()
        .returning(|| Ok(create_mock_key_pair().pub_key.clone()));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
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
    mock_misc_manager
        .expect_get_fwk_pub_key()
        .returning(|| Ok(create_mock_key_pair().pub_key.clone()));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
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
    attribute.set_u16_slice(AttributeKey::AttrAlgoList, &Vec::new());
    let message = attribute.to_bytes().unwrap();

    let result = SecKeyNegoRequest::decode(&message, DeviceType::Default);
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

    let result = SecKeyNegoRequest::decode(&message, DeviceType::Default);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn sec_key_nego_request_decode_test_miss_algo_list() {
    let _guard = ut_registry_guard!();
    log_i!("sec_key_nego_request_decode_test_miss_algo_list start");

    let mut attribute = Attribute::new();
    attribute.set_u32(AttributeKey::AttrResultCode, 0);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecKeyNegoRequest::decode(&message, DeviceType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_key_nego_reply_decode_test_miss_message() {
    let _guard = ut_registry_guard!();
    log_i!("sec_key_nego_reply_decode_test_miss_message start");

    let mut attribute = Attribute::new();
    attribute.set_u16_slice(AttributeKey::AttrAlgoList, &Vec::new());
    let message = attribute.to_bytes().unwrap();

    let result = SecKeyNegoReply::decode(&message, DeviceType::Default);
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

    let result = SecKeyNegoReply::decode(&message, DeviceType::Default);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn sec_key_nego_reply_decode_test_miss_algorithm() {
    let _guard = ut_registry_guard!();
    log_i!("sec_key_nego_reply_decode_test_miss_algorithm start");

    let mut attribute = Attribute::new();
    attribute.set_u32(AttributeKey::AttrResultCode, 0);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecKeyNegoReply::decode(&message, DeviceType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_key_nego_reply_decode_test_miss_challenge() {
    let _guard = ut_registry_guard!();
    log_i!("sec_key_nego_reply_decode_test_miss_challenge start");

    let mut attribute = Attribute::new();
    attribute.set_u16(AttributeKey::AttrAlgoList, 0);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecKeyNegoReply::decode(&message, DeviceType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_key_nego_reply_decode_test_miss_public_key() {
    let _guard = ut_registry_guard!();
    log_i!("sec_key_nego_reply_decode_test_miss_public_key start");

    let mut attribute = Attribute::new();
    attribute.set_u16(AttributeKey::AttrAlgoList, 0);
    attribute.set_u64(AttributeKey::AttrChallenge, 0);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecKeyNegoReply::decode(&message, DeviceType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_binding_request_decode_test_miss_message() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_request_decode_test_miss_message start");

    let mut attribute = Attribute::new();
    attribute.set_u16_slice(AttributeKey::AttrAlgoList, &Vec::new());
    let message = attribute.to_bytes().unwrap();

    let result = SecBindingRequest::decode(&message, DeviceType::Default);
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

    let result = SecBindingRequest::decode(&message, DeviceType::Default);
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

    let result = SecBindingRequest::decode(&message, DeviceType::Default);
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

    let result = SecBindingRequest::decode(&message, DeviceType::Default);
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

    let result = SecBindingRequest::decode(&message, DeviceType::Default);
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

    let result = SecBindingRequest::decode(&message, DeviceType::Default);
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

    let result = SecBindingRequest::decode(&message, DeviceType::Default);
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

    let result = SecBindingRequest::decode(&message, DeviceType::Default);
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

    let result = SecBindingRequest::decode(&message, DeviceType::Default);
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

    let result = SecBindingRequest::decode(&message, DeviceType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_binding_reply_decode_test_miss_message() {
    let _guard = ut_registry_guard!();
    log_i!("sec_binding_reply_decode_test_miss_message start");

    let mut attribute = Attribute::new();
    attribute.set_u16_slice(AttributeKey::AttrAlgoList, &Vec::new());
    let message = attribute.to_bytes().unwrap();

    let result = SecBindingReply::decode(&message, DeviceType::Default);
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

    let result = SecBindingReply::decode(&message, DeviceType::Default);
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

    let result = SecBindingReply::decode(&message, DeviceType::Default);
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

    let result = SecBindingReply::decode(&message, DeviceType::Default);
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

    let result = SecBindingReply::decode(&message, DeviceType::Default);
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

    let result = SecBindingReply::decode(&message, DeviceType::Default);
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

    let result = SecBindingReply::decode(&message, DeviceType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}
