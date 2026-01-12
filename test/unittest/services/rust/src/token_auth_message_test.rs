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
use crate::request::token_auth::auth_message::{FwkAuthRequest, FwkAuthReply, SecAuthReply};
use crate::traits::crypto_engine::{CryptoEngineRegistry, KeyPair, MockCryptoEngine};
use crate::traits::misc_manager::{MiscManagerRegistry, MockMiscManager};
use crate::ut_registry_guard;
use crate::utils::message_codec::{MessageCodec, MessageSignParam};
use crate::utils::{Attribute, AttributeKey};
use std::boxed::Box;

fn create_mock_key_pair() -> KeyPair {
    KeyPair { pub_key: vec![1u8, 2, 3], pri_key: vec![4u8, 5, 6] }
}

fn mock_set_misc_manager() {
    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_get_fwk_pub_key().returning(|| Ok(create_mock_key_pair().pub_key.clone()));
    mock_misc_manager.expect_get_local_key_pair().returning(|| Ok(create_mock_key_pair()));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));
}

fn mock_set_crypto_engine() {
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_ed25519_sign().returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
}

#[test]
fn fwk_auth_request_decode_test_invalid_message() {
    let _guard = ut_registry_guard!();
    log_i!("fwk_auth_request_decode_test_invalid_message start");

    mock_set_misc_manager();

    let invalid_message = vec![1, 2, 3];
    let result = FwkAuthRequest::decode(&invalid_message);
    assert_eq!(result, Err(ErrorCode::ReadParcelError));
}

#[test]
fn fwk_auth_request_decode_test_missing_schedule_id() {
    let _guard = ut_registry_guard!();
    log_i!("fwk_auth_request_decode_test_missing_schedule_id start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let mut attribute = Attribute::new();
    attribute.set_i32(AttributeKey::AttrAuthTrustLevel, 30000);
    
    let message_codec = MessageCodec::new(MessageSignParam::Executor(create_mock_key_pair()));
    let fwk_message = message_codec.serialize_attribute(&attribute).unwrap();

    let result = FwkAuthRequest::decode(&fwk_message);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn fwk_auth_request_decode_test_missing_template_id_list() {
    let _guard = ut_registry_guard!();
    log_i!("fwk_auth_request_decode_test_missing_template_id_list start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let mut attribute = Attribute::new();
    attribute.set_u64(AttributeKey::AttrScheduleId, 1);
    
    let message_codec = MessageCodec::new(MessageSignParam::Executor(create_mock_key_pair()));
    let fwk_message = message_codec.serialize_attribute(&attribute).unwrap();

    let result = FwkAuthRequest::decode(&fwk_message);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn fwk_auth_request_decode_test_missing_atl() {
    let _guard = ut_registry_guard!();
    log_i!("fwk_auth_request_decode_test_missing_schedule_id start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let mut attribute = Attribute::new();
    attribute.set_u64(AttributeKey::AttrScheduleId, 1);
    attribute.set_u64_slice(AttributeKey::AttrTemplateIdList, &[]);
    
    let message_codec = MessageCodec::new(MessageSignParam::Executor(create_mock_key_pair()));
    let fwk_message = message_codec.serialize_attribute(&attribute).unwrap();

    let result = FwkAuthRequest::decode(&fwk_message);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn fwk_auth_reply_encode_test_serialize_attribute_fail() {
    let _guard = ut_registry_guard!();
    log_i!("fwk_auth_reply_encode_test_serialize_attribute_fail start");

    mock_set_misc_manager();

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_ed25519_sign().returning(|_, _| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let reply = FwkAuthReply {
        schedule_id: 1,
        template_id: 123,
        result_code: 0,
        acl: 3,
        pin_sub_type: 1,
        remain_attempts: 5,
        lock_duration: 0,
    };

    let result = reply.encode();
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_auth_reply_decode_test_miss_message() {
    let _guard = ut_registry_guard!();
    log_i!("sec_auth_reply_decode_test_miss_message start");

    let mut attribute = Attribute::new();
    attribute.set_u32(AttributeKey::AttrResultCode, 0);
    let message = attribute.to_bytes().unwrap();

    let result = SecAuthReply::decode(&message, DeviceType::None);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_auth_reply_decode_test_try_from_bytes_fail() {
    let _guard = ut_registry_guard!();
    log_i!("sec_auth_reply_decode_test_try_from_bytes_fail start");

    let attribute = Attribute::new();
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecAuthReply::decode(&message, DeviceType::None);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn sec_auth_reply_decode_test_miss_hmac() {
    let _guard = ut_registry_guard!();
    log_i!("sec_auth_reply_decode_test_miss_hmac start");

    let mut attribute = Attribute::new();
    attribute.set_u32(AttributeKey::AttrResultCode, 0);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecAuthReply::decode(&message, DeviceType::None);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}
