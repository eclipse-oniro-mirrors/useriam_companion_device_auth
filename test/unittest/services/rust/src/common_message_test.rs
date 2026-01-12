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
use crate::request::jobs::common_message::{SecCommonRequest, SecCommonReply, SecIssueToken};
use crate::traits::crypto_engine::{CryptoEngineRegistry, KeyPair, MockCryptoEngine};
use crate::traits::misc_manager::{MiscManagerRegistry, MockMiscManager};
use crate::ut_registry_guard;
use crate::utils::message_codec::{MessageCodec, MessageSignParam};
use crate::utils::{Attribute, AttributeKey};
use std::boxed::Box;

#[test]
fn sec_common_request_decode_test_miss_message() {
    let _guard = ut_registry_guard!();
    log_i!("sec_common_request_decode_test_miss_message start");

    let mut attribute = Attribute::new();
    attribute.set_u16_slice(AttributeKey::AttrAlgoList, &Vec::new());
    let message = attribute.to_bytes().unwrap();

    let result = SecCommonRequest::decode(&message, DeviceType::None);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_common_request_decode_test_try_from_bytes_fail() {
    let _guard = ut_registry_guard!();
    log_i!("sec_common_request_decode_test_try_from_bytes_fail start");

    let attribute = Attribute::new();
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecCommonRequest::decode(&message, DeviceType::None);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn sec_common_request_decode_test_miss_salt() {
    let _guard = ut_registry_guard!();
    log_i!("sec_common_request_decode_test_miss_salt start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrPublicKey, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecCommonRequest::decode(&message, DeviceType::None);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_common_request_decode_test_miss_tag() {
    let _guard = ut_registry_guard!();
    log_i!("sec_common_request_decode_test_miss_tag start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrSalt, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecCommonRequest::decode(&message, DeviceType::None);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_common_request_decode_test_miss_iv() {
    let _guard = ut_registry_guard!();
    log_i!("sec_common_request_decode_test_miss_iv start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrSalt, &[]);
    attribute.set_u8_slice(AttributeKey::AttrTag, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecCommonRequest::decode(&message, DeviceType::None);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_common_request_decode_test_miss_encrypt_data() {
    let _guard = ut_registry_guard!();
    log_i!("sec_common_request_decode_test_miss_encrypt_data start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrSalt, &[]);
    attribute.set_u8_slice(AttributeKey::AttrTag, &[]);
    attribute.set_u8_slice(AttributeKey::AttrIv, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecCommonRequest::decode(&message, DeviceType::None);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_common_request_decode_test_salt_try_into_fail() {
    let _guard = ut_registry_guard!();
    log_i!("sec_common_request_decode_test_salt_try_into_fail start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrSalt, &[]);
    attribute.set_u8_slice(AttributeKey::AttrTag, &[]);
    attribute.set_u8_slice(AttributeKey::AttrIv, &[]);
    attribute.set_u8_slice(AttributeKey::AttrEncryptData, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecCommonRequest::decode(&message, DeviceType::None);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_common_request_decode_test_tag_try_into_fail() {
    let _guard = ut_registry_guard!();
    log_i!("sec_common_request_decode_test_tag_try_into_fail start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrSalt, &[0u8; HKDF_SALT_SIZE]);
    attribute.set_u8_slice(AttributeKey::AttrTag, &[]);
    attribute.set_u8_slice(AttributeKey::AttrIv, &[]);
    attribute.set_u8_slice(AttributeKey::AttrEncryptData, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecCommonRequest::decode(&message, DeviceType::None);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_common_request_decode_test_iv_try_into_fail() {
    let _guard = ut_registry_guard!();
    log_i!("sec_common_request_decode_test_iv_try_into_fail start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrSalt, &[0u8; HKDF_SALT_SIZE]);
    attribute.set_u8_slice(AttributeKey::AttrTag, &[0u8; AES_GCM_TAG_SIZE]);
    attribute.set_u8_slice(AttributeKey::AttrIv, &[]);
    attribute.set_u8_slice(AttributeKey::AttrEncryptData, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecCommonRequest::decode(&message, DeviceType::None);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_common_reply_decode_test_miss_message() {
    let _guard = ut_registry_guard!();
    log_i!("sec_common_reply_decode_test_miss_message start");

    let mut attribute = Attribute::new();
    attribute.set_u16_slice(AttributeKey::AttrAlgoList, &Vec::new());
    let message = attribute.to_bytes().unwrap();

    let result = SecCommonReply::decode(&message, DeviceType::None);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_common_reply_decode_test_try_from_bytes_fail() {
    let _guard = ut_registry_guard!();
    log_i!("sec_common_reply_decode_test_try_from_bytes_fail start");

    let attribute = Attribute::new();
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecCommonReply::decode(&message, DeviceType::None);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn sec_common_reply_decode_test_miss_tag() {
    let _guard = ut_registry_guard!();
    log_i!("sec_common_reply_decode_test_miss_tag start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrSalt, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecCommonReply::decode(&message, DeviceType::None);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_common_reply_decode_test_miss_iv() {
    let _guard = ut_registry_guard!();
    log_i!("sec_common_reply_decode_test_miss_iv start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrTag, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecCommonReply::decode(&message, DeviceType::None);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_common_reply_decode_test_miss_encrypt_data() {
    let _guard = ut_registry_guard!();
    log_i!("sec_common_reply_decode_test_miss_encrypt_data start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrTag, &[]);
    attribute.set_u8_slice(AttributeKey::AttrIv, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecCommonReply::decode(&message, DeviceType::None);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_common_reply_decode_test_tag_try_into_fail() {
    let _guard = ut_registry_guard!();
    log_i!("sec_common_reply_decode_test_tag_try_into_fail start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrTag, &[]);
    attribute.set_u8_slice(AttributeKey::AttrIv, &[]);
    attribute.set_u8_slice(AttributeKey::AttrEncryptData, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecCommonReply::decode(&message, DeviceType::None);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_common_reply_decode_test_iv_try_into_fail() {
    let _guard = ut_registry_guard!();
    log_i!("sec_common_reply_decode_test_iv_try_into_fail start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrTag, &[0u8; AES_GCM_TAG_SIZE]);
    attribute.set_u8_slice(AttributeKey::AttrIv, &[]);
    attribute.set_u8_slice(AttributeKey::AttrEncryptData, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecCommonReply::decode(&message, DeviceType::None);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}
