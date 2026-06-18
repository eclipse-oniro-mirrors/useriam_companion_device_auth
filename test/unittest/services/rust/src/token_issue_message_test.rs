
use crate::traits::log_trace::TestFileId;
const FILE_ID: u16 = TestFileId::TokenIssueMessageTest as u16;
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
use crate::request::token_issue::token_issue_message::{SecIssueTokenReply, SecPreIssueRequest};
use crate::ut_registry_guard;
use crate::utils::{Attribute, AttributeKey};

#[test]
fn sec_pre_issue_request_decode_test_miss_message() {
    let _guard = ut_registry_guard!();
    log_i!("sec_pre_issue_request_decode_test_miss_message start");

    let mut attribute = Attribute::new();
    attribute.set_u32(AttributeKey::AttrResultCode, 0);
    let message = attribute.to_bytes().unwrap();

    let result = SecPreIssueRequest::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_pre_issue_request_decode_test_try_from_bytes_fail() {
    let _guard = ut_registry_guard!();
    log_i!("sec_pre_issue_request_decode_test_try_from_bytes_fail start");

    let attribute = Attribute::new();
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecPreIssueRequest::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn sec_pre_issue_request_decode_test_miss_salt() {
    let _guard = ut_registry_guard!();
    log_i!("sec_pre_issue_request_decode_test_miss_salt start");

    let mut attribute = Attribute::new();
    attribute.set_u32(AttributeKey::AttrResultCode, 0);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecPreIssueRequest::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_pre_issue_request_decode_test_salt_convert_fail() {
    let _guard = ut_registry_guard!();
    log_i!("sec_pre_issue_request_decode_test_salt_convert_fail start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrSalt, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecPreIssueRequest::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_issue_token_reply_decode_test_miss_message() {
    let _guard = ut_registry_guard!();
    log_i!("sec_issue_token_reply_decode_test_miss_message start");

    let mut attribute = Attribute::new();
    attribute.set_u32(AttributeKey::AttrResultCode, 0);
    let message = attribute.to_bytes().unwrap();

    let result = SecIssueTokenReply::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn sec_issue_token_reply_decode_test_try_from_bytes_fail() {
    let _guard = ut_registry_guard!();
    log_i!("sec_issue_token_reply_decode_test_try_from_bytes_fail start");

    let attribute = Attribute::new();
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecIssueTokenReply::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn sec_issue_token_reply_decode_test_miss_result_code() {
    let _guard = ut_registry_guard!();
    log_i!("sec_issue_token_reply_decode_test_miss_result_code start");

    let mut attribute = Attribute::new();
    attribute.set_u8_slice(AttributeKey::AttrSalt, &[]);
    let mut final_attribute = Attribute::new();
    final_attribute.set_u8_slice(AttributeKey::AttrMessage, attribute.to_bytes().unwrap().as_slice());
    let message = final_attribute.to_bytes().unwrap();

    let result = SecIssueTokenReply::decode(&message, ProcessorType::Default);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}
