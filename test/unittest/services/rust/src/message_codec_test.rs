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

use rust::common::constants::ErrorCode;
use rust::common::types::Udid;
use rust::traits::crypto_engine::{CryptoEngineRegistry, KeyPair};
use rust::traits::misc_manager::MiscManagerRegistry;
use rust::utils::attribute::{Attribute, AttributeKey};
use rust::Vec;
use rust::{log_i, log_e, p};
use rust::traits::crypto_engine::MockCryptoEngine;
use rust::traits::misc_manager::MockMiscManager;
use rust::ut_registry_guard;
use rust::SHA256_DIGEST_SIZE;
use rust::utils::message_codec;

#[test]
fn serialize_attribute_test() {
    let _guard = ut_registry_guard!();
    log_i!("serialize_attribute_test start");

    let attribute = Attribute::new();
    let message_codec = MessageCodec::new(MessageSignParam::Executor(vec![]));

    assert_eq!(message_codec.serialize_attribute(&attribute), Err(ErrorCode::GeneralError));
}

#[test]
fn deserialize_attribute_test() {
    let _guard = ut_registry_guard!();
    log_i!("deserialize_attribute_test start");

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_get_distribute_key().returning(|_| Ok(vec![]));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_ed25519_sign().returning(|_, _, _| Ok(Vec::new()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _, _| Err(ErrorCode::GeneralError));
    mock_crypto_engine.expect_hmac_sha256().returning(|_, _| Ok(vec![1u8; SHA256_DIGEST_SIZE]));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut attribute = Attribute::new();
    attribute.set_i32(AttributeKey::AttrResult, 1);

    let mut message_codec = MessageCodec::new(MessageSignParam::NoSign);
    let mut message = message_codec.serialize_attribute(&attribute).unwrap();
    assert_eq!(message_codec.deserialize_attribute(message.as_slice()).unwrap(), attribute);

    let key_pair = KeyPair { pub_key: vec![], pri_key: vec![] };
    message_codec = MessageCodec::new(MessageSignParam::Framework(key_pair));
    message = message_codec.serialize_attribute(&attribute).unwrap();
    assert_eq!(message_codec.deserialize_attribute(message.as_slice()), Err(ErrorCode::GeneralError));

    message_codec = MessageCodec::new(MessageSignParam::CrossDevice(Udid([0u8; 64])));
    message = message_codec.serialize_attribute(&attribute).unwrap();

    mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_hmac_sha256().returning(|_, _|  Ok(vec![1u8; 1]));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    assert_eq!(message_codec.deserialize_attribute(message.as_slice()), Err(ErrorCode::BadSign));
}