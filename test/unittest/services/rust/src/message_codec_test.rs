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

use crate::common::constants::ErrorCode;
use crate::common::types::Udid;
use crate::traits::crypto_engine::{CryptoEngineRegistry, KeyPair};
use crate::utils::attribute::{Attribute, AttributeKey};
use crate::log_i;
use crate::traits::crypto_engine::MockCryptoEngine;
use crate::ut_registry_guard;
use crate::SHA256_DIGEST_SIZE;
use crate::utils::message_codec::{MessageCodec, MessageSignParam};

#[test]
fn serialize_attribute_test() {
    let _guard = ut_registry_guard!();
    log_i!("serialize_attribute_test start");

    let mut attr = Attribute::new();
    attr.set_u32(AttributeKey::AttrData, 1);

    let message_codec_no_sign = MessageCodec::new(MessageSignParam::NoSign);
    assert!(message_codec_no_sign.serialize_attribute(&attr).is_ok());

    let _ = ut_registry_guard!();

    let message_codec_executor = MessageCodec::new(MessageSignParam::Executor(KeyPair {
        pub_key: Vec::<u8>::new(),
        pri_key: Vec::<u8>::new(),
    }));

    let mut mock_crypto_engin = MockCryptoEngine::new();
    mock_crypto_engin
        .expect_ed25519_sign()
        .returning(|_, _| Err(ErrorCode::BadSign));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engin));
    assert_eq!(message_codec_executor.serialize_attribute(&attr), Err(ErrorCode::BadSign));

    mock_crypto_engin = MockCryptoEngine::new();
    mock_crypto_engin.expect_ed25519_sign().returning(|_, _| Ok(Vec::<u8>::new()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engin));
    assert!(message_codec_executor.serialize_attribute(&attr).is_ok());

    let message_codec_fwk = MessageCodec::new(MessageSignParam::Framework(Vec::<u8>::new()));
    assert_eq!(message_codec_fwk.serialize_attribute(&attr), Err(ErrorCode::GeneralError));
}

#[test]
fn deserialize_attribute_test() {
    let _guard = ut_registry_guard!();
    log_i!("deserialize_attribute_test start");

    let mut attr = Attribute::new();

    let message_codec_nosign = MessageCodec::new(MessageSignParam::NoSign);
    assert_eq!(message_codec_nosign.deserialize_attribute(&[]), Err(ErrorCode::BadParam));
    assert_eq!(message_codec_nosign.deserialize_attribute(&attr.to_bytes().unwrap()), Err(ErrorCode::BadParam));
    attr.set_u8_slice(AttributeKey::AttrRoot, &[0u8; 0]);
    assert_eq!(message_codec_nosign.deserialize_attribute(&attr.to_bytes().unwrap()), Err(ErrorCode::BadParam));

    let mut data_and_sign_attr = Attribute::new();
    attr.set_u8_slice(AttributeKey::AttrRoot, &data_and_sign_attr.to_bytes().unwrap());
    assert_eq!(message_codec_nosign.deserialize_attribute(&attr.to_bytes().unwrap()), Err(ErrorCode::BadParam));

    data_and_sign_attr.set_u8_slice(AttributeKey::AttrData, &[0u8; 32]);
    attr.set_u8_slice(AttributeKey::AttrRoot, &data_and_sign_attr.to_bytes().unwrap());
    assert!(message_codec_nosign.deserialize_attribute(&attr.to_bytes().unwrap()).is_ok());

    let _ = ut_registry_guard!();

    let message_codec_executor = MessageCodec::new(MessageSignParam::Executor(KeyPair {
        pub_key: Vec::<u8>::new(),
        pri_key: Vec::<u8>::new(),
    }));
    let message_codec_fwk = MessageCodec::new(MessageSignParam::Framework(Vec::<u8>::new()));
    assert_eq!(
        message_codec_executor.deserialize_attribute(&attr.to_bytes().unwrap()),
        Err(ErrorCode::GeneralError)
    );
    assert_eq!(message_codec_fwk.deserialize_attribute(&attr.to_bytes().unwrap()), Err(ErrorCode::GeneralError));

    data_and_sign_attr.set_u8_slice(AttributeKey::AttrSignature, &[0u8; 32]);
    attr.set_u8_slice(AttributeKey::AttrRoot, &data_and_sign_attr.to_bytes().unwrap());
    let mut mock_crypto_engin = MockCryptoEngine::new();
    mock_crypto_engin
        .expect_ed25519_verify()
        .returning(|_, _| Err(ErrorCode::BadSign));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engin));
    assert_eq!(message_codec_executor.deserialize_attribute(&attr.to_bytes().unwrap()), Err(ErrorCode::BadSign));
    assert_eq!(message_codec_fwk.deserialize_attribute(&attr.to_bytes().unwrap()), Err(ErrorCode::BadSign));

    mock_crypto_engin = MockCryptoEngine::new();
    mock_crypto_engin.expect_ed25519_verify().returning(|_, _| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engin));
    assert!(message_codec_executor.deserialize_attribute(&attr.to_bytes().unwrap()).is_ok());
    assert!(message_codec_fwk.deserialize_attribute(&attr.to_bytes().unwrap()).is_ok());
}