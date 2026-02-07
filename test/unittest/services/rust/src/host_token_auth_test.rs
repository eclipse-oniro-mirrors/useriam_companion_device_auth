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
use crate::entry::companion_device_auth_ffi::{
    DataArray1024Ffi, HostBeginTokenAuthInputFfi, HostBeginTokenAuthOutputFfi, HostEndTokenAuthInputFfi,
    HostEndTokenAuthOutputFfi,
};
use crate::log_i;
use crate::request::token_auth::host_token_auth::{HostTokenAuthRequest, TOKEN_VALID_PERIOD};
use crate::request::token_auth::token_auth_message::SecAuthReply;
use crate::traits::crypto_engine::{CryptoEngineRegistry, KeyPair, MockCryptoEngine};
use crate::traits::db_manager::{CompanionDeviceInfo, CompanionDeviceSk, CompanionTokenInfo, DeviceKey, UserInfo};
use crate::traits::host_db_manager::{HostDbManagerRegistry, MockHostDbManager};
use crate::traits::misc_manager::{MiscManagerRegistry, MockMiscManager};
use crate::traits::request_manager::{Request, RequestParam};
use crate::traits::time_keeper::{MockTimeKeeper, TimeKeeperRegistry};
use crate::ut_registry_guard;
use crate::utils::message_codec::{MessageCodec, MessageSignParam};
use crate::utils::{Attribute, AttributeKey};
use std::boxed::Box;

fn create_mock_key_pair() -> KeyPair {
    KeyPair { pub_key: vec![1u8, 2, 3], pri_key: vec![4u8, 5, 6] }
}

fn create_valid_fwk_auth_request(schedule_id: u64, template_ids: &[u64], atl: i32) -> Vec<u8> {
    let mut attribute = Attribute::new();
    attribute.set_u64(AttributeKey::AttrScheduleId, schedule_id);
    attribute.set_u64_slice(AttributeKey::AttrTemplateIdList, template_ids);
    attribute.set_i32(AttributeKey::AttrAuthTrustLevel, atl);

    let message_codec = MessageCodec::new(MessageSignParam::Executor(create_mock_key_pair()));
    message_codec.serialize_attribute(&attribute).unwrap()
}

fn create_valid_auth_reply_message(hmac: &[u8]) -> Vec<u8> {
    let reply = SecAuthReply { hmac: hmac.to_vec() };
    reply.encode(DeviceType::Default).unwrap()
}

fn create_mock_companion_device_info(template_id: u64, secure_protocol_id: u16) -> CompanionDeviceInfo {
    CompanionDeviceInfo {
        template_id,
        device_key: DeviceKey { device_id: String::from("test_device"), device_id_type: 1, user_id: 100 },
        user_info: UserInfo { user_id: 100, user_type: 0 },
        added_time: 123456,
        secure_protocol_id,
        is_valid: true,
        capability_list: vec![1, 2, 3],
    }
}

fn create_mock_companion_token_info(added_time: u64) -> CompanionTokenInfo {
    CompanionTokenInfo {
        template_id: 123,
        device_type: DeviceType::Default,
        token: [1u8; TOKEN_KEY_LEN],
        atl: AuthTrustLevel::Atl3,
        added_time,
    }
}

fn mock_set_crypto_engine() {
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
}

fn mock_set_misc_manager() {
    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager
        .expect_get_fwk_pub_key()
        .returning(|| Ok(create_mock_key_pair().pub_key.clone()));
    mock_misc_manager
        .expect_get_local_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));
}

fn mock_set_time_keeper(time: u64) {
    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(move || Ok(time));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));
}

#[test]
fn host_token_auth_request_new_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_token_auth_request_new_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let result = HostTokenAuthRequest::new(&input);
    assert!(result.is_ok());

    let request = result.unwrap();
    assert_eq!(request.get_request_id(), 1);
    assert_eq!(request.auth_param.schedule_id, 1);
    assert_eq!(request.auth_param.template_id, 123);
    assert_eq!(request.atl, AuthTrustLevel::Atl0);
    assert_eq!(request.acl, AuthCapabilityLevel::Acl0);
    assert_eq!(request.device_type, DeviceType::Default);
}

#[test]
fn host_token_auth_request_new_test_secure_random_salt_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_token_auth_request_new_test_secure_random_salt_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_secure_random()
        .returning(|_| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let result = HostTokenAuthRequest::new(&input);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_token_auth_request_prepare_test_not_implemented() {
    let _guard = ut_registry_guard!();
    log_i!("host_token_auth_request_prepare_test_not_implemented start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let mut request = HostTokenAuthRequest::new(&input).unwrap();

    let mut output = HostBeginTokenAuthOutputFfi::default();
    let param = RequestParam::HostTokenAuthBegin(&input, &mut output);
    let result = request.prepare(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_token_auth_request_begin_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("host_token_auth_request_begin_test_wrong_input_type start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let mut request = HostTokenAuthRequest::new(&input).unwrap();

    let wrong_input = HostEndTokenAuthInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };

    let mut output = HostEndTokenAuthOutputFfi::default();
    let param = RequestParam::HostTokenAuthEnd(&wrong_input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn host_token_auth_request_begin_test_schedule_id_mismatch() {
    let _guard = ut_registry_guard!();
    log_i!("host_token_auth_request_begin_test_schedule_id_mismatch start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123, 1)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let fwk_message = create_valid_fwk_auth_request(999, &[123u64], AuthTrustLevel::Atl3 as i32);
    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
    };

    let mut request = HostTokenAuthRequest::new(&input).unwrap();

    let mut output = HostBeginTokenAuthOutputFfi::default();
    let param = RequestParam::HostTokenAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_token_auth_request_begin_test_template_id_not_found() {
    let _guard = ut_registry_guard!();
    log_i!("host_token_auth_request_begin_test_template_id_not_found start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123, 1)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let fwk_message = create_valid_fwk_auth_request(1, &[456u64], AuthTrustLevel::Atl3 as i32);
    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
    };

    let mut request = HostTokenAuthRequest::new(&input).unwrap();

    let mut output = HostBeginTokenAuthOutputFfi::default();
    let param = RequestParam::HostTokenAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_token_auth_request_begin_test_atl_try_from_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_token_auth_request_begin_test_atl_try_from_fail start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123, 1)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let fwk_message = create_valid_fwk_auth_request(1, &[123u64], 99999);
    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
    };

    let mut request = HostTokenAuthRequest::new(&input).unwrap();

    let mut output = HostBeginTokenAuthOutputFfi::default();
    let param = RequestParam::HostTokenAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_token_auth_request_begin_test_get_device_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_token_auth_request_begin_test_get_device_fail start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123, 1)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_get_device().returning(|| Err(ErrorCode::NotFound));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let fwk_message = create_valid_fwk_auth_request(1, &[123u64], AuthTrustLevel::Atl3 as i32);
    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
    };

    let mut request = HostTokenAuthRequest::new(&input).unwrap();

    let mut output = HostBeginTokenAuthOutputFfi::default();
    let param = RequestParam::HostTokenAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn host_token_auth_request_begin_test_secure_protocol_id_not_support() {
    let _guard = ut_registry_guard!();
    log_i!("host_token_auth_request_begin_test_secure_protocol_id_not_support start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123, 1)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123, 999)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let fwk_message = create_valid_fwk_auth_request(1, &[123u64], AuthTrustLevel::Atl3 as i32);
    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
    };

    let mut request = HostTokenAuthRequest::new(&input).unwrap();

    let mut output = HostBeginTokenAuthOutputFfi::default();
    let param = RequestParam::HostTokenAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_token_auth_request_begin_test_get_token_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_token_auth_request_begin_test_get_token_fail start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123, 1)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123, 1)));
    mock_host_db_manager.expect_get_token().returning(|| Err(ErrorCode::NotFound));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let fwk_message = create_valid_fwk_auth_request(1, &[123u64], AuthTrustLevel::Atl3 as i32);
    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
    };

    let mut request = HostTokenAuthRequest::new(&input).unwrap();

    let mut output = HostBeginTokenAuthOutputFfi::default();
    let param = RequestParam::HostTokenAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn host_token_auth_request_begin_test_get_rtc_time_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_token_auth_request_begin_test_get_rtc_time_fail start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123, 1)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123, 1)));
    mock_host_db_manager
        .expect_get_token()
        .returning(|| Ok(create_mock_companion_token_info(1000)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper
        .expect_get_rtc_time()
        .returning(|| Err(ErrorCode::GeneralError));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let fwk_message = create_valid_fwk_auth_request(1, &[123u64], AuthTrustLevel::Atl3 as i32);
    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
    };

    let mut request = HostTokenAuthRequest::new(&input).unwrap();

    let mut output = HostBeginTokenAuthOutputFfi::default();
    let param = RequestParam::HostTokenAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_token_auth_request_begin_test_token_time_bad() {
    let _guard = ut_registry_guard!();
    log_i!("host_token_auth_request_begin_test_token_time_bad start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123, 1)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));
    mock_set_time_keeper(1000);

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123, 1)));
    mock_host_db_manager
        .expect_get_token()
        .returning(|| Ok(create_mock_companion_token_info(10000)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let fwk_message = create_valid_fwk_auth_request(1, &[123u64], AuthTrustLevel::Atl3 as i32);
    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
    };

    let mut request = HostTokenAuthRequest::new(&input).unwrap();

    let mut output = HostBeginTokenAuthOutputFfi::default();
    let param = RequestParam::HostTokenAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_token_auth_request_begin_test_token_expired() {
    let _guard = ut_registry_guard!();
    log_i!("host_token_auth_request_begin_test_token_expired start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123, 1)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));
    mock_set_time_keeper(1001 + TOKEN_VALID_PERIOD);

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123, 1)));
    mock_host_db_manager
        .expect_get_token()
        .returning(|| Ok(create_mock_companion_token_info(1000)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let fwk_message = create_valid_fwk_auth_request(1, &[123u64], AuthTrustLevel::Atl3 as i32);
    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
    };

    let mut request = HostTokenAuthRequest::new(&input).unwrap();

    let mut output = HostBeginTokenAuthOutputFfi::default();
    let param = RequestParam::HostTokenAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_token_auth_request_begin_test_get_session_key_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_token_auth_request_begin_test_get_session_key_fail start");

    mock_set_crypto_engine();
    mock_set_misc_manager();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123, 1)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));
    mock_set_time_keeper(2000);

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123, 1)));
    mock_host_db_manager
        .expect_get_token()
        .returning(|| Ok(create_mock_companion_token_info(1000)));
    mock_host_db_manager
        .expect_read_device_sk()
        .returning(|| Err(ErrorCode::NotFound));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let fwk_message = create_valid_fwk_auth_request(1, &[123u64], AuthTrustLevel::Atl3 as i32);
    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
    };

    let mut request = HostTokenAuthRequest::new(&input).unwrap();

    let mut output = HostBeginTokenAuthOutputFfi::default();
    let param = RequestParam::HostTokenAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn host_token_auth_request_begin_test_aes_gcm_encrypt_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_token_auth_request_begin_test_aes_gcm_encrypt_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_encrypt()
        .returning(|_, _| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    mock_set_misc_manager();

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123, 1)));
    mock_host_db_manager
        .expect_get_token()
        .returning(|| Ok(create_mock_companion_token_info(1000)));
    mock_host_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceSk { device_type: DeviceType::Default, sk: [0u8; SHARE_KEY_LEN] }]));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));
    mock_set_time_keeper(2000);

    let fwk_message = create_valid_fwk_auth_request(1, &[123u64], AuthTrustLevel::Atl3 as i32);
    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(fwk_message).unwrap(),
    };

    let mut request = HostTokenAuthRequest::new(&input).unwrap();

    let mut output = HostBeginTokenAuthOutputFfi::default();
    let param = RequestParam::HostTokenAuthBegin(&input, &mut output);
    let result = request.begin(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_token_auth_request_end_test_wrong_input_type() {
    let _guard = ut_registry_guard!();
    log_i!("host_token_auth_request_end_test_wrong_input_type start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let mut request = HostTokenAuthRequest::new(&input).unwrap();

    let mut output = HostBeginTokenAuthOutputFfi::default();
    let param = RequestParam::HostTokenAuthBegin(&input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn host_token_auth_request_end_test_get_token_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_token_auth_request_end_test_get_token_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_get_token().returning(|| Err(ErrorCode::NotFound));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let mut request = HostTokenAuthRequest::new(&input).unwrap();
    request.device_type = DeviceType::Default;

    let hmac = vec![1u8, 2, 3, 4, 5];
    let sec_message = create_valid_auth_reply_message(&hmac);
    let end_input = HostEndTokenAuthInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndTokenAuthOutputFfi::default();
    let param = RequestParam::HostTokenAuthEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_token_auth_request_end_test_hmac_sha256_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_token_auth_request_end_test_hmac_sha256_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_hmac_sha256()
        .returning(|_, _| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_token()
        .returning(|| Ok(create_mock_companion_token_info(1000)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let mut request = HostTokenAuthRequest::new(&input).unwrap();
    request.device_type = DeviceType::Default;

    let hmac = vec![1u8, 2, 3, 4, 5];
    let sec_message = create_valid_auth_reply_message(&hmac);
    let end_input = HostEndTokenAuthInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndTokenAuthOutputFfi::default();
    let param = RequestParam::HostTokenAuthEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_token_auth_request_end_test_hmac_verification_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_token_auth_request_end_test_hmac_verification_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_hmac_sha256()
        .returning(|_, _| Ok(vec![9u8, 9, 9, 9, 9]));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_token()
        .returning(|| Ok(create_mock_companion_token_info(1000)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let mut request = HostTokenAuthRequest::new(&input).unwrap();
    request.device_type = DeviceType::Default;

    let hmac = vec![1u8, 2, 3, 4, 5];
    let sec_message = create_valid_auth_reply_message(&hmac);
    let end_input = HostEndTokenAuthInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndTokenAuthOutputFfi::default();
    let param = RequestParam::HostTokenAuthEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_token_auth_request_end_test_get_local_key_pair_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_token_auth_request_end_test_get_local_key_pair_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_hmac_sha256()
        .returning(|_, _| Ok(vec![1u8, 2, 3, 4, 5]));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_token()
        .returning(|| Ok(create_mock_companion_token_info(1000)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager
        .expect_get_local_key_pair()
        .returning(|| Err(ErrorCode::GeneralError));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };

    let mut request = HostTokenAuthRequest::new(&input).unwrap();
    request.device_type = DeviceType::Default;

    let hmac = vec![1u8, 2, 3, 4, 5];
    let sec_message = create_valid_auth_reply_message(&hmac);
    let end_input = HostEndTokenAuthInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(sec_message).unwrap(),
    };

    let mut output = HostEndTokenAuthOutputFfi::default();
    let param = RequestParam::HostTokenAuthEnd(&end_input, &mut output);
    let result = request.end(param);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}
