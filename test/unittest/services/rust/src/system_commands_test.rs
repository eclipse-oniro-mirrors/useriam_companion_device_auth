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

use crate::commands::system_commands::*;
use crate::common::constants::*;
use crate::entry::companion_device_auth_ffi::*;
use crate::impls::default_companion_request_manager::DefaultCompanionRequestManager;
use crate::impls::default_host_request_manager::DefaultHostRequestManager;
use crate::log_i;
use crate::request::delegate_auth::companion_auth::CompanionDelegateAuthRequest;
use crate::request::delegate_auth::host_auth::HostDelegateAuthRequest;
use crate::request::enroll::companion_enroll::CompanionDeviceEnrollRequest;
use crate::request::enroll::enroll_message::{SecBindingRequest, SecKeyNegoReply, SecKeyNegoRequest};
use crate::request::enroll::host_enroll::HostDeviceEnrollRequest;
use crate::request::jobs::common_message::{SecCommonRequest, SecIssueToken};
use crate::request::jobs::token_helper::DeviceTokenInfo;
use crate::request::status_sync::host_sync_status::HostDeviceSyncStatusRequest;
use crate::request::token_auth::auth_message::SecAuthReply;
use crate::request::token_auth::host_auth::HostTokenAuthRequest;
use crate::request::token_issue::companion_issue_token::CompanionDeviceIssueTokenRequest;
use crate::request::token_issue::host_issue_token::HostDeviceIssueTokenRequest;
use crate::request::token_issue::token_issue_message::SecPreIssueRequest;
use crate::request::token_obtain::companion_obtain_token::CompanionDeviceObtainTokenRequest;
use crate::request::token_obtain::host_obtain_token::HostDeviceObtainTokenRequest;
use crate::request::token_obtain::token_obtain_message::SecPreObtainTokenRequest;
use crate::traits::companion_db_manager::{CompanionDbManagerRegistry, MockCompanionDbManager};
use crate::traits::companion_request_manager::{CompanionRequestManagerRegistry, MockCompanionRequestManager};
use crate::traits::crypto_engine::{AesGcmResult, CryptoEngineRegistry, KeyPair, MockCryptoEngine};
use crate::traits::db_manager::{
    CompanionDeviceBaseInfo, CompanionDeviceCapability, CompanionDeviceInfo, CompanionDeviceSk, CompanionTokenInfo,
    DeviceKey, HostDeviceInfo, HostDeviceSk, HostTokenInfo, UserInfo,
};
use crate::traits::host_db_manager::{HostDbManagerRegistry, MockHostDbManager};
use crate::traits::host_request_manager::{HostRequestManagerRegistry, MockHostRequestManager};
use crate::traits::misc_manager::{MiscManagerRegistry, MockMiscManager};
use crate::traits::time_keeper::{MockTimeKeeper, TimeKeeperRegistry};
use crate::ut_registry_guard;
use crate::utils::auth_token::{TokenDataPlain, UserAuthToken, AUTH_TOKEN_CIPHER_LEN};
use crate::utils::message_codec::{MessageCodec, MessageSignParam};
use crate::utils::{Attribute, AttributeKey};
use std::{boxed::Box, string::String, vec::Vec};

fn create_mock_key_pair() -> KeyPair {
    KeyPair { pub_key: vec![1u8, 2, 3], pri_key: vec![4u8, 5, 6] }
}

fn create_mock_companion_device_info(template_id: u64) -> CompanionDeviceInfo {
    CompanionDeviceInfo {
        template_id,
        device_key: DeviceKey { device_id: String::from("test_device"), device_id_type: 1, user_id: 100 },
        user_info: UserInfo { user_id: 100, user_type: 0 },
        added_time: 123456,
        secure_protocol_id: 1,
        is_valid: true,
    }
}

fn create_mock_companion_device_base_info() -> CompanionDeviceBaseInfo {
    CompanionDeviceBaseInfo {
        device_model: String::from("TestModel"),
        device_name: String::from("TestDevice"),
        device_user_name: String::from("TestUser"),
        business_ids: vec![1, 2, 3],
    }
}

fn create_mock_host_device_info(binding_id: i32) -> HostDeviceInfo {
    HostDeviceInfo {
        device_key: DeviceKey { device_id: String::from("host_device"), device_id_type: 1, user_id: 100 },
        binding_id,
        user_info: UserInfo { user_id: 100, user_type: 0 },
        binding_time: 123456,
        last_used_time: 123456,
    }
}

fn create_mock_companion_device_capability() -> CompanionDeviceCapability {
    CompanionDeviceCapability {
        device_type: DeviceType::None,
        esl: ExecutorSecurityLevel::Esl3,
        track_ability_level: 1,
    }
}

fn create_mock_companion_token_info(atl: AuthTrustLevel) -> CompanionTokenInfo {
    CompanionTokenInfo { template_id: 123, device_type: DeviceType::None, token: Vec::new(), atl, added_time: 1000 }
}

fn mock_set_host_db_manager_for_host_update_token() {
    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Ok(vec![create_mock_companion_device_capability()]));
    mock_host_db_manager
        .expect_get_token()
        .returning(|| Ok(create_mock_companion_token_info(AuthTrustLevel::Atl3)));
    mock_host_db_manager
        .expect_get_token()
        .returning(|| Ok(create_mock_companion_token_info(AuthTrustLevel::Atl2)));
    mock_host_db_manager
        .expect_get_token()
        .returning(|| Err(ErrorCode::GeneralError));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));
}

#[test]
fn init_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("init_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_generate_ed25519_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_set_local_key_pair().returning(|| Ok(()));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_read_device_db().returning(|| Ok(()));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager.expect_read_device_db().returning(|| Ok(()));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let input = InitInputFfi::default();
    let mut output = InitOutputFfi::default();
    let result = init(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn init_test_crypto_engine_fail() {
    let _guard = ut_registry_guard!();
    log_i!("init_test_crypto_engine_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_generate_ed25519_key_pair()
        .returning(|| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = InitInputFfi::default();
    let mut output = InitOutputFfi::default();
    let result = init(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn init_test_misc_manager_fail() {
    let _guard = ut_registry_guard!();
    log_i!("init_test_misc_manager_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_generate_ed25519_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager
        .expect_set_local_key_pair()
        .returning(|| Err(ErrorCode::GeneralError));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let input = InitInputFfi::default();
    let mut output = InitOutputFfi::default();
    let result = init(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn init_test_host_db_fail() {
    let _guard = ut_registry_guard!();
    log_i!("init_test_host_db_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_generate_ed25519_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_set_local_key_pair().returning(|| Ok(()));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_db()
        .returning(|| Err(ErrorCode::GeneralError));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager.expect_read_device_db().returning(|| Ok(()));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let input = InitInputFfi::default();
    let mut output = InitOutputFfi::default();
    let result = init(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn init_test_companion_db_fail() {
    let _guard = ut_registry_guard!();
    log_i!("init_test_companion_db_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_generate_ed25519_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_set_local_key_pair().returning(|| Ok(()));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_db()
        .returning(|| Err(ErrorCode::GeneralError));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let input = InitInputFfi::default();
    let mut output = InitOutputFfi::default();
    let result = init(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn get_executor_info_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("get_executor_info_test_success start");

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager
        .expect_get_local_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let input = GetExecutorInfoInputFfi::default();
    let mut output = GetExecutorInfoOutputFfi { esl: 0, max_template_acl: 0, public_key: DataArray1024Ffi::default() };
    let result = get_executor_info(&input, &mut output);
    assert!(result.is_ok());
    assert_eq!(output.esl, ExecutorSecurityLevel::Esl3 as i32);
    assert_eq!(output.max_template_acl, AuthCapabilityLevel::Acl3 as i32);
    assert_eq!(output.public_key, create_mock_key_pair().pub_key.clone().try_into().unwrap());
}

#[test]
fn get_executor_info_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("get_executor_info_test_fail start");

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager
        .expect_get_local_key_pair()
        .returning(|| Err(ErrorCode::GeneralError));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let input = GetExecutorInfoInputFfi::default();
    let mut output = GetExecutorInfoOutputFfi { esl: 0, max_template_acl: 0, public_key: DataArray1024Ffi::default() };
    let result = get_executor_info(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_on_register_finish_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_on_register_finish_test_success start");

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_set_fwk_pub_key().returning(|| Ok(()));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device_list()
        .returning(|| vec![create_mock_companion_device_info(123)]);
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut input = HostRegisterFinishInputFfi {
        template_ids: TemplateIdArrayFfi::default(),
        public_key: DataArray1024Ffi::default(),
        fwk_msg: DataArray1024Ffi::default(),
    };
    input.template_ids.data[0] = 123;
    input.template_ids.len = 1;
    let mut output = HostRegisterFinishOutputFfi::default();
    let result = host_on_register_finish(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_on_register_finish_test_misc_manager_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_on_register_finish_test_misc_manager_fail start");

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager
        .expect_set_fwk_pub_key()
        .returning(|| Err(ErrorCode::GeneralError));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut input = HostRegisterFinishInputFfi {
        template_ids: TemplateIdArrayFfi::default(),
        public_key: DataArray1024Ffi::default(),
        fwk_msg: DataArray1024Ffi::default(),
    };
    input.template_ids.data[0] = 123;
    input.template_ids.len = 1;
    let mut output = HostRegisterFinishOutputFfi::default();
    let result = host_on_register_finish(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_on_register_finish_test_remove_device_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_on_register_finish_test_remove_device_success start");

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_set_fwk_pub_key().returning(|| Ok(()));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device_list()
        .returning(|| vec![create_mock_companion_device_info(123)]);
    mock_host_db_manager
        .expect_remove_device()
        .returning(|| Ok(create_mock_companion_device_info(123)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut input = HostRegisterFinishInputFfi {
        template_ids: TemplateIdArrayFfi::default(),
        public_key: DataArray1024Ffi::default(),
        fwk_msg: DataArray1024Ffi::default(),
    };
    input.template_ids.data[0] = 456;
    input.template_ids.len = 1;
    let mut output = HostRegisterFinishOutputFfi::default();
    let result = host_on_register_finish(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_on_register_finish_test_remove_device_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_on_register_finish_test_remove_device_fail start");

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_set_fwk_pub_key().returning(|| Ok(()));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device_list()
        .returning(|| vec![create_mock_companion_device_info(123)]);
    mock_host_db_manager
        .expect_remove_device()
        .returning(|| Err(ErrorCode::GeneralError));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut input = HostRegisterFinishInputFfi {
        template_ids: TemplateIdArrayFfi::default(),
        public_key: DataArray1024Ffi::default(),
        fwk_msg: DataArray1024Ffi::default(),
    };
    input.template_ids.data[0] = 456;
    input.template_ids.len = 1;
    let mut output = HostRegisterFinishOutputFfi::default();
    let result = host_on_register_finish(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_get_persisted_status_test_success_with_devices() {
    let _guard = ut_registry_guard!();
    log_i!("host_get_persisted_status_test_success_with_devices start");

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device_list()
        .returning(|| vec![create_mock_companion_device_info(123)]);
    mock_host_db_manager
        .expect_read_device_base_info()
        .returning(|| Ok(create_mock_companion_device_base_info()));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostGetPersistedStatusInputFfi { user_id: 100 };
    let mut output = HostGetPersistedStatusOutputFfi { companion_status_list: CompanionStatusArrayFfi::default() };
    let result = host_get_persisted_status(&input, &mut output);
    assert!(result.is_ok());
    assert_eq!(output.companion_status_list.len, 1);
}

#[test]
fn host_get_persisted_status_test_success_no_devices() {
    let _guard = ut_registry_guard!();
    log_i!("host_get_persisted_status_test_success_no_devices start");

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_get_device_list().returning(|| Vec::new());
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostGetPersistedStatusInputFfi { user_id: 100 };
    let mut output = HostGetPersistedStatusOutputFfi { companion_status_list: CompanionStatusArrayFfi::default() };
    let result = host_get_persisted_status(&input, &mut output);
    assert!(result.is_ok());
    assert_eq!(output.companion_status_list.len, 0);
}

#[test]
fn host_get_persisted_status_test_read_device_base_info_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_get_persisted_status_test_read_device_base_info_fail start");

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device_list()
        .returning(|| vec![create_mock_companion_device_info(123)]);
    mock_host_db_manager
        .expect_read_device_base_info()
        .returning(|| Err(ErrorCode::GeneralError));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostGetPersistedStatusInputFfi { user_id: 100 };
    let mut output = HostGetPersistedStatusOutputFfi { companion_status_list: CompanionStatusArrayFfi::default() };
    let result = host_get_persisted_status(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_begin_companion_check_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_begin_companion_check_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager.expect_add_request().returning(|| Ok(()));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1 };
    let mut output = HostBeginCompanionCheckOutputFfi { challenge: 0, salt: DataArray32Ffi { data: [0u8; SALT_LEN_FFI], len: SALT_LEN_FFI as u32 } };
    let result = host_begin_companion_check(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_begin_companion_check_test_request_new_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_begin_companion_check_test_request_new_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_secure_random()
        .returning(|_buf| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1 };
    let mut output = HostBeginCompanionCheckOutputFfi { challenge: 0, salt: DataArray32Ffi { data: [0u8; SALT_LEN_FFI], len: SALT_LEN_FFI as u32 } };
    let result = host_begin_companion_check(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_begin_companion_check_test_add_request_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_begin_companion_check_test_add_request_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_add_request()
        .returning(|| Err(ErrorCode::GeneralError));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input = HostBeginCompanionCheckInputFfi { request_id: 1 };
    let mut output = HostBeginCompanionCheckOutputFfi { challenge: 0, salt: DataArray32Ffi { data: [0u8; SALT_LEN_FFI], len: SALT_LEN_FFI as u32 } };
    let result = host_begin_companion_check(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_end_companion_check_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_end_companion_check_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let begin_input = HostBeginCompanionCheckInputFfi { request_id: 1 };
    let sync_status_request = HostDeviceSyncStatusRequest::new(&begin_input).unwrap();

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(sync_status_request.clone())));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Ok(Vec::new()));
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123)));
    mock_host_db_manager.expect_update_device().returning(|| Ok(()));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        protocal_list: Uint16Array64Ffi::default(),
        capability_list: Uint16Array64Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut output = HostEndCompanionCheckOutputFfi::default();
    let result = host_end_companion_check(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_end_companion_check_test_remove_request_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_end_companion_check_test_remove_request_fail start");

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(|| Err(ErrorCode::GeneralError));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        protocal_list: Uint16Array64Ffi::default(),
        capability_list: Uint16Array64Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut output = HostEndCompanionCheckOutputFfi::default();
    let result = host_end_companion_check(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_end_companion_check_test_request_end_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_end_companion_check_test_request_end_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let begin_input = HostBeginCompanionCheckInputFfi { request_id: 1 };
    let sync_status_request = HostDeviceSyncStatusRequest::new(&begin_input).unwrap();

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(sync_status_request.clone())));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Ok(Vec::new()));
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Err(ErrorCode::GeneralError));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostEndCompanionCheckInputFfi {
        request_id: 1,
        template_id: 123,
        protocal_list: Uint16Array64Ffi::default(),
        capability_list: Uint16Array64Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut output = HostEndCompanionCheckOutputFfi::default();
    let result = host_end_companion_check(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_cancel_companion_check_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_cancel_companion_check_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let begin_input = HostBeginCompanionCheckInputFfi { request_id: 1 };
    let sync_status_request = HostDeviceSyncStatusRequest::new(&begin_input).unwrap();

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(sync_status_request.clone())));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input = HostCancelCompanionCheckInputFfi { request_id: 1 };
    let mut output = HostCancelCompanionCheckOutputFfi::default();
    let result = host_cancel_companion_check(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_cancel_companion_check_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_cancel_companion_check_test_fail start");

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(|| Err(ErrorCode::NotFound));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input = HostCancelCompanionCheckInputFfi { request_id: 1 };
    let mut output = HostCancelCompanionCheckOutputFfi::default();
    let result = host_cancel_companion_check(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn host_get_init_key_negotiation_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_get_init_key_negotiation_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager.expect_add_request().returning(|| Ok(()));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };
    let mut output = HostGetInitKeyNegotiationOutputFfi { sec_message: DataArray20000Ffi::default() };
    let result = host_get_init_key_negotiation(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_get_init_key_negotiation_test_request_new_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_get_init_key_negotiation_test_request_new_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_secure_random()
        .returning(|_buf| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };
    let mut output = HostGetInitKeyNegotiationOutputFfi { sec_message: DataArray20000Ffi::default() };
    let result = host_get_init_key_negotiation(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_get_init_key_negotiation_test_add_request_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_get_init_key_negotiation_test_add_request_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_add_request()
        .returning(|| Err(ErrorCode::GeneralError));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };
    let mut output = HostGetInitKeyNegotiationOutputFfi { sec_message: DataArray20000Ffi::default() };
    let result = host_get_init_key_negotiation(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_begin_add_companion_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_begin_add_companion_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    mock_crypto_engine
        .expect_generate_x25519_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Ok(Vec::new()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let host_request_manager = DefaultHostRequestManager::new();
    HostRequestManagerRegistry::set(Box::new(host_request_manager));

    let nego_input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };
    let enroll_request = HostDeviceEnrollRequest::new(&nego_input).unwrap();
    HostRequestManagerRegistry::get_mut()
        .add_request(Box::new(enroll_request))
        .unwrap();

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_get_fwk_pub_key().returning(|| Ok(vec![1u8, 2, 3]));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut attr = Attribute::new();
    attr.set_u64(AttributeKey::AttrScheduleId, 1);
    attr.set_i32(AttributeKey::AttrAuthTrustLevel, 30000);

    let fwk_message_codec = MessageCodec::new(MessageSignParam::Executor(create_mock_key_pair()));
    let fwk_message = fwk_message_codec.serialize_attribute(&attr).unwrap();

    let sec_key_nego_reply = SecKeyNegoReply { algorithm: 1, challenge: 0, pub_key: vec![1, 2, 3] };
    let sec_message = sec_key_nego_reply.encode(DeviceType::None).unwrap();

    let input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi::default(),
        companion_device_key: DeviceKeyFfi::default(),
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::try_from(&sec_message).unwrap(),
    };
    let mut output = HostBeginAddCompanionOutputFfi::default();
    let result = host_begin_add_companion(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_begin_add_companion_test_get_request_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_begin_add_companion_test_get_request_fail start");

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager.expect_get_request(Ok(())); // No request stored, will return NotFound
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi::default(),
        companion_device_key: DeviceKeyFfi::default(),
        fwk_message: DataArray1024Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::default(),
    };
    let mut output = HostBeginAddCompanionOutputFfi::default();
    let result = host_begin_add_companion(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn host_begin_add_companion_test_request_begin_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_begin_add_companion_test_request_begin_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let host_request_manager = DefaultHostRequestManager::new();
    HostRequestManagerRegistry::set(Box::new(host_request_manager));

    let nego_input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };
    let enroll_request = HostDeviceEnrollRequest::new(&nego_input).unwrap();
    HostRequestManagerRegistry::get_mut()
        .add_request(Box::new(enroll_request))
        .unwrap();

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager
        .expect_get_fwk_pub_key()
        .returning(|| Err(ErrorCode::GeneralError));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let input = HostBeginAddCompanionInputFfi {
        request_id: 1,
        schedule_id: 1,
        host_device_key: DeviceKeyFfi::default(),
        companion_device_key: DeviceKeyFfi::default(),
        fwk_message: DataArray1024Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray20000Ffi::default(),
    };
    let mut output = HostBeginAddCompanionOutputFfi::default();
    let result = host_begin_add_companion(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_end_add_companion_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_end_add_companion_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let nego_input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };
    let mut enroll_request = HostDeviceEnrollRequest::new(&nego_input).unwrap();
    enroll_request.key_negotial_param = Vec::new();
    enroll_request.token_infos = Vec::new();

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(enroll_request.clone())));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_generate_unique_template_id().returning(|| Ok(123));
    mock_host_db_manager.expect_add_device().returning(|| Ok(()));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Ok(1000));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager
        .expect_get_local_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let input = HostEndAddCompanionInputFfi::default();
    let mut output = HostEndAddCompanionOutputFfi::default();
    let result = host_end_add_companion(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_end_add_companion_test_remove_request_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_end_add_companion_test_remove_request_fail start");

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(|| Err(ErrorCode::GeneralError));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input = HostEndAddCompanionInputFfi::default();
    let mut output = HostEndAddCompanionOutputFfi::default();
    let result = host_end_add_companion(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_end_add_companion_test_request_end_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_end_add_companion_test_request_end_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let nego_input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };
    let mut enroll_request = HostDeviceEnrollRequest::new(&nego_input).unwrap();
    enroll_request.key_negotial_param = Vec::new();
    enroll_request.token_infos = Vec::new();

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(enroll_request.clone())));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_generate_unique_template_id()
        .returning(|| Err(ErrorCode::GeneralError));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostEndAddCompanionInputFfi::default();
    let mut output = HostEndAddCompanionOutputFfi::default();
    let result = host_end_add_companion(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_cancel_add_companion_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_cancel_add_companion_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let nego_input = HostGetInitKeyNegotiationInputFfi { request_id: 1, secure_protocol_id: 1 };
    let enroll_request = HostDeviceEnrollRequest::new(&nego_input).unwrap();

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(enroll_request.clone())));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input = HostCancelAddCompanionInputFfi { request_id: 1 };
    let mut output = HostCancelAddCompanionOutputFfi::default();
    let result = host_cancel_add_companion(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_cancel_add_companion_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_cancel_add_companion_test_fail start");

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(|| Err(ErrorCode::NotFound));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input = HostCancelAddCompanionInputFfi { request_id: 1 };
    let mut output = HostCancelAddCompanionOutputFfi::default();
    let result = host_cancel_add_companion(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn host_remove_companion_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_remove_companion_test_success start");

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123)));
    mock_host_db_manager
        .expect_remove_device()
        .returning(|| Ok(create_mock_companion_device_info(123)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostRemoveCompanionInputFfi { template_id: 123 };
    let mut output = HostRemoveCompanionOutputFfi { user_id: 0, companion_device_key: DeviceKeyFfi::default() };
    let result = host_remove_companion(&input, &mut output);
    assert!(result.is_ok());
    assert_eq!(output.user_id, 100);
}

#[test]
fn host_remove_companion_test_fail_get_device() {
    let _guard = ut_registry_guard!();
    log_i!("host_remove_companion_test_fail_get_device start");

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_get_device().returning(|| Err(ErrorCode::NotFound));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostRemoveCompanionInputFfi { template_id: 123 };
    let mut output = HostRemoveCompanionOutputFfi { user_id: 0, companion_device_key: DeviceKeyFfi::default() };
    let result = host_remove_companion(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn host_remove_companion_test_fail_remove_device() {
    let _guard = ut_registry_guard!();
    log_i!("host_remove_companion_test_fail_remove_device start");

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123)));
    mock_host_db_manager
        .expect_remove_device()
        .returning(|| Err(ErrorCode::GeneralError));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostRemoveCompanionInputFfi { template_id: 123 };
    let mut output = HostRemoveCompanionOutputFfi { user_id: 0, companion_device_key: DeviceKeyFfi::default() };
    let result = host_remove_companion(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_pre_issue_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_pre_issue_token_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    mock_crypto_engine
        .expect_generate_x25519_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Ok(Vec::new()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager.expect_add_request().returning(|| Ok(()));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_get_fwk_pub_key().returning(|| Ok(vec![1u8, 2, 3]));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Ok(Vec::new()));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut attr = Attribute::new();
    attr.set_u32(AttributeKey::AttrPropertyMode, 6);
    attr.set_u32(AttributeKey::AttrType, 64);
    attr.set_i32(AttributeKey::AttrAuthTrustLevel, 30000);
    attr.set_u64_slice(AttributeKey::AttrTemplateIdList, &[123u64; 1]);

    let fwk_message_codec = MessageCodec::new(MessageSignParam::Executor(create_mock_key_pair()));
    let fwk_message = fwk_message_codec.serialize_attribute(&attr).unwrap();

    let input = HostPreIssueTokenInputFfi {
        request_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
    };
    let mut output = HostPreIssueTokenOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = host_pre_issue_token(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_pre_issue_token_test_request_new_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_pre_issue_token_test_request_new_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_secure_random()
        .returning(|_buf| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };
    let mut output = HostPreIssueTokenOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = host_pre_issue_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_pre_issue_token_test_request_prepare_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_pre_issue_token_test_request_prepare_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager
        .expect_get_fwk_pub_key()
        .returning(|| Err(ErrorCode::GeneralError));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let input = HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };
    let mut output = HostPreIssueTokenOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = host_pre_issue_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_pre_issue_token_test_add_request_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_pre_issue_token_test_add_request_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    mock_crypto_engine
        .expect_generate_x25519_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Ok(Vec::new()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_add_request()
        .returning(|| Err(ErrorCode::GeneralError));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_get_fwk_pub_key().returning(|| Ok(vec![1u8, 2, 3]));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Ok(Vec::new()));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut attr = Attribute::new();
    attr.set_u32(AttributeKey::AttrPropertyMode, 6);
    attr.set_u32(AttributeKey::AttrType, 64);
    attr.set_i32(AttributeKey::AttrAuthTrustLevel, 30000);
    attr.set_u64_slice(AttributeKey::AttrTemplateIdList, &[123u64; 1]);

    let fwk_message_codec = MessageCodec::new(MessageSignParam::Executor(create_mock_key_pair()));
    let fwk_message = fwk_message_codec.serialize_attribute(&attr).unwrap();

    let input = HostPreIssueTokenInputFfi {
        request_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
    };
    let mut output = HostPreIssueTokenOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = host_pre_issue_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_begin_issue_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_begin_issue_token_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Ok(Vec::new()));
    mock_host_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceSk { device_type: DeviceType::None, sk: Vec::new() }]));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let host_request_manager = DefaultHostRequestManager::new();
    HostRequestManagerRegistry::set(Box::new(host_request_manager));

    let pre_input =
        HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };
    let mut issue_token_request = HostDeviceIssueTokenRequest::new(&pre_input).unwrap();
    issue_token_request.token_infos.push(DeviceTokenInfo {
        device_type: DeviceType::None,
        challenge: 0,
        atl: AuthTrustLevel::Atl3,
        token: Vec::new(),
    });
    HostRequestManagerRegistry::get_mut()
        .add_request(Box::new(issue_token_request))
        .unwrap();

    let input =
        HostBeginIssueTokenInputFfi { request_id: 1, secure_protocol_id: 1, sec_message: DataArray1024Ffi::default() };
    let mut output = HostBeginIssueTokenOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = host_begin_issue_token(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_begin_issue_token_test_get_request_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_begin_issue_token_test_get_request_fail start");

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager.expect_get_request(Ok(())); // No request stored, will return NotFound
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input =
        HostBeginIssueTokenInputFfi { request_id: 1, secure_protocol_id: 1, sec_message: DataArray1024Ffi::default() };
    let mut output = HostBeginIssueTokenOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = host_begin_issue_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn host_begin_issue_token_test_request_begin_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_begin_issue_token_test_request_begin_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Err(ErrorCode::GeneralError));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let host_request_manager = DefaultHostRequestManager::new();
    HostRequestManagerRegistry::set(Box::new(host_request_manager));

    let pre_input =
        HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };
    let issue_token_request = HostDeviceIssueTokenRequest::new(&pre_input).unwrap();
    HostRequestManagerRegistry::get_mut()
        .add_request(Box::new(issue_token_request))
        .unwrap();

    let input =
        HostBeginIssueTokenInputFfi { request_id: 1, secure_protocol_id: 1, sec_message: DataArray1024Ffi::default() };
    let mut output = HostBeginIssueTokenOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = host_begin_issue_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_end_issue_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_end_issue_token_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let pre_input =
        HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };
    let mut issue_token_request = HostDeviceIssueTokenRequest::new(&pre_input).unwrap();
    issue_token_request.token_infos = Vec::new();

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(issue_token_request.clone())));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input =
        HostEndIssueTokenInputFfi { request_id: 1, secure_protocol_id: 1, sec_message: DataArray1024Ffi::default() };
    let mut output = HostEndIssueTokenOutputFfi::default();
    let result = host_end_issue_token(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_end_issue_token_test_remove_request_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_end_issue_token_test_remove_request_fail start");

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(|| Err(ErrorCode::GeneralError));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input =
        HostEndIssueTokenInputFfi { request_id: 1, secure_protocol_id: 1, sec_message: DataArray1024Ffi::default() };
    let mut output = HostEndIssueTokenOutputFfi::default();
    let result = host_end_issue_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_cancel_issue_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_cancel_issue_token_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let pre_input =
        HostPreIssueTokenInputFfi { request_id: 1, template_id: 123, fwk_message: DataArray1024Ffi::default() };
    let issue_token_request = HostDeviceIssueTokenRequest::new(&pre_input).unwrap();

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(issue_token_request.clone())));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input = HostCancelIssueTokenInputFfi { request_id: 1 };
    let mut output = HostCancelIssueTokenOutputFfi::default();
    let result = host_cancel_issue_token(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_cancel_issue_token_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_cancel_issue_token_test_fail start");

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(|| Err(ErrorCode::NotFound));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input = HostCancelIssueTokenInputFfi { request_id: 1 };
    let mut output = HostCancelIssueTokenOutputFfi::default();
    let result = host_cancel_issue_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn host_begin_token_auth_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_begin_token_auth_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    mock_crypto_engine
        .expect_generate_x25519_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Ok(Vec::new()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager.expect_add_request().returning(|| Ok(()));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_get_fwk_pub_key().returning(|| Ok(vec![1u8, 2, 3]));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123)));
    mock_host_db_manager
        .expect_get_token()
        .returning(|| Ok(create_mock_companion_token_info(AuthTrustLevel::Atl3)));
    mock_host_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceSk { device_type: DeviceType::None, sk: Vec::new() }]));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Ok(2000));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let mut attr = Attribute::new();
    attr.set_u64(AttributeKey::AttrScheduleId, 1);
    attr.set_u64_slice(AttributeKey::AttrTemplateIdList, &[123u64; 1]);
    attr.set_i32(AttributeKey::AttrAuthTrustLevel, 30000);

    let fwk_message_codec = MessageCodec::new(MessageSignParam::Executor(create_mock_key_pair()));
    let fwk_message = fwk_message_codec.serialize_attribute(&attr).unwrap();

    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
    };
    let mut output = HostBeginTokenAuthOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = host_begin_token_auth(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_begin_token_auth_test_request_new_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_begin_token_auth_test_request_new_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_secure_random()
        .returning(|_buf| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };
    let mut output = HostBeginTokenAuthOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = host_begin_token_auth(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_begin_token_auth_test_request_begin_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_begin_token_auth_test_request_begin_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager
        .expect_get_fwk_pub_key()
        .returning(|| Err(ErrorCode::GeneralError));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };
    let mut output = HostBeginTokenAuthOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = host_begin_token_auth(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_begin_token_auth_test_add_request_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_begin_token_auth_test_add_request_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    mock_crypto_engine
        .expect_generate_x25519_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Ok(Vec::new()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_add_request()
        .returning(|| Err(ErrorCode::GeneralError));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_get_fwk_pub_key().returning(|| Ok(vec![1u8, 2, 3]));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123)));
    mock_host_db_manager
        .expect_get_token()
        .returning(|| Ok(create_mock_companion_token_info(AuthTrustLevel::Atl3)));
    mock_host_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceSk { device_type: DeviceType::None, sk: Vec::new() }]));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Ok(2000));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let mut attr = Attribute::new();
    attr.set_u64(AttributeKey::AttrScheduleId, 1);
    attr.set_u64_slice(AttributeKey::AttrTemplateIdList, &[123u64; 1]);
    attr.set_i32(AttributeKey::AttrAuthTrustLevel, 30000);

    let fwk_message_codec = MessageCodec::new(MessageSignParam::Executor(create_mock_key_pair()));
    let fwk_message = fwk_message_codec.serialize_attribute(&attr).unwrap();

    let input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
    };
    let mut output = HostBeginTokenAuthOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = host_begin_token_auth(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_end_token_auth_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_end_token_auth_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hmac_sha256().returning(|_, _| Ok(vec![1, 2, 3]));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let begin_input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };
    let token_auth_request = HostTokenAuthRequest::new(&begin_input).unwrap();

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(token_auth_request.clone())));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_token()
        .returning(|| Ok(create_mock_companion_token_info(AuthTrustLevel::Atl3)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager
        .expect_get_local_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let sec_auth_reply = SecAuthReply { hmac: vec![1, 2, 3] };
    let sec_message = sec_auth_reply.encode(DeviceType::None).unwrap();

    let input = HostEndTokenAuthInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(&sec_message).unwrap(),
    };
    let mut output = HostEndTokenAuthOutputFfi { fwk_message: DataArray1024Ffi::default() };
    let result = host_end_token_auth(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_end_token_auth_test_remove_request_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_end_token_auth_test_remove_request_fail start");

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(|| Err(ErrorCode::GeneralError));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input = HostEndTokenAuthInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut output = HostEndTokenAuthOutputFfi { fwk_message: DataArray1024Ffi::default() };
    let result = host_end_token_auth(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_end_token_auth_test_request_end_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_end_token_auth_test_request_end_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let begin_input = HostBeginTokenAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };
    let token_auth_request = HostTokenAuthRequest::new(&begin_input).unwrap();

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(token_auth_request.clone())));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input = HostEndTokenAuthInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut output = HostEndTokenAuthOutputFfi { fwk_message: DataArray1024Ffi::default() };
    let result = host_end_token_auth(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_revoke_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_revoke_token_test_success start");

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_remove_token()
        .returning(|| Ok(create_mock_companion_token_info(AuthTrustLevel::Atl3)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostRevokeTokenInputFfi { template_id: 123 };
    let mut output = HostRevokeTokenOutputFfi::default();
    let result = host_revoke_token(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_revoke_token_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_revoke_token_test_fail start");

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_remove_token()
        .returning(|| Err(ErrorCode::NotFound));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostRevokeTokenInputFfi { template_id: 123 };
    let mut output = HostRevokeTokenOutputFfi::default();
    let result = host_revoke_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn host_update_companion_status_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_update_companion_status_test_success start");

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_base_info()
        .returning(|| Ok(create_mock_companion_device_base_info()));
    mock_host_db_manager.expect_write_device_base_info().returning(|| Ok(()));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostUpdateCompanionStatusInputFfi {
        template_id: 123,
        device_name: DataArray256Ffi::default(),
        device_user_name: DataArray256Ffi::default(),
    };
    let mut output = HostUpdateCompanionStatusOutputFfi::default();
    let result = host_update_companion_status(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_update_companion_status_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_update_companion_status_test_fail start");

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_base_info()
        .returning(|| Err(ErrorCode::GeneralError));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostUpdateCompanionStatusInputFfi {
        template_id: 123,
        device_name: DataArray256Ffi::default(),
        device_user_name: DataArray256Ffi::default(),
    };
    let mut output = HostUpdateCompanionStatusOutputFfi::default();
    let result = host_update_companion_status(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_update_companion_enabled_business_ids_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_update_companion_enabled_business_ids_test_success start");

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123)));
    mock_host_db_manager
        .expect_read_device_base_info()
        .returning(|| Ok(create_mock_companion_device_base_info()));
    mock_host_db_manager.expect_write_device_base_info().returning(|| Ok(()));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input =
        HostUpdateCompanionEnabledBusinessIdsInputFfi { template_id: 123, business_ids: Int32Array64Ffi::default() };
    let mut output = HostUpdateCompanionEnabledBusinessIdsOutputFfi::default();
    let result = host_update_companion_enabled_business_ids(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_update_companion_enabled_business_ids_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_update_companion_enabled_business_ids_test_fail start");

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_get_device().returning(|| Err(ErrorCode::NotFound));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input =
        HostUpdateCompanionEnabledBusinessIdsInputFfi { template_id: 123, business_ids: Int32Array64Ffi::default() };
    let mut output = HostUpdateCompanionEnabledBusinessIdsOutputFfi::default();
    let result = host_update_companion_enabled_business_ids(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn host_check_template_enrolled_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_check_template_enrolled_test_success start");

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Ok(create_mock_companion_device_info(123)));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostCheckTemplateEnrolledInputFfi { template_id: 123 };
    let mut output = HostCheckTemplateEnrolledOutputFfi { enrolled: 10 };
    let result = host_check_template_enrolled(&input, &mut output);
    assert!(result.is_ok());
    assert_eq!(output.enrolled, 1);
}

#[test]
fn host_check_template_enrolled_test_not_found() {
    let _guard = ut_registry_guard!();
    log_i!("host_check_template_enrolled_test_not_found start");

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager.expect_get_device().returning(|| Err(ErrorCode::NotFound));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostCheckTemplateEnrolledInputFfi { template_id: 123 };
    let mut output = HostCheckTemplateEnrolledOutputFfi { enrolled: 10 };
    let result = host_check_template_enrolled(&input, &mut output);
    assert!(result.is_ok());
    assert_eq!(output.enrolled, 0);
}

#[test]
fn host_check_template_enrolled_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_check_template_enrolled_test_fail start");

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_get_device()
        .returning(|| Err(ErrorCode::GeneralError));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostCheckTemplateEnrolledInputFfi { template_id: 123 };
    let mut output = HostCheckTemplateEnrolledOutputFfi { enrolled: 10 };
    let result = host_check_template_enrolled(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
    assert_eq!(output.enrolled, 10);
}

#[test]
fn host_begin_delegate_auth_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_begin_delegate_auth_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    mock_crypto_engine
        .expect_generate_x25519_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Ok(Vec::new()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager.expect_add_request().returning(|| Ok(()));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_get_fwk_pub_key().returning(|| Ok(vec![1u8, 2, 3]));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Ok(Vec::new()));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut attr = Attribute::new();
    attr.set_u64(AttributeKey::AttrScheduleId, 1);
    attr.set_i32(AttributeKey::AttrAuthTrustLevel, 30000);

    let fwk_message_codec = MessageCodec::new(MessageSignParam::Executor(create_mock_key_pair()));
    let fwk_message = fwk_message_codec.serialize_attribute(&attr).unwrap();

    let input = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
    };
    let mut output = HostBeginDelegateAuthOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = host_begin_delegate_auth(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_begin_delegate_auth_test_request_new_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_begin_delegate_auth_test_request_new_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_secure_random()
        .returning(|_buf| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };
    let mut output = HostBeginDelegateAuthOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = host_begin_delegate_auth(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_begin_delegate_auth_test_request_begin_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_begin_delegate_auth_test_request_begin_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager
        .expect_get_fwk_pub_key()
        .returning(|| Err(ErrorCode::GeneralError));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let input = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };
    let mut output = HostBeginDelegateAuthOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = host_begin_delegate_auth(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_begin_delegate_auth_test_add_request_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_begin_delegate_auth_test_add_request_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    mock_crypto_engine
        .expect_generate_x25519_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Ok(Vec::new()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_add_request()
        .returning(|| Err(ErrorCode::GeneralError));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_get_fwk_pub_key().returning(|| Ok(vec![1u8, 2, 3]));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Ok(Vec::new()));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut attr = Attribute::new();
    attr.set_u64(AttributeKey::AttrScheduleId, 1);
    attr.set_i32(AttributeKey::AttrAuthTrustLevel, 30000);

    let fwk_message_codec = MessageCodec::new(MessageSignParam::Executor(create_mock_key_pair()));
    let fwk_message = fwk_message_codec.serialize_attribute(&attr).unwrap();

    let input = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
    };
    let mut output = HostBeginDelegateAuthOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = host_begin_delegate_auth(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_end_delegate_auth_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_end_delegate_auth_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let begin_input = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };
    let mut delegate_auth_request = HostDelegateAuthRequest::new(&begin_input).unwrap();
    delegate_auth_request.auth_type = 64;
    delegate_auth_request.atl = AuthTrustLevel::Atl3;

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(delegate_auth_request.clone())));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Ok(Vec::new()));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager
        .expect_get_local_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let input =
        HostEndDelegateAuthInputFfi { request_id: 1, secure_protocol_id: 1, sec_message: DataArray1024Ffi::default() };
    let mut output = HostEndDelegateAuthOutputFfi { fwk_message: DataArray1024Ffi::default(), auth_type: 0, atl: 0 };
    let result = host_end_delegate_auth(&input, &mut output);
    assert!(result.is_ok());
    assert_eq!(output.auth_type, 64);
    assert_eq!(output.atl, AuthTrustLevel::Atl3 as i32);
}

#[test]
fn host_end_delegate_auth_test_remove_request_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_end_delegate_auth_test_remove_request_fail start");

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(|| Err(ErrorCode::NotFound));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input =
        HostEndDelegateAuthInputFfi { request_id: 1, secure_protocol_id: 1, sec_message: DataArray1024Ffi::default() };
    let mut output = HostEndDelegateAuthOutputFfi { fwk_message: DataArray1024Ffi::default(), auth_type: 0, atl: 0 };
    let result = host_end_delegate_auth(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn host_end_delegate_auth_test_request_end_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_end_delegate_auth_test_request_end_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let begin_input = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };
    let delegate_auth_request = HostDelegateAuthRequest::new(&begin_input).unwrap();

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(delegate_auth_request.clone())));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Err(ErrorCode::GeneralError));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input =
        HostEndDelegateAuthInputFfi { request_id: 1, secure_protocol_id: 1, sec_message: DataArray1024Ffi::default() };
    let mut output = HostEndDelegateAuthOutputFfi { fwk_message: DataArray1024Ffi::default(), auth_type: 0, atl: 0 };
    let result = host_end_delegate_auth(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_cancel_delegate_auth_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_cancel_delegate_auth_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let begin_input = HostBeginDelegateAuthInputFfi {
        request_id: 1,
        schedule_id: 1,
        template_id: 123,
        fwk_message: DataArray1024Ffi::default(),
    };
    let delegate_auth_request = HostDelegateAuthRequest::new(&begin_input).unwrap();

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(delegate_auth_request.clone())));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input = HostCancelDelegateAuthInputFfi { request_id: 1 };
    let mut output = HostCancelDelegateAuthOutputFfi::default();
    let result = host_cancel_delegate_auth(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_cancel_delegate_auth_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_cancel_delegate_auth_test_fail start");

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(|| Err(ErrorCode::NotFound));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input = HostCancelDelegateAuthInputFfi { request_id: 1 };
    let mut output = HostCancelDelegateAuthOutputFfi::default();
    let result = host_cancel_delegate_auth(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn host_process_pre_obtain_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_process_pre_obtain_token_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager.expect_add_request().returning(|| Ok(()));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Ok(Vec::new()));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };
    let mut output = HostProcessPreObtainTokenOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = host_process_pre_obtain_token(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_process_pre_obtain_token_test_request_new_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_process_pre_obtain_token_test_request_new_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_secure_random()
        .returning(|_buf| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };
    let mut output = HostProcessPreObtainTokenOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = host_process_pre_obtain_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_process_pre_obtain_token_test_request_begin_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_process_pre_obtain_token_test_request_begin_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Err(ErrorCode::GeneralError));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };
    let mut output = HostProcessPreObtainTokenOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = host_process_pre_obtain_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_process_pre_obtain_token_test_add_request_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_process_pre_obtain_token_test_add_request_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_add_request()
        .returning(|| Err(ErrorCode::GeneralError));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Ok(Vec::new()));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };
    let mut output = HostProcessPreObtainTokenOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = host_process_pre_obtain_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_process_obtain_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_process_obtain_token_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let pre_input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };
    let mut obtain_token_request = HostDeviceObtainTokenRequest::new(&pre_input).unwrap();
    obtain_token_request.token_infos.push(DeviceTokenInfo {
        device_type: DeviceType::None,
        challenge: 0,
        atl: AuthTrustLevel::Atl3,
        token: Vec::new(),
    });

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(obtain_token_request.clone())));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Ok(Vec::new()));
    mock_host_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(vec![CompanionDeviceSk { device_type: DeviceType::None, sk: Vec::new() }]));
    mock_host_db_manager.expect_add_token().returning(|| Ok(()));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Ok(1000));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let input = HostProcessObtainTokenInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut output = HostProcessObtainTokenOutputFfi { sec_message: DataArray1024Ffi::default(), atl: 0 };
    let result = host_process_obtain_token(&input, &mut output);
    assert!(result.is_ok());
    assert_eq!(output.atl, AuthTrustLevel::Atl3 as i32);
}

#[test]
fn host_process_obtain_token_test_remove_request_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_process_obtain_token_test_remove_request_fail start");

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(|| Err(ErrorCode::NotFound));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input = HostProcessObtainTokenInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut output = HostProcessObtainTokenOutputFfi { sec_message: DataArray1024Ffi::default(), atl: 0 };
    let result = host_process_obtain_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn host_process_obtain_token_test_request_end_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_process_obtain_token_test_request_end_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let pre_input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };
    let obtain_token_request = HostDeviceObtainTokenRequest::new(&pre_input).unwrap();

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(obtain_token_request.clone())));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Ok(Vec::new()));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let input = HostProcessObtainTokenInputFfi {
        request_id: 1,
        template_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut output = HostProcessObtainTokenOutputFfi { sec_message: DataArray1024Ffi::default(), atl: 0 };
    let result = host_process_obtain_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_cancel_obtain_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_cancel_obtain_token_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let pre_input = HostProcessPreObtainTokenInputFfi { request_id: 1, template_id: 123, secure_protocol_id: 1 };
    let obtain_token_request = HostDeviceObtainTokenRequest::new(&pre_input).unwrap();

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(obtain_token_request.clone())));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input = HostCancelObtainTokenInputFfi { request_id: 1 };
    let mut output = HostCancelObtainTokenOutputFfi::default();
    let result = host_cancel_obtain_token(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn host_cancel_obtain_token_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_cancel_obtain_token_test_fail start");

    let mut mock_host_request_manager = MockHostRequestManager::new();
    mock_host_request_manager
        .expect_remove_request()
        .returning(|| Err(ErrorCode::NotFound));
    HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));

    let input = HostCancelObtainTokenInputFfi { request_id: 1 };
    let mut output = HostCancelObtainTokenOutputFfi::default();
    let result = host_cancel_obtain_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn host_update_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("host_update_token_test_success start");

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_get_fwk_pub_key().returning(|| Ok(vec![1u8, 2, 3]));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    mock_set_host_db_manager_for_host_update_token();

    let mut attr = Attribute::new();
    attr.set_i32(AttributeKey::AttrAuthTrustLevel, 30000);

    let fwk_message_codec = MessageCodec::new(MessageSignParam::Executor(create_mock_key_pair()));
    let fwk_message = fwk_message_codec.serialize_attribute(&attr).unwrap();

    let input =
        HostUpdateTokenInputFfi { template_id: 123, fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap() };
    let mut output = HostUpdateTokenOutputFfi { need_redistribute: false };
    let result = host_update_token(&input, &mut output);
    assert!(result.is_ok());
    assert_eq!(output.need_redistribute, false);

    let result = host_update_token(&input, &mut output);
    assert!(result.is_ok());
    assert_eq!(output.need_redistribute, true);

    let result = host_update_token(&input, &mut output);
    assert!(result.is_ok());
    assert_eq!(output.need_redistribute, true);

    let result = host_update_token(&input, &mut output);
    assert!(result.is_ok());
    assert_eq!(output.need_redistribute, true);
}

#[test]
fn host_update_token_test_get_fwk_pub_key_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_update_token_test_get_fwk_pub_key_fail start");

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager
        .expect_get_fwk_pub_key()
        .returning(|| Err(ErrorCode::GeneralError));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let input = HostUpdateTokenInputFfi { template_id: 123, fwk_message: DataArray1024Ffi::default() };
    let mut output = HostUpdateTokenOutputFfi { need_redistribute: false };
    let result = host_update_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn host_update_token_test_deserialize_attribute_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_update_token_test_deserialize_attribute_fail start");

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_get_fwk_pub_key().returning(|| Ok(vec![1u8, 2, 3]));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let input = HostUpdateTokenInputFfi { template_id: 123, fwk_message: DataArray1024Ffi::default() };
    let mut output = HostUpdateTokenOutputFfi { need_redistribute: false };
    let result = host_update_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn host_update_token_test_read_device_capability_info_fail() {
    let _guard = ut_registry_guard!();
    log_i!("host_update_token_test_read_device_capability_info_fail start");

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_get_fwk_pub_key().returning(|| Ok(vec![1u8, 2, 3]));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_host_db_manager = MockHostDbManager::new();
    mock_host_db_manager
        .expect_read_device_capability_info()
        .returning(|| Err(ErrorCode::NotFound));
    HostDbManagerRegistry::set(Box::new(mock_host_db_manager));

    let mut attr = Attribute::new();
    attr.set_i32(AttributeKey::AttrAuthTrustLevel, 30000);

    let fwk_message_codec = MessageCodec::new(MessageSignParam::Executor(create_mock_key_pair()));
    let fwk_message = fwk_message_codec.serialize_attribute(&attr).unwrap();

    let input =
        HostUpdateTokenInputFfi { template_id: 123, fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap() };
    let mut output = HostUpdateTokenOutputFfi { need_redistribute: false };
    let result = host_update_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn companion_get_persisted_status_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("companion_get_persisted_status_test_success start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_get_device_list()
        .returning(|| vec![create_mock_host_device_info(123)]);
    mock_companion_db_manager.expect_is_device_token_valid().returning(|| Ok(true));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let input = CompanionGetPersistedStatusInputFfi { user_id: 100 };
    let mut output = CompanionGetPersistedStatusOutputFfi { binding_status_list: HostBindingStatusArrayFfi::default() };
    let result = companion_get_persisted_status(&input, &mut output);
    assert!(result.is_ok());
    assert_eq!(output.binding_status_list.len, 1);
}

#[test]
fn companion_get_persisted_status_test_token_valid_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_get_persisted_status_test_token_valid_fail start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_get_device_list()
        .returning(|| vec![create_mock_host_device_info(123)]);
    mock_companion_db_manager
        .expect_is_device_token_valid()
        .returning(|| Err(ErrorCode::GeneralError));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let input = CompanionGetPersistedStatusInputFfi { user_id: 100 };
    let mut output = CompanionGetPersistedStatusOutputFfi { binding_status_list: HostBindingStatusArrayFfi::default() };
    let result = companion_get_persisted_status(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_process_check_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("companion_process_check_test_success start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(HostDeviceSk { sk: Vec::new() }));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = CompanionProcessCheckInputFfi {
        binding_id: 123,
        capability_list: Uint16Array64Ffi::default(),
        secure_protocol_id: 1,
        salt: DataArray32Ffi { data: [0u8; SALT_LEN_FFI], len: SALT_LEN_FFI as u32 },
        challenge: 12345,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut output = CompanionProcessCheckOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = companion_process_check(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn companion_process_check_test_request_begin_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_process_check_test_request_begin_fail start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_sk()
        .returning(|| Err(ErrorCode::GeneralError));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let input = CompanionProcessCheckInputFfi {
        binding_id: 123,
        capability_list: Uint16Array64Ffi::default(),
        secure_protocol_id: 1,
        salt: DataArray32Ffi { data: [0u8; SALT_LEN_FFI], len: SALT_LEN_FFI as u32 },
        challenge: 12345,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut output = CompanionProcessCheckOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = companion_process_check(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_init_key_negotiation_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("companion_init_key_negotiation_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_generate_x25519_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_companion_request_manager = MockCompanionRequestManager::new();
    mock_companion_request_manager.expect_add_request().returning(|| Ok(()));
    CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

    let sec_key_nego_request = SecKeyNegoRequest { algorithm_list: vec![1] };
    let sec_message = sec_key_nego_request.encode(DeviceType::None).unwrap();

    let input = CompanionInitKeyNegotiationInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        companion_device_key: DeviceKeyFfi::default(),
        host_device_key: DeviceKeyFfi::default(),
        sec_message: DataArray20000Ffi::try_from(&sec_message).unwrap(),
    };
    let mut output = CompanionInitKeyNegotiationOutputFfi { sec_message: DataArray20000Ffi::default() };
    let result = companion_init_key_negotiation(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn companion_init_key_negotiation_test_request_new_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_init_key_negotiation_test_request_new_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_secure_random()
        .returning(|_buf| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = CompanionInitKeyNegotiationInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        companion_device_key: DeviceKeyFfi::default(),
        host_device_key: DeviceKeyFfi::default(),
        sec_message: DataArray20000Ffi::default(),
    };
    let mut output = CompanionInitKeyNegotiationOutputFfi { sec_message: DataArray20000Ffi::default() };
    let result = companion_init_key_negotiation(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_init_key_negotiation_test_request_prepare_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_init_key_negotiation_test_request_prepare_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = CompanionInitKeyNegotiationInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        companion_device_key: DeviceKeyFfi::default(),
        host_device_key: DeviceKeyFfi::default(),
        sec_message: DataArray20000Ffi::default(),
    };
    let mut output = CompanionInitKeyNegotiationOutputFfi { sec_message: DataArray20000Ffi::default() };
    let result = companion_init_key_negotiation(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_init_key_negotiation_test_add_request_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_init_key_negotiation_test_add_request_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_generate_x25519_key_pair()
        .returning(|| Ok(create_mock_key_pair()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_companion_request_manager = MockCompanionRequestManager::new();
    mock_companion_request_manager
        .expect_add_request()
        .returning(|| Err(ErrorCode::GeneralError));
    CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

    let sec_key_nego_request = SecKeyNegoRequest { algorithm_list: vec![1] };
    let sec_message = sec_key_nego_request.encode(DeviceType::None).unwrap();

    let input = CompanionInitKeyNegotiationInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        companion_device_key: DeviceKeyFfi::default(),
        host_device_key: DeviceKeyFfi::default(),
        sec_message: DataArray20000Ffi::try_from(&sec_message).unwrap(),
    };
    let mut output = CompanionInitKeyNegotiationOutputFfi { sec_message: DataArray20000Ffi::default() };
    let result = companion_init_key_negotiation(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_begin_add_host_binding_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("companion_begin_add_host_binding_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_x25519_ecdh().returning(|| Ok(Vec::new()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_generate_unique_binding_id()
        .returning(|| Ok(1));
    mock_companion_db_manager
        .expect_get_device_by_device_key()
        .returning(|| Err(ErrorCode::NotFound));
    mock_companion_db_manager.expect_add_device().returning(|| Ok(()));
    mock_companion_db_manager
        .expect_get_device_by_binding_id()
        .returning(|| Ok(create_mock_host_device_info(1)));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Ok(1000));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let companion_request_manager = DefaultCompanionRequestManager::new();
    CompanionRequestManagerRegistry::set(Box::new(companion_request_manager));

    let init_input = CompanionInitKeyNegotiationInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        companion_device_key: DeviceKeyFfi::default(),
        host_device_key: DeviceKeyFfi::default(),
        sec_message: DataArray20000Ffi::default(),
    };
    let mut enroll_request = CompanionDeviceEnrollRequest::new(&init_input).unwrap();
    enroll_request.key_nego_param.key_pair = Some(create_mock_key_pair());
    enroll_request.key_nego_param.host_device_key.device_id = "test-device-id".to_string();
    enroll_request.key_nego_param.host_device_key.user_id = 100;
    enroll_request.key_nego_param.challenge = 0;
    CompanionRequestManagerRegistry::get_mut()
        .add_request(Box::new(enroll_request))
        .unwrap();

    let mut attr = Attribute::new();
    attr.set_string(AttributeKey::AttrDeviceId, "test-device-id".to_string());
    attr.set_i32(AttributeKey::AttrUserId, 100);
    attr.set_u64(AttributeKey::AttrChallenge, 0);

    let sec_binding_request = SecBindingRequest {
        pub_key: vec![1, 2, 3],
        salt: [0u8; HKDF_SALT_SIZE],
        tag: [0u8; AES_GCM_TAG_SIZE],
        iv: [0u8; AES_GCM_IV_SIZE],
        encrypt_data: attr.to_bytes().unwrap(),
    };
    let sec_message = sec_binding_request.encode(DeviceType::None).unwrap();

    let input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(&sec_message).unwrap(),
    };
    let mut output = CompanionBeginAddHostBindingOutputFfi {
        sec_message: DataArray1024Ffi::default(),
        binding_id: -1,
        binding_status: PersistedHostBindingStatusFfi::default(),
    };
    let result = companion_begin_add_host_binding(&input, &mut output);
    assert!(result.is_ok());
    assert_eq!(output.binding_id, 1);
}

#[test]
fn companion_begin_add_host_binding_test_get_request_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_begin_add_host_binding_test_get_request_fail start");

    let mut mock_companion_request_manager = MockCompanionRequestManager::new();
    mock_companion_request_manager.expect_get_request(Ok(())); // No request stored, will return NotFound
    CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

    let input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut output = CompanionBeginAddHostBindingOutputFfi {
        sec_message: DataArray1024Ffi::default(),
        binding_id: -1,
        binding_status: PersistedHostBindingStatusFfi::default(),
    };
    let result = companion_begin_add_host_binding(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn companion_begin_add_host_binding_test_request_begin_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_begin_add_host_binding_test_request_begin_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let companion_request_manager = DefaultCompanionRequestManager::new();
    CompanionRequestManagerRegistry::set(Box::new(companion_request_manager));

    let init_input = CompanionInitKeyNegotiationInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        companion_device_key: DeviceKeyFfi::default(),
        host_device_key: DeviceKeyFfi::default(),
        sec_message: DataArray20000Ffi::default(),
    };
    let enroll_request = CompanionDeviceEnrollRequest::new(&init_input).unwrap();
    CompanionRequestManagerRegistry::get_mut()
        .add_request(Box::new(enroll_request))
        .unwrap();

    let input = CompanionBeginAddHostBindingInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut output = CompanionBeginAddHostBindingOutputFfi {
        sec_message: DataArray1024Ffi::default(),
        binding_id: -1,
        binding_status: PersistedHostBindingStatusFfi::default(),
    };
    let result = companion_begin_add_host_binding(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_end_add_host_binding_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("companion_end_add_host_binding_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager.expect_write_device_token().returning(|| Ok(()));
    mock_companion_db_manager
        .expect_get_device_by_binding_id()
        .returning(|| Ok(create_mock_host_device_info(1)));
    mock_companion_db_manager.expect_update_device().returning(|| Ok(()));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut mock_time_keeper = MockTimeKeeper::new();
    mock_time_keeper.expect_get_rtc_time().returning(|| Ok(1000));
    TimeKeeperRegistry::set(Box::new(mock_time_keeper));

    let init_input = CompanionInitKeyNegotiationInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        companion_device_key: DeviceKeyFfi::default(),
        host_device_key: DeviceKeyFfi::default(),
        sec_message: DataArray20000Ffi::default(),
    };
    let enroll_request = CompanionDeviceEnrollRequest::new(&init_input).unwrap();

    let mut mock_companion_request_manager = MockCompanionRequestManager::new();
    mock_companion_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(enroll_request.clone())));
    CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

    let sec_issue_token = SecIssueToken { challenge: 0, atl: 30000, token: Vec::new() };
    let sec_message = sec_issue_token
        .encrypt_issue_token(&[0u8; SALT_LEN_FFI], DeviceType::None, &[1, 2, 3])
        .unwrap();

    let input = CompanionEndAddHostBindingInputFfi {
        request_id: 1,
        result: 0,
        sec_message: DataArray1024Ffi::try_from(&sec_message).unwrap(),
    };
    let mut output = CompanionEndAddHostBindingOutputFfi { binding_id: -1 };
    let result = companion_end_add_host_binding(&input, &mut output);
    assert!(result.is_ok());
    assert_eq!(output.binding_id, 0);
}

#[test]
fn companion_end_add_host_binding_test_remove_request_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_end_add_host_binding_test_remove_request_fail start");

    let mut mock_companion_request_manager = MockCompanionRequestManager::new();
    mock_companion_request_manager
        .expect_remove_request()
        .returning(|| Err(ErrorCode::NotFound));
    CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

    let input =
        CompanionEndAddHostBindingInputFfi { request_id: 1, result: 0, sec_message: DataArray1024Ffi::default() };
    let mut output = CompanionEndAddHostBindingOutputFfi { binding_id: -1 };
    let result = companion_end_add_host_binding(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn companion_end_add_host_binding_test_request_end_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_end_add_host_binding_test_request_end_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let init_input = CompanionInitKeyNegotiationInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        companion_device_key: DeviceKeyFfi::default(),
        host_device_key: DeviceKeyFfi::default(),
        sec_message: DataArray20000Ffi::default(),
    };
    let enroll_request = CompanionDeviceEnrollRequest::new(&init_input).unwrap();

    let mut mock_companion_request_manager = MockCompanionRequestManager::new();
    mock_companion_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(enroll_request.clone())));
    CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

    let input =
        CompanionEndAddHostBindingInputFfi { request_id: 1, result: 1, sec_message: DataArray1024Ffi::default() };
    let mut output = CompanionEndAddHostBindingOutputFfi { binding_id: -1 };
    let result = companion_end_add_host_binding(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_remove_host_binding_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("companion_remove_host_binding_test_success start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_remove_device()
        .returning(|| Ok(create_mock_host_device_info(123)));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let input = CompanionRemoveHostBindingInputFfi { binding_id: 123 };
    let mut output = CompanionRemoveHostBindingOutputFfi::default();
    let result = companion_remove_host_binding(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn companion_remove_host_binding_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_remove_host_binding_test_fail start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_remove_device()
        .returning(|| Err(ErrorCode::NotFound));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let input = CompanionRemoveHostBindingInputFfi { binding_id: 123 };
    let mut output = CompanionRemoveHostBindingOutputFfi::default();
    let result = companion_remove_host_binding(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn companion_pre_issue_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("companion_pre_issue_token_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_companion_request_manager = MockCompanionRequestManager::new();
    mock_companion_request_manager.expect_add_request().returning(|| Ok(()));
    CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(HostDeviceSk { sk: Vec::new() }));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let sec_pre_issue_request = SecPreIssueRequest { salt: [0u8; HKDF_SALT_SIZE] };
    let sec_message = sec_pre_issue_request.encode(DeviceType::None).unwrap();

    let input = CompanionPreIssueTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(&sec_message).unwrap(),
    };
    let mut output = CompanionPreIssueTokenOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = companion_pre_issue_token(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn companion_pre_issue_token_test_request_new_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_pre_issue_token_test_request_new_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_secure_random()
        .returning(|_buf| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = CompanionPreIssueTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut output = CompanionPreIssueTokenOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = companion_pre_issue_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_pre_issue_token_test_request_begin_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_pre_issue_token_test_request_begin_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = CompanionPreIssueTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut output = CompanionPreIssueTokenOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = companion_pre_issue_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_pre_issue_token_test_add_request_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_pre_issue_token_test_add_request_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_companion_request_manager = MockCompanionRequestManager::new();
    mock_companion_request_manager
        .expect_add_request()
        .returning(|| Err(ErrorCode::GeneralError));
    CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(HostDeviceSk { sk: Vec::new() }));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let sec_pre_issue_request = SecPreIssueRequest { salt: [0u8; HKDF_SALT_SIZE] };
    let sec_message = sec_pre_issue_request.encode(DeviceType::None).unwrap();

    let input = CompanionPreIssueTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(&sec_message).unwrap(),
    };
    let mut output = CompanionPreIssueTokenOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = companion_pre_issue_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_process_issue_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("companion_process_issue_token_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager.expect_write_device_token().returning(|| Ok(()));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let pre_input = CompanionPreIssueTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut issue_token_request = CompanionDeviceIssueTokenRequest::new(&pre_input).unwrap();
    issue_token_request.pre_issue_param.challenge = 0;

    let mut mock_companion_request_manager = MockCompanionRequestManager::new();
    mock_companion_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(issue_token_request.clone())));
    CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

    let sec_issue_token = SecIssueToken { challenge: 0, atl: 30000, token: Vec::new() };
    let sec_message = sec_issue_token
        .encrypt_issue_token(&[0u8; SALT_LEN_FFI], DeviceType::None, &[1, 2, 3])
        .unwrap();

    let input = CompanionProcessIssueTokenInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(&sec_message).unwrap(),
    };
    let mut output = CompanionProcessIssueTokenOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = companion_process_issue_token(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn companion_process_issue_token_test_remove_request_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_process_issue_token_test_remove_request_fail start");

    let mut mock_companion_request_manager = MockCompanionRequestManager::new();
    mock_companion_request_manager
        .expect_remove_request()
        .returning(|| Err(ErrorCode::NotFound));
    CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

    let input = CompanionProcessIssueTokenInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut output = CompanionProcessIssueTokenOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = companion_process_issue_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn companion_process_issue_token_test_request_end_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_process_issue_token_test_request_end_fail start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let pre_input = CompanionPreIssueTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let issue_token_request = CompanionDeviceIssueTokenRequest::new(&pre_input).unwrap();

    let mut mock_companion_request_manager = MockCompanionRequestManager::new();
    mock_companion_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(issue_token_request.clone())));
    CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

    let input = CompanionProcessIssueTokenInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut output = CompanionProcessIssueTokenOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = companion_process_issue_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_cancel_issue_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("companion_cancel_issue_token_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let pre_input = CompanionPreIssueTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let issue_token_request = CompanionDeviceIssueTokenRequest::new(&pre_input).unwrap();

    let mut mock_companion_request_manager = MockCompanionRequestManager::new();
    mock_companion_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(issue_token_request.clone())));
    CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

    let input = CompanionCancelIssueTokenInputFfi { request_id: 1 };
    let mut output = CompanionCancelIssueTokenOutputFfi::default();
    let result = companion_cancel_issue_token(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn companion_cancel_issue_token_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_cancel_issue_token_test_fail start");

    let mut mock_companion_request_manager = MockCompanionRequestManager::new();
    mock_companion_request_manager
        .expect_remove_request()
        .returning(|| Err(ErrorCode::NotFound));
    CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

    let input = CompanionCancelIssueTokenInputFfi { request_id: 1 };
    let mut output = CompanionCancelIssueTokenOutputFfi::default();
    let result = companion_cancel_issue_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn companion_process_token_auth_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("companion_process_token_auth_test_success start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(HostDeviceSk { sk: Vec::new() }));
    mock_companion_db_manager
        .expect_read_device_token()
        .returning(|| Ok(HostTokenInfo { token: Vec::new(), atl: AuthTrustLevel::Atl3 }));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine.expect_hmac_sha256().returning(|_, _| Ok(vec![1, 2, 3]));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut attr = Attribute::new();
    attr.set_u64(AttributeKey::AttrChallenge, 0);

    let sec_common_request = SecCommonRequest {
        salt: [0u8; HKDF_SALT_SIZE],
        tag: [0u8; AES_GCM_TAG_SIZE],
        iv: [0u8; AES_GCM_IV_SIZE],
        encrypt_data: attr.to_bytes().unwrap(),
    };
    let sec_message = sec_common_request.encode(DeviceType::None).unwrap();

    let input = CompanionProcessTokenAuthInputFfi {
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(&sec_message).unwrap(),
    };
    let mut output = CompanionProcessTokenAuthOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = companion_process_token_auth(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn companion_process_token_auth_test_request_begin_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_process_token_auth_test_request_begin_fail start");

    let input = CompanionProcessTokenAuthInputFfi {
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut output = CompanionProcessTokenAuthOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = companion_process_token_auth(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_revoke_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("companion_revoke_token_test_success start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager.expect_delete_device_token().returning(|| Ok(()));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let input = CompanionRevokeTokenInputFfi { binding_id: 123 };
    let mut output = CompanionRevokeTokenOutputFfi::default();
    let result = companion_revoke_token(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn companion_revoke_token_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_revoke_token_test_fail start");

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_delete_device_token()
        .returning(|| Err(ErrorCode::NotFound));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let input = CompanionRevokeTokenInputFfi { binding_id: 123 };
    let mut output = CompanionRevokeTokenOutputFfi::default();
    let result = companion_revoke_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn companion_begin_delegate_auth_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("companion_begin_delegate_auth_test_success start");

    let mut mock_companion_request_manager = MockCompanionRequestManager::new();
    mock_companion_request_manager.expect_add_request().returning(|| Ok(()));
    CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(HostDeviceSk { sk: Vec::new() }));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut attr = Attribute::new();
    attr.set_u64(AttributeKey::AttrChallenge, 0);
    attr.set_i32(AttributeKey::AttrAuthTrustLevel, 30000);

    let sec_common_request = SecCommonRequest {
        salt: [0u8; HKDF_SALT_SIZE],
        tag: [0u8; AES_GCM_TAG_SIZE],
        iv: [0u8; AES_GCM_IV_SIZE],
        encrypt_data: attr.to_bytes().unwrap(),
    };
    let sec_message = sec_common_request.encode(DeviceType::None).unwrap();

    let input = CompanionBeginDelegateAuthInputFfi {
        request_id: 1,
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(&sec_message).unwrap(),
    };
    let mut output = CompanionBeginDelegateAuthOutputFfi { challenge: 1, atl: 0 };
    let result = companion_begin_delegate_auth(&input, &mut output);
    assert!(result.is_ok());
    assert_eq!(output.challenge, 0);
    assert_eq!(output.atl, 30000);
}

#[test]
fn companion_begin_delegate_auth_test_request_begin_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_begin_delegate_auth_test_request_begin_fail start");

    let input = CompanionBeginDelegateAuthInputFfi {
        request_id: 1,
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut output = CompanionBeginDelegateAuthOutputFfi { challenge: 1, atl: 0 };
    let result = companion_begin_delegate_auth(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::BadParam));
}

#[test]
fn companion_begin_delegate_auth_test_add_request_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_begin_delegate_auth_test_add_request_fail start");

    let mut mock_companion_request_manager = MockCompanionRequestManager::new();
    mock_companion_request_manager
        .expect_add_request()
        .returning(|| Err(ErrorCode::GeneralError));
    CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(HostDeviceSk { sk: Vec::new() }));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut attr = Attribute::new();
    attr.set_u64(AttributeKey::AttrChallenge, 0);
    attr.set_i32(AttributeKey::AttrAuthTrustLevel, 30000);

    let sec_common_request = SecCommonRequest {
        salt: [0u8; HKDF_SALT_SIZE],
        tag: [0u8; AES_GCM_TAG_SIZE],
        iv: [0u8; AES_GCM_IV_SIZE],
        encrypt_data: attr.to_bytes().unwrap(),
    };
    let sec_message = sec_common_request.encode(DeviceType::None).unwrap();

    let input = CompanionBeginDelegateAuthInputFfi {
        request_id: 1,
        binding_id: 123,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(&sec_message).unwrap(),
    };
    let mut output = CompanionBeginDelegateAuthOutputFfi { challenge: 1, atl: 0 };
    let result = companion_begin_delegate_auth(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

// TODO
// #[test]
// fn companion_end_delegate_auth_test_success() {
//     let _guard = ut_registry_guard!();
//     log_i!("companion_end_delegate_auth_test_success start");

//     let mut mock_crypto_engine = MockCryptoEngine::new();
//     // mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
//     // mock_crypto_engine.expect_aes_gcm_decrypt().returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
//     // mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| Ok(AesGcmResult { ciphertext: data.to_vec(),
//     //     authentication_tag: [0u8; AES_GCM_TAG_SIZE],
//     // }));
//     CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

//     // let mut mock_companion_db_manager = MockCompanionDbManager::new();
//     // mock_companion_db_manager.expect_write_device_token().returning(|| Ok(()));
//     // CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

//     let begin_input = CompanionBeginDelegateAuthInputFfi {
//         request_id: 1,
//         binding_id: 123,
//         secure_protocol_id: 1,
//         sec_message: DataArray1024Ffi::default(),
//     };
//     let mut delagate_auth_request = CompanionDelegateAuthRequest::new(&begin_input).unwrap();

//     let mut mock_companion_request_manager = MockCompanionRequestManager::new();
//     mock_companion_request_manager.expect_remove_request()
//         .returning(move || Ok(Box::new(delagate_auth_request.clone())));
//     CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

//     let token_data_plain = TokenDataPlain {
//         challenge: [0u8; CHALLENGE_LEN],
//         time: 1000,
//         auth_trust_level: AuthTrustLevel::Atl3,
//         auth_type: AuthType::CompanionDevice,
//         schedule_mode: 1,
//         security_level: AuthSecurityLevel::Asl3,
//         token_type: 1,
//     };
//     let user_auth_token = UserAuthToken {
//         version: 1,
//         token_data_plain,
//         token_data_cipher: [0u8; AUTH_TOKEN_CIPHER_LEN],
//         tag: [0u8; AES_GCM_TAG_SIZE],
//         iv: [0u8; AES_GCM_IV_SIZE],
//         sign: [0u8; SHA256_DIGEST_SIZE],
//     };
//     let serialized = user_auth_token.serialize();
//     let mut auth_token_array = [0u8; AUTH_TOKEN_SIZE_FFI];
//     let len = serialized.len().min(AUTH_TOKEN_SIZE_FFI);
//     auth_token_array[..len].copy_from_slice(&serialized[..len]);

//     let input = CompanionEndDelegateAuthInputFfi {
//         request_id: 1,
//         result: 0,
//         auth_token: auth_token_array,
//     };
//     let mut output = CompanionEndDelegateAuthOutputFfi { sec_message: DataArray1024Ffi::default() };
//     let result = companion_end_delegate_auth(&input, &mut output);
//     assert!(result.is_ok());
// }

#[test]
fn companion_begin_obtain_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("companion_begin_obtain_token_test_success start");

    let mut mock_companion_request_manager = MockCompanionRequestManager::new();
    mock_companion_request_manager.expect_add_request().returning(|| Ok(()));
    CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_get_fwk_pub_key().returning(|| Ok(vec![1u8, 2, 3]));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(HostDeviceSk { sk: Vec::new() }));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut attr = Attribute::new();
    attr.set_u32(AttributeKey::AttrPropertyMode, 6);
    attr.set_u32(AttributeKey::AttrType, 64);
    attr.set_i32(AttributeKey::AttrAuthTrustLevel, 30000);

    let fwk_message_codec = MessageCodec::new(MessageSignParam::Executor(create_mock_key_pair()));
    let fwk_message = fwk_message_codec.serialize_attribute(&attr).unwrap();

    let sec_pre_obtain_token_request = SecPreObtainTokenRequest { salt: [0u8; HKDF_SALT_SIZE], challenge: 0 };
    let sec_message = sec_pre_obtain_token_request.encode(DeviceType::None).unwrap();

    let input = CompanionBeginObtainTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(&sec_message).unwrap(),
    };
    let mut output = CompanionBeginObtainTokenOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = companion_begin_obtain_token(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn companion_begin_obtain_token_test_request_begin_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_begin_obtain_token_test_request_begin_fail start");

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager
        .expect_get_fwk_pub_key()
        .returning(|| Err(ErrorCode::GeneralError));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let input = CompanionBeginObtainTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        fwk_message: DataArray1024Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut output = CompanionBeginObtainTokenOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = companion_begin_obtain_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_begin_obtain_token_test_add_request_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_begin_obtain_token_test_add_request_fail start");

    let mut mock_companion_request_manager = MockCompanionRequestManager::new();
    mock_companion_request_manager
        .expect_add_request()
        .returning(|| Err(ErrorCode::GeneralError));
    CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_ed25519_sign()
        .returning(|_, bytes| Ok(bytes.to_vec()));
    mock_crypto_engine.expect_ed25519_verify().returning(|_, _| Ok(()));
    mock_crypto_engine.expect_hkdf().returning(|_, _| Ok(Vec::new()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_misc_manager = MockMiscManager::new();
    mock_misc_manager.expect_get_fwk_pub_key().returning(|| Ok(vec![1u8, 2, 3]));
    MiscManagerRegistry::set(Box::new(mock_misc_manager));

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager
        .expect_read_device_sk()
        .returning(|| Ok(HostDeviceSk { sk: Vec::new() }));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let mut attr = Attribute::new();
    attr.set_u32(AttributeKey::AttrPropertyMode, 6);
    attr.set_u32(AttributeKey::AttrType, 64);
    attr.set_i32(AttributeKey::AttrAuthTrustLevel, 30000);

    let fwk_message_codec = MessageCodec::new(MessageSignParam::Executor(create_mock_key_pair()));
    let fwk_message = fwk_message_codec.serialize_attribute(&attr).unwrap();

    let sec_pre_obtain_token_request = SecPreObtainTokenRequest { salt: [0u8; HKDF_SALT_SIZE], challenge: 0 };
    let sec_message = sec_pre_obtain_token_request.encode(DeviceType::None).unwrap();

    let input = CompanionBeginObtainTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        fwk_message: DataArray1024Ffi::try_from(&fwk_message).unwrap(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(&sec_message).unwrap(),
    };
    let mut output = CompanionBeginObtainTokenOutputFfi { sec_message: DataArray1024Ffi::default() };
    let result = companion_begin_obtain_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_end_obtain_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("companion_end_obtain_token_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    mock_crypto_engine
        .expect_aes_gcm_decrypt()
        .returning(|_aes_gcm_result| Ok(_aes_gcm_result.ciphertext.clone()));
    mock_crypto_engine.expect_aes_gcm_encrypt().returning(|data, _| {
        Ok(AesGcmResult { ciphertext: data.to_vec(), authentication_tag: [0u8; AES_GCM_TAG_SIZE] })
    });
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let mut mock_companion_db_manager = MockCompanionDbManager::new();
    mock_companion_db_manager.expect_write_device_token().returning(|| Ok(()));
    CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));

    let begin_input = CompanionBeginObtainTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        fwk_message: DataArray1024Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut obtain_token_request = CompanionDeviceObtainTokenRequest::new(&begin_input).unwrap();
    obtain_token_request.obtain_param.challenge = 0;

    let mut mock_companion_request_manager = MockCompanionRequestManager::new();
    mock_companion_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(obtain_token_request.clone())));
    CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

    let sec_issue_token = SecIssueToken { challenge: 0, atl: 30000, token: Vec::new() };
    let sec_message = sec_issue_token
        .encrypt_issue_token(&[0u8; SALT_LEN_FFI], DeviceType::None, &[1, 2, 3])
        .unwrap();

    let input = CompanionEndObtainTokenInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::try_from(&sec_message).unwrap(),
    };
    let mut output = CompanionEndObtainTokenOutputFfi::default();
    let result = companion_end_obtain_token(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn companion_end_obtain_token_test_remove_request_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_end_obtain_token_test_remove_request_fail start");

    let mut mock_companion_request_manager = MockCompanionRequestManager::new();
    mock_companion_request_manager
        .expect_remove_request()
        .returning(|| Err(ErrorCode::NotFound));
    CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

    let input = CompanionEndObtainTokenInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut output = CompanionEndObtainTokenOutputFfi::default();
    let result = companion_end_obtain_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::NotFound));
}

#[test]
fn companion_end_obtain_token_test_request_end_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_end_obtain_token_test_request_end_fail start");

    let begin_input = CompanionBeginObtainTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        fwk_message: DataArray1024Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut obtain_token_request = CompanionDeviceObtainTokenRequest::new(&begin_input).unwrap();
    obtain_token_request.obtain_param.challenge = 0;

    let mut mock_companion_request_manager = MockCompanionRequestManager::new();
    mock_companion_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(obtain_token_request.clone())));
    CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

    let input = CompanionEndObtainTokenInputFfi {
        request_id: 1,
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let mut output = CompanionEndObtainTokenOutputFfi::default();
    let result = companion_end_obtain_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::GeneralError));
}

#[test]
fn companion_cancel_obtain_token_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("companion_cancel_obtain_token_test_success start");

    let begin_input = CompanionBeginObtainTokenInputFfi {
        request_id: 1,
        binding_id: 123,
        fwk_message: DataArray1024Ffi::default(),
        secure_protocol_id: 1,
        sec_message: DataArray1024Ffi::default(),
    };
    let obtain_token_request = CompanionDeviceObtainTokenRequest::new(&begin_input).unwrap();

    let mut mock_companion_request_manager = MockCompanionRequestManager::new();
    mock_companion_request_manager
        .expect_remove_request()
        .returning(move || Ok(Box::new(obtain_token_request.clone())));
    CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

    let input = CompanionCancelObtainTokenInputFfi { request_id: 1 };
    let mut output = CompanionCancelObtainTokenOutputFfi::default();
    let result = companion_cancel_obtain_token(&input, &mut output);
    assert!(result.is_ok());
}

#[test]
fn companion_cancel_obtain_token_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("companion_cancel_obtain_token_test_fail start");

    let mut mock_companion_request_manager = MockCompanionRequestManager::new();
    mock_companion_request_manager
        .expect_remove_request()
        .returning(|| Err(ErrorCode::NotFound));
    CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));

    let input = CompanionCancelObtainTokenInputFfi { request_id: 1 };
    let mut output = CompanionCancelObtainTokenOutputFfi::default();
    let result = companion_cancel_obtain_token(&input, &mut output);
    assert_eq!(result, Err(ErrorCode::NotFound));
}
