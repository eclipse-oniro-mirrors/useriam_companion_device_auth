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
use crate::entry::companion_device_auth_ffi::HostGetInitKeyNegotiationInputFfi;
use crate::impls::default_host_request_manager::DefaultHostRequestManager;
use crate::log_i;
use crate::request::enroll::host_enroll::HostDeviceEnrollRequest;
use crate::traits::crypto_engine::{CryptoEngineRegistry, MockCryptoEngine};
use crate::traits::host_request_manager::HostRequestManager;
use crate::ut_registry_guard;
use std::boxed::Box;

const MAX_REQUEST_NUM: usize = 50;

fn create_test_host_get_init_key_negotiation_input_ffi(request_id: i32) -> HostGetInitKeyNegotiationInputFfi {
    HostGetInitKeyNegotiationInputFfi { request_id, secure_protocol_id: 1 }
}

fn mock_set_crypto_engine() {
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_secure_random().returning(|_buf| Ok(()));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
}

#[test]
fn default_host_request_manager_add_request_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_request_manager_add_request_test_success start");

    mock_set_crypto_engine();

    let mut manager = DefaultHostRequestManager::new();
    let input = create_test_host_get_init_key_negotiation_input_ffi(1);
    let request = HostDeviceEnrollRequest::new(&input).unwrap();

    let result = manager.add_request(Box::new(request));
    assert!(result.is_ok());
}

#[test]
fn default_host_request_manager_add_request_test_id_exists() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_request_manager_add_request_test_id_exists start");

    mock_set_crypto_engine();

    let mut manager = DefaultHostRequestManager::new();
    let input = create_test_host_get_init_key_negotiation_input_ffi(1);
    let request = HostDeviceEnrollRequest::new(&input).unwrap();

    let _ = manager.add_request(Box::new(request));

    let exist_request = HostDeviceEnrollRequest::new(&input).unwrap();
    let result = manager.add_request(Box::new(exist_request));
    assert_eq!(result, Err(ErrorCode::IdExists));
}

#[test]
fn default_host_request_manager_add_request_test_reached_limit() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_request_manager_add_request_test_reached_limit start");

    mock_set_crypto_engine();

    let mut manager = DefaultHostRequestManager::new();

    for i in 0..MAX_REQUEST_NUM {
        let input = create_test_host_get_init_key_negotiation_input_ffi(i as i32);
        let request = HostDeviceEnrollRequest::new(&input).unwrap();
        let _ = manager.add_request(Box::new(request));
    }

    let input = create_test_host_get_init_key_negotiation_input_ffi(999);
    let request = HostDeviceEnrollRequest::new(&input).unwrap();

    let result = manager.add_request(Box::new(request));
    assert!(result.is_ok());
}

#[test]
fn default_host_request_manager_remove_request_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_request_manager_remove_request_test_success start");

    mock_set_crypto_engine();

    let mut manager = DefaultHostRequestManager::new();
    let input = create_test_host_get_init_key_negotiation_input_ffi(1);
    let request = HostDeviceEnrollRequest::new(&input).unwrap();

    let _ = manager.add_request(Box::new(request));

    let result = manager.remove_request(1);
    assert!(result.is_ok());
}

#[test]
fn default_host_request_manager_remove_request_test_not_found() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_request_manager_remove_request_test_not_found start");

    let mut manager = DefaultHostRequestManager::new();

    let result = manager.remove_request(1);
    assert!(result.is_err());
}

#[test]
fn default_host_request_manager_get_request_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_request_manager_get_request_test_success start");

    mock_set_crypto_engine();

    let mut manager = DefaultHostRequestManager::new();
    let input = create_test_host_get_init_key_negotiation_input_ffi(1);
    let request = HostDeviceEnrollRequest::new(&input).unwrap();

    let _ = manager.add_request(Box::new(request));

    let result = manager.get_request(1);
    assert!(result.is_ok());
}

#[test]
fn default_host_request_manager_get_request_test_not_found() {
    let _guard = ut_registry_guard!();
    log_i!("default_host_request_manager_get_request_test_not_found start");

    let mut manager = DefaultHostRequestManager::new();

    let result = manager.get_request(1);
    assert!(result.is_err());
}
