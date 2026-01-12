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
use crate::entry::companion_device_auth_ffi::*;
use crate::log_i;
use crate::traits::crypto_engine::{CryptoEngineRegistry, MockCryptoEngine};
use crate::ut_registry_guard;
use core::mem::size_of;
use std::ptr;

fn create_rust_command_param(
    input_data: Option<*const u8>,
    input_data_len: Option<u32>,
    output_data: Option<*mut u8>,
    output_data_len: Option<u32>,
    common_output_data: Option<*mut u8>,
    common_output_data_len: Option<u32>,
) -> RustCommandParam {
    RustCommandParam {
        command_id: 1,
        input_data: input_data.unwrap_or(ptr::null()),
        input_data_len: input_data_len.unwrap_or(0),
        output_data: output_data.unwrap_or(ptr::null_mut()),
        output_data_len: output_data_len.unwrap_or(0),
        common_output_data: common_output_data.unwrap_or(ptr::null_mut()),
        common_output_data_len: common_output_data_len.unwrap_or(0),
    }
}

#[test]
fn event_array_ffi_test_default() {
    let _guard = ut_registry_guard!();
    log_i!("event_array_ffi_test_default start");

    let array = EventArrayFfi::default();
    assert_eq!(array.len, 0);
    assert_eq!(array.data.len(), MAX_EVENT_NUM_FFI);
}

#[test]
fn common_output_ffi_test_default() {
    let _guard = ut_registry_guard!();
    log_i!("common_output_ffi_test_default start");

    let output = CommonOutputFfi::default();
    assert_eq!(output.result, 0);
    assert_eq!(output.has_fatal_error, 0);
    assert_eq!(output.events.len, 0);
}

#[test]
fn command_id_test_try_from() {
    let _guard = ut_registry_guard!();
    log_i!("command_id_test_try_from start");

    assert_eq!(CommandId::try_from(1).unwrap(), CommandId::Init);
    assert_eq!(CommandId::try_from(2).unwrap(), CommandId::GetExecutorInfo);
    assert_eq!(CommandId::try_from(1001).unwrap(), CommandId::HostRegisterFinish);
    assert_eq!(CommandId::try_from(1002).unwrap(), CommandId::HostGetPersistedStatus);
    assert_eq!(CommandId::try_from(1003).unwrap(), CommandId::HostBeginCompanionCheck);
    assert_eq!(CommandId::try_from(1004).unwrap(), CommandId::HostEndCompanionCheck);
    assert_eq!(CommandId::try_from(1005).unwrap(), CommandId::HostCancelCompanionCheck);
    assert_eq!(CommandId::try_from(1006).unwrap(), CommandId::HostGetInitKeyNegotiation);
    assert_eq!(CommandId::try_from(1007).unwrap(), CommandId::HostBeginAddCompanion);
    assert_eq!(CommandId::try_from(1008).unwrap(), CommandId::HostEndAddCompanion);
    assert_eq!(CommandId::try_from(1009).unwrap(), CommandId::HostCancelAddCompanion);
    assert_eq!(CommandId::try_from(1010).unwrap(), CommandId::HostRemoveCompanion);
    assert_eq!(CommandId::try_from(1011).unwrap(), CommandId::HostPreIssueToken);
    assert_eq!(CommandId::try_from(1012).unwrap(), CommandId::HostBeginIssueToken);
    assert_eq!(CommandId::try_from(1013).unwrap(), CommandId::HostEndIssueToken);
    assert_eq!(CommandId::try_from(1014).unwrap(), CommandId::HostCancelIssueToken);
    assert_eq!(CommandId::try_from(1015).unwrap(), CommandId::HostBeginTokenAuth);
    assert_eq!(CommandId::try_from(1016).unwrap(), CommandId::HostEndTokenAuth);
    assert_eq!(CommandId::try_from(1017).unwrap(), CommandId::HostRevokeToken);
    assert_eq!(CommandId::try_from(1018).unwrap(), CommandId::HostUpdateCompanionStatus);
    assert_eq!(CommandId::try_from(1019).unwrap(), CommandId::HostUpdateCompanionEnabledBusinessIds);
    assert_eq!(CommandId::try_from(1020).unwrap(), CommandId::HostBeginDelegateAuth);
    assert_eq!(CommandId::try_from(1021).unwrap(), CommandId::HostEndDelegateAuth);
    assert_eq!(CommandId::try_from(1022).unwrap(), CommandId::HostCancelDelegateAuth);
    assert_eq!(CommandId::try_from(1023).unwrap(), CommandId::HostProcessPreObtainToken);
    assert_eq!(CommandId::try_from(1024).unwrap(), CommandId::HostProcessObtainToken);
    assert_eq!(CommandId::try_from(1025).unwrap(), CommandId::HostCancelObtainToken);
    assert_eq!(CommandId::try_from(1026).unwrap(), CommandId::HostActivateToken);
    assert_eq!(CommandId::try_from(1027).unwrap(), CommandId::HostCheckTemplateEnrolled);
    assert_eq!(CommandId::try_from(2000).unwrap(), CommandId::CompanionGetPersistedStatus);
    assert_eq!(CommandId::try_from(2001).unwrap(), CommandId::CompanionProcessCheck);
    assert_eq!(CommandId::try_from(2002).unwrap(), CommandId::CompanionInitKeyNegotiation);
    assert_eq!(CommandId::try_from(2003).unwrap(), CommandId::CompanionBeginAddHostBinding);
    assert_eq!(CommandId::try_from(2004).unwrap(), CommandId::CompanionEndAddHostBinding);
    assert_eq!(CommandId::try_from(2005).unwrap(), CommandId::CompanionRemoveHostBinding);
    assert_eq!(CommandId::try_from(2006).unwrap(), CommandId::CompanionPreIssueToken);
    assert_eq!(CommandId::try_from(2007).unwrap(), CommandId::CompanionProcessIssueToken);
    assert_eq!(CommandId::try_from(2008).unwrap(), CommandId::CompanionCancelIssueToken);
    assert_eq!(CommandId::try_from(2009).unwrap(), CommandId::CompanionProcessTokenAuth);
    assert_eq!(CommandId::try_from(2010).unwrap(), CommandId::CompanionRevokeToken);
    assert_eq!(CommandId::try_from(2011).unwrap(), CommandId::CompanionBeginDelegateAuth);
    assert_eq!(CommandId::try_from(2012).unwrap(), CommandId::CompanionEndDelegateAuth);
    assert_eq!(CommandId::try_from(2013).unwrap(), CommandId::CompanionBeginObtainToken);
    assert_eq!(CommandId::try_from(2014).unwrap(), CommandId::CompanionEndObtainToken);
    assert_eq!(CommandId::try_from(2015).unwrap(), CommandId::CompanionCancelObtainToken);
    assert_eq!(CommandId::try_from(-1), Err(ErrorCode::BadParam));
}

#[test]
fn uninit_rust_env_test() {
    let _guard = ut_registry_guard!();
    log_i!("uninit_rust_env_test start");

    assert_eq!(uninit_rust_env(), 0);
}

#[test]
fn invoke_rust_command_test_success() {
    let _guard = ut_registry_guard!();
    log_i!("invoke_rust_command_test_success start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine.expect_generate_ed25519_key_pair().returning(|| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input_data = Box::new([1u8; size_of::<InitInputFfi>()]);
    let mut output_buffer = Box::new([0u8; size_of::<InitOutputFfi>()]);
    let mut common_output_buffer = Box::new([0u8; size_of::<CommonOutputFfi>()]);

    let param = create_rust_command_param(
        Some(input_data.as_ptr()), Some(input_data.len() as u32),
        Some(output_buffer.as_mut_ptr()), Some(output_buffer.len() as u32),
        Some(common_output_buffer.as_mut_ptr()), Some(common_output_buffer.len() as u32),
    );

    assert_eq!(invoke_rust_command(param), 0);
}

#[test]
fn invoke_rust_command_test_fail() {
    let _guard = ut_registry_guard!();
    log_i!("invoke_rust_command_test_fail start");

    let input_data = Box::new([1u8; 4]);
    let mut output_buffer = Box::new([0u8; 4]);
    let mut common_output_buffer = Box::new([0u8; size_of::<CommonOutputFfi>()]);

    let param = create_rust_command_param(None, None, None, None, None, None);
    assert_eq!(invoke_rust_command(param), ErrorCode::BadParam as i32);

    let param = create_rust_command_param(None, Some(input_data.len() as u32), None, None, None, None);
    assert_eq!(invoke_rust_command(param), ErrorCode::BadParam as i32);

    let param = create_rust_command_param(
        Some(input_data.as_ptr()), Some(input_data.len() as u32), None, None, None, None
    );
    assert_eq!(invoke_rust_command(param), ErrorCode::BadParam as i32);

    let param = create_rust_command_param(
        Some(input_data.as_ptr()), Some(input_data.len() as u32), None, Some(output_buffer.len() as u32), None, None
    );
    assert_eq!(invoke_rust_command(param), ErrorCode::BadParam as i32);

    let param = create_rust_command_param(
        Some(input_data.as_ptr()), Some(input_data.len() as u32), Some(output_buffer.as_mut_ptr()),
        Some(output_buffer.len() as u32), None, None
    );
    assert_eq!(invoke_rust_command(param), ErrorCode::BadParam as i32);

    let param = create_rust_command_param(
        Some(input_data.as_ptr()), Some(input_data.len() as u32), Some(output_buffer.as_mut_ptr()),
        Some(output_buffer.len() as u32), None, Some(common_output_buffer.len() as u32)
    );
    assert_eq!(invoke_rust_command(param), ErrorCode::BadParam as i32);

    let param = create_rust_command_param(
        Some(input_data.as_ptr()), Some(input_data.len() as u32),
        Some(output_buffer.as_mut_ptr()), Some(output_buffer.len() as u32),
        Some(common_output_buffer.as_mut_ptr()), Some(common_output_buffer.len() as u32),
    );
    assert_eq!(invoke_rust_command(param), 0);

    let input_data = Box::new([1u8; size_of::<InitInputFfi>()]);
    let param = create_rust_command_param(
        Some(input_data.as_ptr()), Some(input_data.len() as u32),
        Some(output_buffer.as_mut_ptr()), Some(output_buffer.len() as u32),
        Some(common_output_buffer.as_mut_ptr()), Some(common_output_buffer.len() as u32),
    );
    assert_eq!(invoke_rust_command(param), 0);
}