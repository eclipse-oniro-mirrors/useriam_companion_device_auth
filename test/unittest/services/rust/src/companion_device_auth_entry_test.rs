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
use crate::entry::companion_device_auth_entry::{handle_rust_command, handle_rust_env_init, handle_rust_env_uninit};
use crate::entry::companion_device_auth_ffi::{
    CommandId, CommonOutputFfi, InitInputFfi, InitOutputFfi, PlaceHolderFfi,
};
use crate::log_i;
use crate::traits::companion_db_manager::{CompanionDbManagerRegistry, MockCompanionDbManager};
use crate::traits::crypto_engine::{CryptoEngineRegistry, KeyPair, MockCryptoEngine};
use crate::traits::host_db_manager::{HostDbManagerRegistry, MockHostDbManager};
use crate::traits::misc_manager::{MiscManagerRegistry, MockMiscManager};
use crate::ut_registry_guard;
use core::mem::size_of;

fn mock_set_init_command_env() {
    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_generate_ed25519_key_pair()
        .returning(|| Ok(KeyPair { pub_key: vec![1u8, 2, 3], pri_key: vec![4u8, 5, 6] }));
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
}

#[test]
fn handle_rust_env_uninit_test() {
    let _guard = ut_registry_guard!();
    log_i!("handle_rust_env_uninit_test start");

    assert!(handle_rust_env_uninit().is_ok());
}

#[test]
fn handle_rust_command_test() {
    let _guard = ut_registry_guard!();
    log_i!("handle_rust_command_test start");

    let mut mock_crypto_engine = MockCryptoEngine::new();
    mock_crypto_engine
        .expect_generate_ed25519_key_pair()
        .returning(|| Err(ErrorCode::GeneralError));
    CryptoEngineRegistry::set(Box::new(mock_crypto_engine));

    let input = [0u8; size_of::<InitInputFfi>()];
    let mut output = [0u8; size_of::<InitOutputFfi>()];
    let mut common_output = [0u8; size_of::<CommonOutputFfi>() + 1];

    assert_eq!(
        handle_rust_command(CommandId::Init as i32, &input, &mut output, &mut common_output),
        Err(ErrorCode::BadParam)
    );

    let mut common_output = [0u8; size_of::<CommonOutputFfi>()];
    assert!(handle_rust_command(CommandId::Init as i32, &input, &mut output, &mut common_output).is_ok());

    mock_set_init_command_env();
    assert!(handle_rust_command(CommandId::Init as i32, &input, &mut output, &mut common_output).is_ok());
    assert!(handle_rust_command(99999, &input, &mut output, &mut common_output).is_ok());
}
