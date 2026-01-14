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

#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils {
    use super::*;

    use crate::common::constants::*;
    use crate::common::types::*;
    use crate::entry::companion_device_auth_ffi::CommandId;
    use crate::traits::{
        companion_db_manager::{CompanionDbManagerRegistry, MockCompanionDbManager},
        companion_request_manager::{CompanionRequestManagerRegistry, MockCompanionRequestManager},
        crypto_engine::{CryptoEngineRegistry, KeyPair, MockCryptoEngine},
        event_manager::{Event, EventManagerRegistry, MockEventManager},
        host_db_manager::{HostDbManagerRegistry, MockHostDbManager},
        host_request_manager::{HostRequestManagerRegistry, MockHostRequestManager},
        logger::{LogLevel, Logger, LoggerRegistry},
        misc_manager::{MiscManagerRegistry, MockMiscManager},
        storage_io::{MockStorageIo, StorageIo, StorageIoRegistry},
        time_keeper::{MockTimeKeeper, TimeKeeper, TimeKeeperRegistry},
    };
    use crate::{Box, Vec};

    // Test Logger implementation
    pub struct TestLogger;

    impl TestLogger {
        pub fn new() -> Self {
            TestLogger
        }
    }

    impl Logger for TestLogger {
        fn log(&self, level: LogLevel, file_path: &str, line_num: u32, args: core::fmt::Arguments<'_>) {
            const MAX_LOG_LINE_LEN: usize = 256;
            let file_name = file_path.rsplit('/').last().unwrap_or(file_path);
            let prefix = format!("[LOG] [{:?}] [{}:{}] ", level, file_name, line_num);
            let message = format!("{}", args);
            let max_message_len = MAX_LOG_LINE_LEN - prefix.len();
            message
                .chars()
                .collect::<Vec<char>>()
                .chunks(max_message_len)
                .map(|chunk| chunk.iter().collect::<String>())
                .for_each(|line_message| {
                    println!("{}{}", prefix, line_message);
                });
        }
    }

    pub struct UtRegistryGuard {}

    impl UtRegistryGuard {
        pub fn new() -> Self {
            let mock_logger = TestLogger::new();
            LoggerRegistry::set(Box::new(mock_logger));

            let mock_misc_manager = MockMiscManager::new();
            MiscManagerRegistry::set(Box::new(mock_misc_manager));
            let mock_storage_io = MockStorageIo::new();
            StorageIoRegistry::set(Box::new(mock_storage_io));
            let mock_time_keeper = MockTimeKeeper::new();
            TimeKeeperRegistry::set(Box::new(mock_time_keeper));
            let mock_crypto_engine = MockCryptoEngine::new();
            CryptoEngineRegistry::set(Box::new(mock_crypto_engine));
            let mock_event_manager = MockEventManager::new();
            EventManagerRegistry::set(Box::new(mock_event_manager));
            let mock_host_db_manager = MockHostDbManager::new();
            HostDbManagerRegistry::set(Box::new(mock_host_db_manager));
            let mock_companion_db_manager = MockCompanionDbManager::new();
            CompanionDbManagerRegistry::set(Box::new(mock_companion_db_manager));
            let mock_host_request_manager = MockHostRequestManager::new();
            HostRequestManagerRegistry::set(Box::new(mock_host_request_manager));
            let mock_companion_request_manager = MockCompanionRequestManager::new();
            CompanionRequestManagerRegistry::set(Box::new(mock_companion_request_manager));
            Self {}
        }
    }

    impl Drop for UtRegistryGuard {
        fn drop(&mut self) {
            // Reset all registries to default implementation
            LoggerRegistry::reset();
            MiscManagerRegistry::reset();
            CryptoEngineRegistry::reset();
            StorageIoRegistry::reset();
            TimeKeeperRegistry::reset();
            EventManagerRegistry::reset();
            HostDbManagerRegistry::reset();
            CompanionDbManagerRegistry::reset();
            HostRequestManagerRegistry::reset();
            CompanionRequestManagerRegistry::reset();
        }
    }
}

#[macro_export]
macro_rules! ut_registry_guard {
    () => {
        $crate::test_utils::trait_mocks::test_utils::UtRegistryGuard::new()
    };
}
