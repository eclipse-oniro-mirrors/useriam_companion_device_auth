/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef COMPANION_DEVICE_AUTH_FUZZ_CONSTANTS_H
#define COMPANION_DEVICE_AUTH_FUZZ_CONSTANTS_H

#include <cstddef>

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// Fuzz data consumption limits for different data types
// These constants define the maximum number of bytes to consume from the fuzzed input
// for different types of data, enabling varied data sizes for better fuzzing coverage.

// ============================================================================
// Cryptographic Data Types
// ============================================================================
// Maximum length for salt and cryptographic material
constexpr size_t FUZZ_MAX_SALT_LENGTH = 128;

// Maximum length for keys and key material
constexpr size_t FUZZ_MAX_KEY_LENGTH = 256;

// ============================================================================
// Protocol Message Types (varied sizes for better fuzzing coverage)
// ============================================================================
// Small protocol messages (e.g., simple requests/replies)
constexpr size_t FUZZ_MAX_SMALL_MESSAGE_LENGTH = 256;

// Standard protocol messages/requests/replies (default size)
constexpr size_t FUZZ_MAX_MESSAGE_LENGTH = 512;

// Large protocol messages (e.g., complex key negotiation messages)
constexpr size_t FUZZ_MAX_LARGE_MESSAGE_LENGTH = 1024;

// ============================================================================
// Specific Data Types
// ============================================================================
// Token data (pre-issued tokens, issue tokens, obtain tokens, etc.)
constexpr size_t FUZZ_MAX_TOKEN_LENGTH = 256;

// Framework messages (FWK messages from host/companion)
constexpr size_t FUZZ_MAX_FWK_MESSAGE_LENGTH = 512;

// Response data from checks and operations
constexpr size_t FUZZ_MAX_RESPONSE_LENGTH = 512;

// ============================================================================
// Fuzz Test Execution Parameters
// ============================================================================
// Maximum number of iterations in fuzzing test loops
constexpr uint32_t FUZZ_MAX_LOOP_COUNT = 100;

// Maximum number of operations in switch statements (adjust per test)
constexpr uint8_t FUZZ_BASE_OPERATIONS = 6;

// Maximum list/vector sizes for various data structures
constexpr uint8_t FUZZ_MAX_DEVICE_STATUS_COUNT = 10;
constexpr uint8_t FUZZ_MAX_DEVICE_KEY_COUNT = 5;
constexpr uint8_t FUZZ_MAX_CAPABILITIES_COUNT = 8;
constexpr uint8_t FUZZ_MAX_BUSINESS_IDS_COUNT = 10;
constexpr uint8_t FUZZ_MAX_PROTOCOLS_COUNT = 5;
constexpr uint8_t FUZZ_MAX_ATTRIBUTES_COUNT = 20;

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_FUZZ_CONSTANTS_H
