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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "securec.h"
#include <cstdint>
#include <string>
#include <vector>

#include "companion_device_auth_ffi_util.h"
#include "security_agent.h"

#define LOG_TAG "DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
using namespace testing;
using namespace testing::ext;

class FfiUtilTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp() override;
    void TearDown() override;
};

void FfiUtilTest::SetUpTestCase()
{
}

void FfiUtilTest::TearDownTestCase()
{
}

void FfiUtilTest::SetUp()
{
}

void FfiUtilTest::TearDown()
{
}

// ============================================================================
// Test DecodeDeviceKey - Length Validation
// ============================================================================

HWTEST_F(FfiUtilTest, DecodeDeviceKeyValid, TestSize.Level1)
{
    DeviceKeyFfi ffi;
    ffi.deviceIdType = 1;
    ffi.userId = 100;

    const char *testId = "test_device_id";
    ffi.deviceId.len = strlen(testId);
    ASSERT_EQ(memcpy_s(ffi.deviceId.data, sizeof(ffi.deviceId.data), testId, ffi.deviceId.len), EOK);

    DeviceKey key;
    EXPECT_TRUE(DecodeDeviceKey(ffi, key));
    EXPECT_EQ(key.deviceUserId, 100U);
    EXPECT_EQ(key.deviceId, testId);
}

// ============================================================================
// Test EncodeDeviceKey - Length Validation
// ============================================================================

HWTEST_F(FfiUtilTest, EncodeDeviceKeyValidAndIdTooLong, TestSize.Level1)
{
    // Valid case
    {
        DeviceKey key;
        key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        key.deviceUserId = 42;
        key.deviceId = "test_device_123";

        DeviceKeyFfi ffi = {};

        EXPECT_TRUE(EncodeDeviceKey(key, ffi));
        EXPECT_EQ(ffi.userId, 42U);
    }

    // Invalid case: ID too long
    {
        DeviceKey key;
        key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        key.deviceUserId = 1;
        key.deviceId = std::string(MAX_DATA_LEN_256 + 1, 'A');

        DeviceKeyFfi ffi = {};

        EXPECT_FALSE(EncodeDeviceKey(key, ffi));
    }
}

// ============================================================================
// Test DecodePersistedCompanionStatus - Length Validation
// ============================================================================

HWTEST_F(FfiUtilTest, DecodePersistedCompanionStatusLenValidationTrue, TestSize.Level1)
{
    // Valid case
    {
        PersistedCompanionStatusFfi ffi = {};

        ffi.templateId = 123;
        ffi.hostUserId = 456;
        ffi.enabledBusinessIds.len = 2;
        ffi.enabledBusinessIds.data[0] = 1;
        ffi.enabledBusinessIds.data[1] = 2;
        ffi.companionDeviceKey.deviceId.len = 0;

        PersistedCompanionStatus status;
        EXPECT_TRUE(DecodePersistedCompanionStatus(ffi, status));
        EXPECT_EQ(status.enabledBusinessIds.size(), 2U);
    }
}

HWTEST_F(FfiUtilTest, DecodePersistedCompanionStatusLenValidationFalse, TestSize.Level1)
{
    // Invalid: Business IDs len exceeds max
    {
        PersistedCompanionStatusFfi ffi = {};

        ffi.templateId = 1;
        ffi.hostUserId = 1;
        ffi.enabledBusinessIds.len = sizeof(ffi.enabledBusinessIds.data) / sizeof(ffi.enabledBusinessIds.data[0]) + 1;
        ffi.companionDeviceKey.deviceId.len = 0;

        PersistedCompanionStatus status;
        EXPECT_FALSE(DecodePersistedCompanionStatus(ffi, status));
    }

    // Invalid: Device model len exceeds max
    {
        PersistedCompanionStatusFfi ffi = {};

        ffi.templateId = 1;
        ffi.hostUserId = 1;
        ffi.enabledBusinessIds.len = 0;
        ffi.companionDeviceKey.deviceId.len = 0;
        ffi.deviceModel.len = MAX_DATA_LEN_1024 + 1;

        PersistedCompanionStatus status;
        EXPECT_FALSE(DecodePersistedCompanionStatus(ffi, status));
    }

    // Invalid: Device user name len exceeds max
    {
        PersistedCompanionStatusFfi ffi = {};

        ffi.templateId = 1;
        ffi.hostUserId = 1;
        ffi.enabledBusinessIds.len = 0;
        ffi.companionDeviceKey.deviceId.len = 0;
        ffi.deviceModel.len = 0;
        ffi.deviceUserName.len = MAX_DATA_LEN_1024 + 1;

        PersistedCompanionStatus status;
        EXPECT_FALSE(DecodePersistedCompanionStatus(ffi, status));
    }

    // Invalid: Device name len exceeds max
    {
        PersistedCompanionStatusFfi ffi = {};

        ffi.templateId = 1;
        ffi.hostUserId = 1;
        ffi.enabledBusinessIds.len = 0;
        ffi.companionDeviceKey.deviceId.len = 0;
        ffi.deviceModel.len = 0;
        ffi.deviceUserName.len = 0;
        ffi.deviceName.len = MAX_DATA_LEN_1024 + 1;

        PersistedCompanionStatus status;
        EXPECT_FALSE(DecodePersistedCompanionStatus(ffi, status));
    }
}

// ============================================================================
// Test EncodePersistedCompanionStatus - Length Validation
// ============================================================================

HWTEST_F(FfiUtilTest, EncodePersistedCompanionStatusLenValidation, TestSize.Level1)
{
    // Valid case
    {
        PersistedCompanionStatus status;
        status.templateId = 789;
        status.hostUserId = 321;
        status.secureProtocolId = SecureProtocolId::DEFAULT;
        status.isValid = true;
        status.enabledBusinessIds = { 1, 3, 5 };
        status.deviceModelInfo = "Model X";

        PersistedCompanionStatusFfi ffi = {};

        EXPECT_TRUE(EncodePersistedCompanionStatus(status, ffi));
        EXPECT_EQ(ffi.enabledBusinessIds.len, 3U);
    }

    // Invalid: Too many business IDs
    {
        PersistedCompanionStatus status;
        status.templateId = 1;
        status.hostUserId = 1;
        status.secureProtocolId = SecureProtocolId::DEFAULT;

        for (int i = 0; i < 100; ++i) {
            status.enabledBusinessIds.push_back(i);
        }

        PersistedCompanionStatusFfi ffi = {};

        EXPECT_FALSE(EncodePersistedCompanionStatus(status, ffi));
    }

    // Invalid: Device info too long
    {
        PersistedCompanionStatus status;
        status.templateId = 1;
        status.hostUserId = 1;
        status.secureProtocolId = SecureProtocolId::DEFAULT;
        status.deviceModelInfo = std::string(MAX_DATA_LEN_1024 + 1, 'A');

        PersistedCompanionStatusFfi ffi = {};

        EXPECT_FALSE(EncodePersistedCompanionStatus(status, ffi));
    }
}

// ============================================================================
// Test DecodePersistedHostBindingStatus - Length Validation
// ============================================================================

HWTEST_F(FfiUtilTest, DecodePersistedHostBindingStatusValid, TestSize.Level1)
{
    PersistedHostBindingStatusFfi ffi = {};

    ffi.bindingId = 555;
    ffi.companionUserId = 888;
    ffi.isTokenValid = 1;
    ffi.hostDeviceKey.deviceIdType = 1;
    ffi.hostDeviceKey.userId = 111;
    ffi.hostDeviceKey.deviceId.len = 0;

    PersistedHostBindingStatus status;
    EXPECT_TRUE(DecodePersistedHostBindingStatus(ffi, status));
    EXPECT_EQ(status.bindingId, 555U);
}

// ============================================================================
// Test DecodeExecutorInfo - Length Validation
// ============================================================================

HWTEST_F(FfiUtilTest, DecodeExecutorInfoLenValidation, TestSize.Level1)
{
    // Valid case
    {
        GetExecutorInfoOutputFfi ffi = {};

        ffi.esl = 5;
        ffi.maxTemplateAcl = 100;
        ffi.publicKey.len = MAX_DATA_LEN_1024;
        for (uint32_t i = 0; i < ffi.publicKey.len; ++i) {
            ffi.publicKey.data[i] = static_cast<uint8_t>(i % 256);
        }

        SecureExecutorInfo info;
        EXPECT_TRUE(DecodeExecutorInfo(ffi, info));
        EXPECT_EQ(info.publicKey.size(), MAX_DATA_LEN_1024);
    }

    // Invalid: Public key len exceeds max
    {
        GetExecutorInfoOutputFfi ffi = {};

        ffi.esl = 5;
        ffi.maxTemplateAcl = 100;
        ffi.publicKey.len = MAX_DATA_LEN_1024 + 1;

        SecureExecutorInfo info;
        EXPECT_FALSE(DecodeExecutorInfo(ffi, info));
    }
}

// ============================================================================
// Test DecodeEvent and DecodeEventArray - Length Validation
// ============================================================================

HWTEST_F(FfiUtilTest, DecodeEventLenValidation, TestSize.Level1)
{
    // Valid case
    {
        EventFfi ffi = {};

        ffi.time = 123456789;
        ffi.lineNumber = 42;
        const char *fileName = "test.cpp";
        ffi.fileName.len = strlen(fileName);
        ASSERT_EQ(memcpy_s(ffi.fileName.data, sizeof(ffi.fileName.data), fileName, ffi.fileName.len), EOK);
        ffi.eventInfo.len = 0;

        Event event;
        EXPECT_TRUE(DecodeEvent(ffi, event));
        EXPECT_EQ(event.fileName, fileName);
    }

    // Invalid: File name len exceeds max (DataArray64)
    {
        EventFfi ffi = {};

        ffi.fileName.len = MAX_DATA_LEN_64 + 1;
        ffi.eventInfo.len = 0;

        Event event;
        EXPECT_FALSE(DecodeEvent(ffi, event));
    }

    // Invalid: Event info len exceeds max (DataArray256)
    {
        EventFfi ffi = {};

        ffi.fileName.len = 0;
        ffi.eventInfo.len = MAX_DATA_LEN_256 + 1;

        Event event;
        EXPECT_FALSE(DecodeEvent(ffi, event));
    }
}

HWTEST_F(FfiUtilTest, DecodeEventArrayLenValidation, TestSize.Level1)
{
    // Valid case: at max size
    {
        EventArrayFfi ffi = {};
        ffi.len = MAX_EVENT_NUM_FFI;

        for (uint32_t i = 0; i < ffi.len; ++i) {
            ffi.data[i].time = i;
            ffi.data[i].fileName.len = 0;
            ffi.data[i].eventInfo.len = 0;
        }

        std::vector<Event> events;
        EXPECT_TRUE(DecodeEventArray(ffi, events));
        EXPECT_EQ(events.size(), MAX_EVENT_NUM_FFI);
    }

    // Invalid: Event count exceeds max
    {
        EventArrayFfi ffi = {};
        ffi.len = MAX_EVENT_NUM_FFI + 1;

        std::vector<Event> events;
        EXPECT_FALSE(DecodeEventArray(ffi, events));
    }

    // Invalid: Inner event has invalid field
    {
        EventArrayFfi ffi = {};
        ffi.len = 2;

        ffi.data[0].time = 1;
        ffi.data[0].fileName.len = 0;
        ffi.data[0].eventInfo.len = 0;

        ffi.data[1].time = 2;
        ffi.data[1].fileName.len = MAX_DATA_LEN_64 + 1;
        ffi.data[1].eventInfo.len = 0;

        std::vector<Event> events;
        EXPECT_FALSE(DecodeEventArray(ffi, events));
    }
}

// ============================================================================
// Test DecodeCommonOutput
// ============================================================================

HWTEST_F(FfiUtilTest, DecodeCommonOutputValid, TestSize.Level1)
{
    CommonOutputFfi ffi = {};

    ffi.result = 0;
    ffi.hasFatalError = 0;
    ffi.events.len = 0;

    CommonOutput output;
    EXPECT_TRUE(DecodeCommonOutput(ffi, output));
    EXPECT_EQ(output.result, 0);
    EXPECT_FALSE(output.hasFatalError);
}

// ============================================================================
// Test DecodePersistedCompanionStatusList - Length Validation
// ============================================================================

HWTEST_F(FfiUtilTest, DecodePersistedCompanionStatusListLenValidation, TestSize.Level1)
{
    // Invalid: Array len exceeds max
    {
        CompanionStatusArrayFfi ffi = {};

        ffi.len = sizeof(ffi.data) / sizeof(ffi.data[0]) + 1;

        std::vector<PersistedCompanionStatus> list;
        EXPECT_FALSE(DecodePersistedCompanionStatusList(ffi, list));
    }
}

// ============================================================================
// Test DecodePersistedHostBindingStatusList - Length Validation
// ============================================================================

HWTEST_F(FfiUtilTest, DecodePersistedHostBindingStatusListLenValidation, TestSize.Level1)
{
    // Invalid: Array len exceeds max
    {
        HostBindingStatusArrayFfi ffi = {};

        ffi.len = sizeof(ffi.data) / sizeof(ffi.data[0]) + 1;

        std::vector<PersistedHostBindingStatus> list;
        EXPECT_FALSE(DecodePersistedHostBindingStatusList(ffi, list));
    }
}

// ============================================================================
// Test EncodeCompanionProcessCheckInput - Salt Size Validation
// ============================================================================

HWTEST_F(FfiUtilTest, EncodeCompanionProcessCheckInputSaltSizeValidation, TestSize.Level1)
{
    // Invalid: Salt too small
    {
        CompanionProcessCheckInput input;
        input.bindingId = 1;
        input.secureProtocolId = SecureProtocolId::DEFAULT;
        input.challenge = 123;
        input.salt.clear();

        CompanionProcessCheckInputFfi ffi = {};

        EXPECT_FALSE(EncodeCompanionProcessCheckInput(input, ffi));
    }

    // Invalid: Salt too large
    {
        CompanionProcessCheckInput input;
        input.bindingId = 1;
        input.secureProtocolId = SecureProtocolId::DEFAULT;
        input.challenge = 123;
        input.salt.resize(SALT_LEN_FFI + 1, 0xAA);

        CompanionProcessCheckInputFfi ffi = {};

        EXPECT_FALSE(EncodeCompanionProcessCheckInput(input, ffi));
    }

    // Valid: Salt size correct
    {
        CompanionProcessCheckInput input;
        input.bindingId = 1;
        input.secureProtocolId = SecureProtocolId::DEFAULT;
        input.challenge = 123;
        input.salt.resize(SALT_LEN_FFI, 0xCC);
        input.capabilityList = { 1, 2 };
        input.companionCheckRequest = { 0xAA, 0xBB };

        CompanionProcessCheckInputFfi ffi = {};

        EXPECT_TRUE(EncodeCompanionProcessCheckInput(input, ffi));
        EXPECT_EQ(ffi.bindingId, 1U);
    }
}

// ============================================================================
// Test EncodeCompanionEndDelegateAuthInput - Auth Token Size Validation
// ============================================================================

HWTEST_F(FfiUtilTest, EncodeCompanionEndDelegateAuthInputAuthTokenSizeValidation, TestSize.Level1)
{
    // Invalid: Token too small
    {
        CompanionDelegateAuthEndInput input;
        input.requestId = 1;
        input.resultCode = static_cast<ResultCode>(0);
        input.authToken.clear();

        CompanionEndDelegateAuthInputFfi ffi = {};

        EXPECT_FALSE(EncodeCompanionEndDelegateAuthInput(input, ffi));
    }

    // Invalid: Token too large
    {
        CompanionDelegateAuthEndInput input;
        input.requestId = 1;
        input.resultCode = static_cast<ResultCode>(0);
        input.authToken.resize(AUTH_TOKEN_SIZE_FFI + 1, 0xBB);

        CompanionEndDelegateAuthInputFfi ffi = {};

        EXPECT_FALSE(EncodeCompanionEndDelegateAuthInput(input, ffi));
    }

    // Valid: Token size correct
    {
        CompanionDelegateAuthEndInput input;
        input.requestId = 1;
        input.resultCode = static_cast<ResultCode>(0);
        input.authToken.resize(AUTH_TOKEN_SIZE_FFI, 0xDD);

        CompanionEndDelegateAuthInputFfi ffi = {};

        EXPECT_TRUE(EncodeCompanionEndDelegateAuthInput(input, ffi));
        EXPECT_EQ(ffi.requestId, 1U);
    }
}

// ============================================================================
// Test Round-trip: Encode then Decode
// ============================================================================

HWTEST_F(FfiUtilTest, RoundTripDeviceKey, TestSize.Level1)
{
    DeviceKey originalKey;
    originalKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    originalKey.deviceUserId = 999;
    originalKey.deviceId = "original_device_id_12345";

    DeviceKeyFfi ffi = {};
    EXPECT_TRUE(EncodeDeviceKey(originalKey, ffi));

    DeviceKey decodedKey;
    EXPECT_TRUE(DecodeDeviceKey(ffi, decodedKey));

    EXPECT_EQ(decodedKey.idType, originalKey.idType);
    EXPECT_EQ(decodedKey.deviceUserId, originalKey.deviceUserId);
    EXPECT_EQ(decodedKey.deviceId, originalKey.deviceId);
}

HWTEST_F(FfiUtilTest, RoundTripCompanionStatus, TestSize.Level1)
{
    PersistedCompanionStatus originalStatus;
    originalStatus.templateId = 555;
    originalStatus.hostUserId = 10;
    originalStatus.addedTime = 1000;
    originalStatus.secureProtocolId = SecureProtocolId::DEFAULT;
    originalStatus.isValid = true;
    originalStatus.enabledBusinessIds = { 1, 2 };
    originalStatus.deviceModelInfo = "Test Device";

    DeviceKey key;
    key.idType = DeviceIdType::MAC_ADDRESS;
    key.deviceUserId = 50;
    key.deviceId = "AA:BB:CC:DD:EE:FF";
    originalStatus.companionDeviceKey = key;

    PersistedCompanionStatusFfi ffi = {};
    EXPECT_TRUE(EncodePersistedCompanionStatus(originalStatus, ffi));

    PersistedCompanionStatus decodedStatus;
    EXPECT_TRUE(DecodePersistedCompanionStatus(ffi, decodedStatus));

    EXPECT_EQ(decodedStatus.templateId, originalStatus.templateId);
    EXPECT_EQ(decodedStatus.hostUserId, originalStatus.hostUserId);
    EXPECT_EQ(decodedStatus.isValid, originalStatus.isValid);
    EXPECT_EQ(decodedStatus.enabledBusinessIds.size(), originalStatus.enabledBusinessIds.size());
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
