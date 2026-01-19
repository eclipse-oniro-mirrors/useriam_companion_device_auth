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

#include <cstdint>
#include <string>
#include <vector>

#include "securec.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "companion_device_auth_ffi_util.h"
#include "security_agent.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
constexpr size_t SIZE_1025 = 1025;
constexpr size_t SIZE_280 = 280;
} // namespace

constexpr int32_t INT32_42 = 42;
constexpr int32_t INT32_123 = 123;
constexpr int32_t INT32_200 = 200;
constexpr int32_t INT32_222 = 222;
constexpr int32_t INT32_333 = 333;
constexpr int32_t INT32_256 = 256;
constexpr int32_t INT32_321 = 321;
constexpr int32_t INT32_444 = 444;
constexpr int32_t INT32_456 = 456;
constexpr int32_t INT32_555 = 555;
constexpr int32_t INT32_999 = 999;
constexpr int32_t INT32_666 = 666;
constexpr int32_t INT32_2222 = 2222;
constexpr int32_t INT32_3333 = 3333;
constexpr int32_t INT32_4444 = 4444;
constexpr int32_t INT32_5555 = 5555;
constexpr int32_t INT32_6666 = 6666;
constexpr int32_t INT32_7777 = 7777;
constexpr int32_t INT32_8888 = 8888;
constexpr int32_t INT32_9999 = 9999;
constexpr int32_t INT32_99999 = 99999;
constexpr int32_t INT32_20000 = 20000;
constexpr int32_t INT32_21000 = 21000;
constexpr int32_t INT32_22000 = 22000;
constexpr int32_t INT32_23000 = 23000;
constexpr int32_t INT32_24000 = 24000;
constexpr int32_t INT32_25000 = 25000;
constexpr int32_t INT32_26000 = 26000;
constexpr int32_t INT32_27000 = 27000;
constexpr int32_t INT32_28000 = 28000;
constexpr int32_t INT32_54321 = 54321;

constexpr uint8_t UINT8_0X00 = 0x00;
constexpr uint8_t UINT8_0X11 = 0x11;
constexpr uint8_t UINT8_0X12 = 0x12;
constexpr uint8_t UINT8_0X22 = 0x22;
constexpr uint8_t UINT8_0X33 = 0x33;
constexpr uint8_t UINT8_0X34 = 0x34;
constexpr uint8_t UINT8_0X44 = 0x44;
constexpr uint8_t UINT8_0X55 = 0x55;
constexpr uint8_t UINT8_0X56 = 0x56;
constexpr uint8_t UINT8_0X66 = 0x66;
constexpr uint8_t UINT8_0X77 = 0x77;
constexpr uint8_t UINT8_0X78 = 0x78;
constexpr uint8_t UINT8_0X88 = 0x88;
constexpr uint8_t UINT8_0X99 = 0x99;
constexpr uint8_t UINT8_0X9A = 0x9A;
constexpr uint8_t UINT8_0XAA = 0xAA;
constexpr uint8_t UINT8_0XBB = 0xBB;
constexpr uint8_t UINT8_0XBC = 0xBC;
constexpr uint8_t UINT8_0XCC = 0xCC;
constexpr uint8_t UINT8_0XDD = 0xDD;
constexpr uint8_t UINT8_0XDE = 0xDE;
constexpr uint8_t UINT8_0XEE = 0xEE;
constexpr uint8_t UINT8_0XFF = 0xFF;
constexpr uint8_t UINT8_0XF0 = 0xF0;
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
        key.deviceUserId = INT32_42;
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

        ffi.templateId = INT32_123;
        ffi.hostUserId = INT32_456;
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
        status.templateId = INT32_999;
        status.hostUserId = INT32_321;
        status.secureProtocolId = SecureProtocolId::DEFAULT;
        status.isValid = true;
        status.enabledBusinessIds = { static_cast<BusinessId>(1), static_cast<BusinessId>(3),
            static_cast<BusinessId>(5) };
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
            status.enabledBusinessIds.push_back(static_cast<BusinessId>(i));
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

    ffi.bindingId = INT32_555;
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
            ffi.publicKey.data[i] = static_cast<uint8_t>(i % INT32_256);
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
        ffi.lineNumber = INT32_42;
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
    // Valid: Empty salt is allowed
    {
        CompanionProcessCheckInput input;
        input.bindingId = 1;
        input.secureProtocolId = SecureProtocolId::DEFAULT;
        input.challenge = INT32_123;
        input.salt.clear();

        CompanionProcessCheckInputFfi ffi = {};

        EXPECT_TRUE(EncodeCompanionProcessCheckInput(input, ffi));
    }

    // Invalid: Salt too large
    {
        CompanionProcessCheckInput input;
        input.bindingId = 1;
        input.secureProtocolId = SecureProtocolId::DEFAULT;
        input.challenge = INT32_123;
        input.salt.resize(SALT_LEN_FFI + 1, UINT8_0XAA);

        CompanionProcessCheckInputFfi ffi = {};

        EXPECT_FALSE(EncodeCompanionProcessCheckInput(input, ffi));
    }

    // Valid: Salt size correct
    {
        CompanionProcessCheckInput input;
        input.bindingId = 1;
        input.secureProtocolId = SecureProtocolId::DEFAULT;
        input.challenge = INT32_123;
        input.salt.resize(SALT_LEN_FFI, UINT8_0XCC);
        input.capabilityList = { 1, 2 };
        input.companionCheckRequest = { UINT8_0XAA, UINT8_0XBB };

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
    // Valid: Empty token is allowed
    {
        CompanionDelegateAuthEndInput input;
        input.requestId = 1;
        input.resultCode = static_cast<ResultCode>(0);
        input.authToken.clear();

        CompanionEndDelegateAuthInputFfi ffi = {};

        EXPECT_TRUE(EncodeCompanionEndDelegateAuthInput(input, ffi));
    }

    // Invalid: Token too large
    {
        CompanionDelegateAuthEndInput input;
        input.requestId = 1;
        input.resultCode = static_cast<ResultCode>(0);
        input.authToken.resize(SIZE_1025, UINT8_0XBB);

        CompanionEndDelegateAuthInputFfi ffi = {};

        EXPECT_FALSE(EncodeCompanionEndDelegateAuthInput(input, ffi));
    }

    // Valid: Token size correct
    {
        CompanionDelegateAuthEndInput input;
        input.requestId = 1;
        input.resultCode = static_cast<ResultCode>(0);
        input.authToken.resize(SIZE_280, UINT8_0XDD);

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
    originalStatus.templateId = INT32_555;
    originalStatus.hostUserId = 10;
    originalStatus.addedTime = 1000;
    originalStatus.secureProtocolId = SecureProtocolId::DEFAULT;
    originalStatus.isValid = true;
    originalStatus.enabledBusinessIds = { static_cast<BusinessId>(1), static_cast<BusinessId>(2) };
    originalStatus.deviceModelInfo = "Test Device";

    DeviceKey key;
    key.idType = DeviceIdType::UNIFIED_DEVICE_ID;
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

HWTEST_F(FfiUtilTest, EncodeHostRegisterFinishInput_001, TestSize.Level0)
{
    RegisterFinishInput input;
    input.templateIdList = { 1, 2, 3 };
    input.fwkPublicKey = { UINT8_0XAA, UINT8_0XBB, UINT8_0XCC };
    input.fwkMsg = { UINT8_0X11, UINT8_0X22, UINT8_0X33 };

    HostRegisterFinishInputFfi ffi = {};
    EXPECT_TRUE(EncodeHostRegisterFinishInput(input, ffi));
    EXPECT_EQ(ffi.templateIds.len, 3U);
}

HWTEST_F(FfiUtilTest, EncodeHostRegisterFinishInput_002, TestSize.Level0)
{
    RegisterFinishInput input;
    for (int i = 0; i < 100; ++i) {
        input.templateIdList.push_back(i);
    }

    HostRegisterFinishInputFfi ffi = {};
    EXPECT_FALSE(EncodeHostRegisterFinishInput(input, ffi));
}

HWTEST_F(FfiUtilTest, EncodeHostEndCompanionCheckInput_001, TestSize.Level0)
{
    HostEndCompanionCheckInput input;
    input.requestId = INT32_123;
    input.templateId = INT32_456;
    input.secureProtocolId = SecureProtocolId::DEFAULT;
    input.protocolVersionList = { 1, 2 };
    input.capabilityList = { 10, 20 };
    input.companionCheckResponse = { UINT8_0XAA, UINT8_0XBB };

    HostEndCompanionCheckInputFfi ffi = {};
    EXPECT_TRUE(EncodeHostEndCompanionCheckInput(input, ffi));
    EXPECT_EQ(ffi.requestId, 123U);
    EXPECT_EQ(ffi.templateId, 456U);
}

HWTEST_F(FfiUtilTest, EncodeHostGetInitKeyNegotiationInput_001, TestSize.Level0)
{
    HostGetInitKeyNegotiationRequestInput input;
    input.requestId = 111;
    input.secureProtocolId = SecureProtocolId::DEFAULT;

    HostGetInitKeyNegotiationInputFfi ffi = {};
    EXPECT_TRUE(EncodeHostGetInitKeyNegotiationInput(input, ffi));
    EXPECT_EQ(ffi.requestId, 111U);
}

HWTEST_F(FfiUtilTest, DecodeHostInitKeyNegotiationOutput_001, TestSize.Level0)
{
    HostGetInitKeyNegotiationOutputFfi ffi = {};
    ffi.secMessage.len = 3;
    ffi.secMessage.data[0] = UINT8_0XAA;
    ffi.secMessage.data[1] = UINT8_0XBB;
    ffi.secMessage.data[2] = UINT8_0XCC;

    HostGetInitKeyNegotiationRequestOutput output;
    EXPECT_TRUE(DecodeHostInitKeyNegotiationOutput(ffi, output));
    EXPECT_EQ(output.initKeyNegotiationRequest.size(), 3U);
}

HWTEST_F(FfiUtilTest, EncodeHostBeginAddCompanionInput_001, TestSize.Level0)
{
    HostBeginAddCompanionInput input;
    input.requestId = INT32_222;
    input.scheduleId = INT32_333;
    input.secureProtocolId = SecureProtocolId::DEFAULT;
    input.hostDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    input.hostDeviceKey.deviceUserId = 100;
    input.hostDeviceKey.deviceId = "host-device";
    input.companionDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    input.companionDeviceKey.deviceUserId = INT32_200;
    input.companionDeviceKey.deviceId = "companion-device";
    input.fwkMsg = { UINT8_0X11, UINT8_0X22 };
    input.initKeyNegotiationReply = { UINT8_0X33, UINT8_0X44 };

    HostBeginAddCompanionInputFfi ffi = {};
    EXPECT_TRUE(EncodeHostBeginAddCompanionInput(input, ffi));
    EXPECT_EQ(ffi.requestId, 222U);
    EXPECT_EQ(ffi.scheduleId, 333U);
}

HWTEST_F(FfiUtilTest, DecodeHostBeginAddCompanionOutput_001, TestSize.Level0)
{
    HostBeginAddCompanionOutputFfi ffi = {};
    ffi.secMessage.len = 2;
    ffi.secMessage.data[0] = UINT8_0XDD;
    ffi.secMessage.data[1] = UINT8_0XEE;

    HostBeginAddCompanionOutput output;
    EXPECT_TRUE(DecodeHostBeginAddCompanionOutput(ffi, output));
    EXPECT_EQ(output.addHostBindingRequest.size(), 2U);
}

HWTEST_F(FfiUtilTest, EncodeHostEndAddCompanionInput_001, TestSize.Level0)
{
    HostEndAddCompanionInput input;
    input.requestId = INT32_444;
    input.secureProtocolId = SecureProtocolId::DEFAULT;
    input.companionStatus.templateId = INT32_555;
    input.companionStatus.hostUserId = INT32_666;
    input.companionStatus.secureProtocolId = SecureProtocolId::DEFAULT;
    input.addHostBindingReply = { UINT8_0X55, UINT8_0X66 };

    HostEndAddCompanionInputFfi ffi = {};
    EXPECT_TRUE(EncodeHostEndAddCompanionInput(input, ffi));
    EXPECT_EQ(ffi.requestId, 444U);
}

HWTEST_F(FfiUtilTest, DecodeHostEndAddCompanionOutput_001, TestSize.Level0)
{
    HostEndAddCompanionOutputFfi ffi = {};
    ffi.templateId = 777;
    ffi.fwkMessage.len = 2;
    ffi.fwkMessage.data[0] = UINT8_0X77;
    ffi.fwkMessage.data[1] = UINT8_0X88;

    HostEndAddCompanionOutput output;
    EXPECT_TRUE(DecodeHostEndAddCompanionOutput(ffi, output));
    EXPECT_EQ(output.templateId, 777U);
    EXPECT_EQ(output.fwkMsg.size(), 2U);
}

HWTEST_F(FfiUtilTest, EncodeHostPreIssueTokenInput_001, TestSize.Level0)
{
    HostPreIssueTokenInput input;
    input.requestId = 888;
    input.templateId = 999;
    input.fwkUnlockMsg = { UINT8_0X99, UINT8_0XAA };

    HostPreIssueTokenInputFfi ffi = {};
    EXPECT_TRUE(EncodeHostPreIssueTokenInput(input, ffi));
    EXPECT_EQ(ffi.requestId, 888U);
    EXPECT_EQ(ffi.templateId, 999U);
}

HWTEST_F(FfiUtilTest, DecodeHostPreIssueTokenOutput_001, TestSize.Level0)
{
    HostPreIssueTokenOutputFfi ffi = {};
    ffi.secMessage.len = 3;
    ffi.secMessage.data[0] = UINT8_0XBB;
    ffi.secMessage.data[1] = UINT8_0XCC;
    ffi.secMessage.data[2] = UINT8_0XDD;

    HostPreIssueTokenOutput output;
    EXPECT_TRUE(DecodeHostPreIssueTokenOutput(ffi, output));
    EXPECT_EQ(output.preIssueTokenRequest.size(), 3U);
}

HWTEST_F(FfiUtilTest, EncodeHostBeginIssueTokenInput_001, TestSize.Level0)
{
    HostBeginIssueTokenInput input;
    input.requestId = 1000;
    input.secureProtocolId = SecureProtocolId::DEFAULT;
    input.preIssueTokenReply = { UINT8_0XEE, UINT8_0XFF };

    HostBeginIssueTokenInputFfi ffi = {};
    EXPECT_TRUE(EncodeHostBeginIssueTokenInput(input, ffi));
    EXPECT_EQ(ffi.requestId, 1000U);
}

HWTEST_F(FfiUtilTest, DecodeHostBeginIssueTokenOutput_001, TestSize.Level0)
{
    HostBeginIssueTokenOutputFfi ffi = {};
    ffi.secMessage.len = 4;
    for (uint32_t i = 0; i < 4; ++i) {
        ffi.secMessage.data[i] = static_cast<uint8_t>(i);
    }

    HostBeginIssueTokenOutput output;
    EXPECT_TRUE(DecodeHostBeginIssueTokenOutput(ffi, output));
    EXPECT_EQ(output.issueTokenRequest.size(), 4U);
}

HWTEST_F(FfiUtilTest, EncodeHostEndIssueTokenInput_001, TestSize.Level0)
{
    HostEndIssueTokenInput input;
    input.requestId = 1111;
    input.secureProtocolId = SecureProtocolId::DEFAULT;
    input.issueTokenReply = { UINT8_0X12, UINT8_0X34 };

    HostEndIssueTokenInputFfi ffi = {};
    EXPECT_TRUE(EncodeHostEndIssueTokenInput(input, ffi));
    EXPECT_EQ(ffi.requestId, 1111U);
}

HWTEST_F(FfiUtilTest, DecodeHostEndIssueTokenOutput_001, TestSize.Level0)
{
    HostEndIssueTokenOutputFfi ffi = {};
    ffi.atl = 12345;

    Atl atl;
    EXPECT_TRUE(DecodeHostEndIssueTokenOutput(ffi, atl));
    EXPECT_EQ(atl, 12345);
}

HWTEST_F(FfiUtilTest, EncodeHostBeginTokenAuthInput_001, TestSize.Level0)
{
    HostBeginTokenAuthInput input;
    input.requestId = INT32_2222;
    input.scheduleId = INT32_3333;
    input.templateId = INT32_4444;
    input.fwkMsg = { UINT8_0X56, UINT8_0X78 };

    HostBeginTokenAuthInputFfi ffi = {};
    EXPECT_TRUE(EncodeHostBeginTokenAuthInput(input, ffi));
    EXPECT_EQ(ffi.requestId, 2222U);
    EXPECT_EQ(ffi.scheduleId, 3333U);
    EXPECT_EQ(ffi.templateId, 4444U);
}

HWTEST_F(FfiUtilTest, DecodeHostBeginTokenAuthOutput_001, TestSize.Level0)
{
    HostBeginTokenAuthOutputFfi ffi = {};
    ffi.secMessage.len = 2;
    ffi.secMessage.data[0] = UINT8_0X9A;
    ffi.secMessage.data[1] = UINT8_0XBC;

    HostBeginTokenAuthOutput output;
    EXPECT_TRUE(DecodeHostBeginTokenAuthOutput(ffi, output));
    EXPECT_EQ(output.tokenAuthRequest.size(), 2U);
}

HWTEST_F(FfiUtilTest, EncodeHostEndTokenAuthInput_001, TestSize.Level0)
{
    HostEndTokenAuthInput input;
    input.requestId = INT32_5555;
    input.templateId = INT32_6666;
    input.secureProtocolId = SecureProtocolId::DEFAULT;
    input.tokenAuthReply = { UINT8_0XDE, UINT8_0XF0 };

    HostEndTokenAuthInputFfi ffi = {};
    EXPECT_TRUE(EncodeHostEndTokenAuthInput(input, ffi));
    EXPECT_EQ(ffi.requestId, 5555U);
    EXPECT_EQ(ffi.templateId, 6666U);
}

HWTEST_F(FfiUtilTest, DecodeHostEndTokenAuthOutput_001, TestSize.Level0)
{
    HostEndTokenAuthOutputFfi ffi = {};
    ffi.fwkMessage.len = 3;
    ffi.fwkMessage.data[0] = UINT8_0X12;
    ffi.fwkMessage.data[1] = UINT8_0X34;
    ffi.fwkMessage.data[2] = UINT8_0X56;

    HostEndTokenAuthOutput output;
    EXPECT_TRUE(DecodeHostEndTokenAuthOutput(ffi, output));
    EXPECT_EQ(output.fwkMsg.size(), 3U);
}

HWTEST_F(FfiUtilTest, EncodeHostUpdateCompanionStatusInput_001, TestSize.Level0)
{
    HostUpdateCompanionStatusInput input;
    input.templateId = INT32_7777;
    input.companionDeviceName = "TestDevice";
    input.companionDeviceUserName = "TestUser";

    HostUpdateCompanionStatusInputFfi ffi = {};
    EXPECT_TRUE(EncodeHostUpdateCompanionStatusInput(input, ffi));
    EXPECT_EQ(ffi.templateId, 7777U);
}

HWTEST_F(FfiUtilTest, EncodeHostUpdateCompanionStatusInput_002, TestSize.Level0)
{
    HostUpdateCompanionStatusInput input;
    input.templateId = 1;
    input.companionDeviceName = std::string(MAX_DATA_LEN_1024 + 1, 'A');

    HostUpdateCompanionStatusInputFfi ffi = {};
    EXPECT_FALSE(EncodeHostUpdateCompanionStatusInput(input, ffi));
}

HWTEST_F(FfiUtilTest, EncodeHostUpdateCompanionEnabledBusinessIdsInput_001, TestSize.Level0)
{
    HostUpdateCompanionEnabledBusinessIdsInput input;
    input.templateId = INT32_8888;
    input.enabledBusinessIds = { static_cast<BusinessId>(1), static_cast<BusinessId>(2), static_cast<BusinessId>(3),
        static_cast<BusinessId>(4) };

    HostUpdateCompanionEnabledBusinessIdsInputFfi ffi = {};
    EXPECT_TRUE(EncodeHostUpdateCompanionEnabledBusinessIdsInput(input, ffi));
    EXPECT_EQ(ffi.templateId, 8888U);
    EXPECT_EQ(ffi.businessIds.len, 4U);
}

HWTEST_F(FfiUtilTest, EncodeHostBeginDelegateAuthInput_001, TestSize.Level0)
{
    HostBeginDelegateAuthInput input;
    input.requestId = INT32_9999;
    input.scheduleId = 10000;
    input.templateId = 11000;
    input.fwkMsg = { UINT8_0X78, UINT8_0X9A };

    HostBeginDelegateAuthInputFfi ffi = {};
    EXPECT_TRUE(EncodeHostBeginDelegateAuthInput(input, ffi));
    EXPECT_EQ(ffi.requestId, 9999U);
    EXPECT_EQ(ffi.scheduleId, 10000U);
    EXPECT_EQ(ffi.templateId, 11000U);
}

HWTEST_F(FfiUtilTest, DecodeHostBeginDelegateAuthOutput_001, TestSize.Level0)
{
    HostBeginDelegateAuthOutputFfi ffi = {};
    ffi.secMessage.len = 2;
    ffi.secMessage.data[0] = UINT8_0XBC;
    ffi.secMessage.data[1] = UINT8_0XDE;

    HostBeginDelegateAuthOutput output;
    EXPECT_TRUE(DecodeHostBeginDelegateAuthOutput(ffi, output));
    EXPECT_EQ(output.startDelegateAuthRequest.size(), 2U);
}

HWTEST_F(FfiUtilTest, EncodeHostEndDelegateAuthInput_001, TestSize.Level0)
{
    HostEndDelegateAuthInput input;
    input.requestId = 12000;
    input.secureProtocolId = SecureProtocolId::DEFAULT;
    input.delegateAuthResult = { UINT8_0XF0, UINT8_0X12 };

    HostEndDelegateAuthInputFfi ffi = {};
    EXPECT_TRUE(EncodeHostEndDelegateAuthInput(input, ffi));
    EXPECT_EQ(ffi.requestId, 12000U);
}

HWTEST_F(FfiUtilTest, DecodeHostEndDelegateAuthOutput_001, TestSize.Level0)
{
    HostEndDelegateAuthOutputFfi ffi = {};
    ffi.authType = 2;
    ffi.atl = INT32_54321;
    ffi.fwkMessage.len = 3;
    ffi.fwkMessage.data[0] = UINT8_0X34;
    ffi.fwkMessage.data[1] = UINT8_0X56;
    ffi.fwkMessage.data[2] = UINT8_0X78;

    HostEndDelegateAuthOutput output;
    EXPECT_TRUE(DecodeHostEndDelegateAuthOutput(ffi, output));
    EXPECT_EQ(output.atl, INT32_54321);
    EXPECT_EQ(output.fwkMsg.size(), 3U);
}

HWTEST_F(FfiUtilTest, EncodeHostProcessPreObtainTokenInput_001, TestSize.Level0)
{
    HostProcessPreObtainTokenInput input;
    input.requestId = 13000;
    input.templateId = 14000;
    input.secureProtocolId = SecureProtocolId::DEFAULT;

    HostProcessPreObtainTokenInputFfi ffi = {};
    EXPECT_TRUE(EncodeHostProcessPreObtainTokenInput(input, ffi));
    EXPECT_EQ(ffi.requestId, 13000U);
    EXPECT_EQ(ffi.templateId, 14000U);
}

HWTEST_F(FfiUtilTest, DecodeHostProcessPreObtainTokenOutput_001, TestSize.Level0)
{
    HostProcessPreObtainTokenOutputFfi ffi = {};
    ffi.secMessage.len = 4;
    ffi.secMessage.data[0] = UINT8_0X9A;
    ffi.secMessage.data[1] = UINT8_0XBC;
    ffi.secMessage.data[2] = UINT8_0XDE;
    ffi.secMessage.data[3] = UINT8_0XF0;

    std::vector<uint8_t> reply;
    EXPECT_TRUE(DecodeHostProcessPreObtainTokenOutput(ffi, reply));
    EXPECT_EQ(reply.size(), 4U);
}

HWTEST_F(FfiUtilTest, EncodeHostProcessObtainTokenInput_001, TestSize.Level0)
{
    HostProcessObtainTokenInput input;
    input.requestId = 15000;
    input.templateId = 16000;
    input.secureProtocolId = SecureProtocolId::DEFAULT;
    input.obtainTokenRequest = { UINT8_0X12, UINT8_0X34, UINT8_0X56 };

    HostProcessObtainTokenInputFfi ffi = {};
    EXPECT_TRUE(EncodeHostProcessObtainTokenInput(input, ffi));
    EXPECT_EQ(ffi.requestId, 15000U);
    EXPECT_EQ(ffi.templateId, 16000U);
}

HWTEST_F(FfiUtilTest, DecodeHostProcessObtainTokenOutput_001, TestSize.Level0)
{
    HostProcessObtainTokenOutputFfi ffi = {};
    ffi.atl = INT32_99999;
    ffi.secMessage.len = 2;
    ffi.secMessage.data[0] = UINT8_0X78;
    ffi.secMessage.data[1] = UINT8_0X9A;

    std::vector<uint8_t> reply;
    Atl atl;
    EXPECT_TRUE(DecodeHostProcessObtainTokenOutput(ffi, reply, atl));
    EXPECT_EQ(atl, INT32_99999);
    EXPECT_EQ(reply.size(), 2U);
}

HWTEST_F(FfiUtilTest, DecodeCompanionProcessCheckOutput_001, TestSize.Level0)
{
    CompanionProcessCheckOutputFfi ffi = {};
    ffi.secMessage.len = 3;
    ffi.secMessage.data[0] = UINT8_0XAA;
    ffi.secMessage.data[1] = UINT8_0XBB;
    ffi.secMessage.data[2] = UINT8_0XCC;

    CompanionProcessCheckOutput output;
    EXPECT_TRUE(DecodeCompanionProcessCheckOutput(ffi, output));
    EXPECT_EQ(output.companionCheckResponse.size(), 3U);
}

HWTEST_F(FfiUtilTest, EncodeCompanionInitKeyNegotiationInput_001, TestSize.Level0)
{
    CompanionInitKeyNegotiationInput input;
    input.requestId = 17000;
    input.secureProtocolId = SecureProtocolId::DEFAULT;
    input.hostDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    input.hostDeviceKey.deviceUserId = 100;
    input.hostDeviceKey.deviceId = "host";
    input.companionDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
    input.companionDeviceKey.deviceUserId = INT32_200;
    input.companionDeviceKey.deviceId = "companion";
    input.initKeyNegotiationRequest = { UINT8_0XDD, UINT8_0XEE };

    CompanionInitKeyNegotiationInputFfi ffi = {};
    EXPECT_TRUE(EncodeCompanionInitKeyNegotiationInput(input, ffi));
    EXPECT_EQ(ffi.requestId, 17000U);
}

HWTEST_F(FfiUtilTest, DecodeCompanionInitKeyNegotiationOutput_001, TestSize.Level0)
{
    CompanionInitKeyNegotiationOutputFfi ffi = {};
    ffi.secMessage.len = 2;
    ffi.secMessage.data[0] = UINT8_0XFF;
    ffi.secMessage.data[1] = UINT8_0X00;

    CompanionInitKeyNegotiationOutput output;
    EXPECT_TRUE(DecodeCompanionInitKeyNegotiationOutput(ffi, output));
    EXPECT_EQ(output.initKeyNegotiationReply.size(), 2U);
}

HWTEST_F(FfiUtilTest, EncodeCompanionBeginAddHostBindingInput_001, TestSize.Level0)
{
    CompanionBeginAddHostBindingInput input;
    input.requestId = 18000;
    input.secureProtocolId = SecureProtocolId::DEFAULT;
    input.addHostBindingRequest = { UINT8_0X11, UINT8_0X22 };

    CompanionBeginAddHostBindingInputFfi ffi = {};
    EXPECT_TRUE(EncodeCompanionBeginAddHostBindingInput(input, ffi));
    EXPECT_EQ(ffi.requestId, 18000U);
}

HWTEST_F(FfiUtilTest, DecodeCompanionBeginAddHostBindingOutput_001, TestSize.Level0)
{
    CompanionBeginAddHostBindingOutputFfi ffi = {};
    ffi.bindingId = INT32_123;
    ffi.bindingStatus.bindingId = INT32_123;
    ffi.bindingStatus.companionUserId = INT32_456;
    ffi.bindingStatus.isTokenValid = 1;
    ffi.bindingStatus.hostDeviceKey.deviceIdType = 1;
    ffi.bindingStatus.hostDeviceKey.userId = INT32_999;
    ffi.bindingStatus.hostDeviceKey.deviceId.len = 0;
    ffi.secMessage.len = 2;
    ffi.secMessage.data[0] = UINT8_0X33;
    ffi.secMessage.data[1] = UINT8_0X44;

    CompanionBeginAddHostBindingOutput output;
    EXPECT_TRUE(DecodeCompanionBeginAddHostBindingOutput(ffi, output));
    EXPECT_EQ(output.addHostBindingReply.size(), 2U);
    EXPECT_TRUE(output.replacedBindingId.has_value());
    EXPECT_EQ(output.replacedBindingId.value(), 123U);
}

HWTEST_F(FfiUtilTest, DecodeCompanionBeginAddHostBindingOutput_002, TestSize.Level0)
{
    CompanionBeginAddHostBindingOutputFfi ffi = {};
    ffi.bindingId = 0;
    ffi.bindingStatus.bindingId = INT32_555;
    ffi.bindingStatus.companionUserId = INT32_666;
    ffi.bindingStatus.isTokenValid = 0;
    ffi.bindingStatus.hostDeviceKey.deviceIdType = 1;
    ffi.bindingStatus.hostDeviceKey.userId = 777;
    ffi.bindingStatus.hostDeviceKey.deviceId.len = 0;
    ffi.secMessage.len = 0;

    CompanionBeginAddHostBindingOutput output;
    EXPECT_TRUE(DecodeCompanionBeginAddHostBindingOutput(ffi, output));
    EXPECT_FALSE(output.replacedBindingId.has_value());
}

HWTEST_F(FfiUtilTest, EncodeCompanionEndAddHostBindingInput_001, TestSize.Level0)
{
    CompanionEndAddHostBindingInput input;
    input.requestId = 19000;
    input.resultCode = ResultCode::SUCCESS;

    CompanionEndAddHostBindingInputFfi ffi = {};
    EXPECT_TRUE(EncodeCompanionEndAddHostBindingInput(input, ffi));
    EXPECT_EQ(ffi.requestId, 19000U);
}

HWTEST_F(FfiUtilTest, DecodeCompanionEndAddHostBindingOutput_001, TestSize.Level0)
{
    CompanionEndAddHostBindingOutputFfi ffi = {};
    ffi.bindingId = 888;

    CompanionEndAddHostBindingOutput output;
    EXPECT_TRUE(DecodeCompanionEndAddHostBindingOutput(ffi, output));
    EXPECT_EQ(output.bindingId, 888U);
}

HWTEST_F(FfiUtilTest, EncodeCompanionPreIssueTokenInput_001, TestSize.Level0)
{
    CompanionPreIssueTokenInput input;
    input.requestId = INT32_20000;
    input.bindingId = INT32_21000;
    input.secureProtocolId = SecureProtocolId::DEFAULT;
    input.preIssueTokenRequest = { UINT8_0X55, UINT8_0X66 };

    CompanionPreIssueTokenInputFfi ffi = {};
    EXPECT_TRUE(EncodeCompanionPreIssueTokenInput(input, ffi));
    EXPECT_EQ(ffi.requestId, 20000U);
    EXPECT_EQ(ffi.bindingId, 21000U);
}

HWTEST_F(FfiUtilTest, DecodeCompanionPreIssueTokenOutput_001, TestSize.Level0)
{
    CompanionPreIssueTokenOutputFfi ffi = {};
    ffi.secMessage.len = 3;
    ffi.secMessage.data[0] = UINT8_0X77;
    ffi.secMessage.data[1] = UINT8_0X88;
    ffi.secMessage.data[2] = UINT8_0X99;

    CompanionPreIssueTokenOutput output;
    EXPECT_TRUE(DecodeCompanionPreIssueTokenOutput(ffi, output));
    EXPECT_EQ(output.preIssueTokenReply.size(), 3U);
}

HWTEST_F(FfiUtilTest, EncodeCompanionProcessIssueTokenInput_001, TestSize.Level0)
{
    CompanionProcessIssueTokenInput input;
    input.requestId = INT32_22000;
    input.secureProtocolId = SecureProtocolId::DEFAULT;
    input.issueTokenRequest = { UINT8_0XAA, UINT8_0XBB };

    CompanionProcessIssueTokenInputFfi ffi = {};
    EXPECT_TRUE(EncodeCompanionProcessIssueTokenInput(input, ffi));
    EXPECT_EQ(ffi.requestId, 22000U);
}

HWTEST_F(FfiUtilTest, DecodeCompanionProcessIssueTokenOutput_001, TestSize.Level0)
{
    CompanionProcessIssueTokenOutputFfi ffi = {};
    ffi.secMessage.len = 2;
    ffi.secMessage.data[0] = UINT8_0XCC;
    ffi.secMessage.data[1] = UINT8_0XDD;

    CompanionProcessIssueTokenOutput output;
    EXPECT_TRUE(DecodeCompanionProcessIssueTokenOutput(ffi, output));
    EXPECT_EQ(output.issueTokenReply.size(), 2U);
}

HWTEST_F(FfiUtilTest, EncodeCompanionProcessTokenAuthInput_001, TestSize.Level0)
{
    CompanionProcessTokenAuthInput input;
    input.bindingId = INT32_23000;
    input.secureProtocolId = SecureProtocolId::DEFAULT;
    input.tokenAuthRequest = { UINT8_0XEE, UINT8_0XFF };

    CompanionProcessTokenAuthInputFfi ffi = {};
    EXPECT_TRUE(EncodeCompanionProcessTokenAuthInput(input, ffi));
    EXPECT_EQ(ffi.bindingId, 23000U);
}

HWTEST_F(FfiUtilTest, DecodeCompanionProcessTokenAuthOutput_001, TestSize.Level0)
{
    CompanionProcessTokenAuthOutputFfi ffi = {};
    ffi.secMessage.len = 4;
    for (uint32_t i = 0; i < 4; ++i) {
        ffi.secMessage.data[i] = static_cast<uint8_t>(i + 10);
    }

    CompanionProcessTokenAuthOutput output;
    EXPECT_TRUE(DecodeCompanionProcessTokenAuthOutput(ffi, output));
    EXPECT_EQ(output.tokenAuthReply.size(), 4U);
}

HWTEST_F(FfiUtilTest, EncodeCompanionBeginDelegateAuthInput_001, TestSize.Level0)
{
    CompanionDelegateAuthBeginInput input;
    input.requestId = INT32_24000;
    input.bindingId = INT32_25000;
    input.secureProtocolId = SecureProtocolId::DEFAULT;
    input.startDelegateAuthRequest = { UINT8_0X00, UINT8_0X11 };

    CompanionBeginDelegateAuthInputFfi ffi = {};
    EXPECT_TRUE(EncodeCompanionBeginDelegateAuthInput(input, ffi));
    EXPECT_EQ(ffi.requestId, 24000U);
    EXPECT_EQ(ffi.bindingId, 25000U);
}

HWTEST_F(FfiUtilTest, DecodeCompanionBeginDelegateAuthOutput_001, TestSize.Level0)
{
    CompanionBeginDelegateAuthOutputFfi ffi = {};
    ffi.challenge = 88888;
    ffi.atl = 77777;

    CompanionDelegateAuthBeginOutput output;
    EXPECT_TRUE(DecodeCompanionBeginDelegateAuthOutput(ffi, output));
    EXPECT_EQ(output.challenge, 88888U);
    EXPECT_EQ(output.atl, 77777);
}

HWTEST_F(FfiUtilTest, DecodeCompanionEndDelegateAuthOutput_001, TestSize.Level0)
{
    CompanionEndDelegateAuthOutputFfi ffi = {};
    ffi.secMessage.len = 3;
    ffi.secMessage.data[0] = UINT8_0X22;
    ffi.secMessage.data[1] = UINT8_0X33;
    ffi.secMessage.data[2] = UINT8_0X44;

    CompanionDelegateAuthEndOutput output;
    EXPECT_TRUE(DecodeCompanionEndDelegateAuthOutput(ffi, output));
    EXPECT_EQ(output.delegateAuthResult.size(), 3U);
}

HWTEST_F(FfiUtilTest, EncodeCompanionBeginObtainTokenInput_001, TestSize.Level0)
{
    CompanionBeginObtainTokenInput input;
    input.requestId = INT32_26000;
    input.bindingId = INT32_27000;
    input.secureProtocolId = SecureProtocolId::DEFAULT;
    input.fwkUnlockMsg = { UINT8_0X55, UINT8_0X66 };
    input.preObtainTokenReply = { UINT8_0X77, UINT8_0X88 };

    CompanionBeginObtainTokenInputFfi ffi = {};
    EXPECT_TRUE(EncodeCompanionBeginObtainTokenInput(input, ffi));
    EXPECT_EQ(ffi.requestId, 26000U);
    EXPECT_EQ(ffi.bindingId, 27000U);
}

HWTEST_F(FfiUtilTest, DecodeCompanionBeginObtainTokenOutput_001, TestSize.Level0)
{
    CompanionBeginObtainTokenOutputFfi ffi = {};
    ffi.secMessage.len = 5;
    for (uint32_t i = 0; i < 5; ++i) {
        ffi.secMessage.data[i] = static_cast<uint8_t>(i * 2);
    }

    std::vector<uint8_t> reply;
    EXPECT_TRUE(DecodeCompanionBeginObtainTokenOutput(ffi, reply));
    EXPECT_EQ(reply.size(), 5U);
}

HWTEST_F(FfiUtilTest, EncodeCompanionEndObtainTokenInput_001, TestSize.Level0)
{
    CompanionEndObtainTokenInput input;
    input.requestId = INT32_28000;
    input.secureProtocolId = SecureProtocolId::DEFAULT;
    input.obtainTokenReply = { UINT8_0X99, UINT8_0XAA, UINT8_0XBB };

    CompanionEndObtainTokenInputFfi ffi = {};
    EXPECT_TRUE(EncodeCompanionEndObtainTokenInput(input, ffi));
    EXPECT_EQ(ffi.requestId, 28000U);
}

HWTEST_F(FfiUtilTest, DecodePersistedCompanionStatusList_001, TestSize.Level0)
{
    CompanionStatusArrayFfi ffi = {};
    ffi.len = 2;

    ffi.data[0].templateId = 111;
    ffi.data[0].hostUserId = INT32_222;
    ffi.data[0].enabledBusinessIds.len = 0;
    ffi.data[0].companionDeviceKey.deviceId.len = 0;
    ffi.data[0].deviceModel.len = 0;
    ffi.data[0].deviceUserName.len = 0;
    ffi.data[0].deviceName.len = 0;

    ffi.data[1].templateId = INT32_333;
    ffi.data[1].hostUserId = INT32_444;
    ffi.data[1].enabledBusinessIds.len = 0;
    ffi.data[1].companionDeviceKey.deviceId.len = 0;
    ffi.data[1].deviceModel.len = 0;
    ffi.data[1].deviceUserName.len = 0;
    ffi.data[1].deviceName.len = 0;

    std::vector<PersistedCompanionStatus> list;
    EXPECT_TRUE(DecodePersistedCompanionStatusList(ffi, list));
    EXPECT_EQ(list.size(), 2U);
    EXPECT_EQ(list[0].templateId, 111U);
    EXPECT_EQ(list[1].templateId, 333U);
}

HWTEST_F(FfiUtilTest, DecodePersistedHostBindingStatusList_001, TestSize.Level0)
{
    HostBindingStatusArrayFfi ffi = {};
    ffi.len = 2;

    ffi.data[0].bindingId = INT32_555;
    ffi.data[0].companionUserId = INT32_666;
    ffi.data[0].isTokenValid = 1;
    ffi.data[0].hostDeviceKey.deviceIdType = 1;
    ffi.data[0].hostDeviceKey.userId = 777;
    ffi.data[0].hostDeviceKey.deviceId.len = 0;

    ffi.data[1].bindingId = 888;
    ffi.data[1].companionUserId = 999;
    ffi.data[1].isTokenValid = 0;
    ffi.data[1].hostDeviceKey.deviceIdType = 1;
    ffi.data[1].hostDeviceKey.userId = 1000;
    ffi.data[1].hostDeviceKey.deviceId.len = 0;

    std::vector<PersistedHostBindingStatus> list;
    EXPECT_TRUE(DecodePersistedHostBindingStatusList(ffi, list));
    EXPECT_EQ(list.size(), 2U);
    EXPECT_EQ(list[0].bindingId, 555U);
    EXPECT_EQ(list[1].bindingId, 888U);
}

// ============================================================================
// Additional Overflow Tests for Missing Coverage
// ============================================================================

HWTEST_F(FfiUtilTest, EncodeHostUpdateCompanionEnabledBusinessIdsInput_002, TestSize.Level1)
{
    // Invalid: enabledBusinessIds exceeds max (64)
    HostUpdateCompanionEnabledBusinessIdsInput input;
    input.templateId = 1;
    for (int i = 0; i < 65; ++i) {
        input.enabledBusinessIds.push_back(static_cast<BusinessId>(i));
    }

    HostUpdateCompanionEnabledBusinessIdsInputFfi ffi = {};
    EXPECT_FALSE(EncodeHostUpdateCompanionEnabledBusinessIdsInput(input, ffi));
}

HWTEST_F(FfiUtilTest, EncodeHostBeginAddCompanionInput_Overflow, TestSize.Level1)
{
    // Invalid: fwkMsg exceeds max (1024)
    {
        HostBeginAddCompanionInput input;
        input.requestId = 1;
        input.scheduleId = 1;
        input.secureProtocolId = SecureProtocolId::DEFAULT;
        input.hostDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        input.hostDeviceKey.deviceUserId = 100;
        input.hostDeviceKey.deviceId = "host";
        input.companionDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        input.companionDeviceKey.deviceUserId = INT32_200;
        input.companionDeviceKey.deviceId = "companion";
        input.fwkMsg.resize(MAX_DATA_LEN_1024 + 1, UINT8_0XBB);

        HostBeginAddCompanionInputFfi ffi = {};
        EXPECT_FALSE(EncodeHostBeginAddCompanionInput(input, ffi));
    }

    // Invalid: initKeyNegotiationReply exceeds max (1024)
    {
        HostBeginAddCompanionInput input;
        input.requestId = 1;
        input.scheduleId = 1;
        input.secureProtocolId = SecureProtocolId::DEFAULT;
        input.hostDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        input.hostDeviceKey.deviceUserId = 100;
        input.hostDeviceKey.deviceId = "host";
        input.companionDeviceKey.idType = DeviceIdType::UNIFIED_DEVICE_ID;
        input.companionDeviceKey.deviceUserId = INT32_200;
        input.companionDeviceKey.deviceId = "companion";
        input.initKeyNegotiationReply.resize(MAX_DATA_LEN_1024 + 1, UINT8_0XCC);

        HostBeginAddCompanionInputFfi ffi = {};
        EXPECT_FALSE(EncodeHostBeginAddCompanionInput(input, ffi));
    }
}

HWTEST_F(FfiUtilTest, EncodeHostEndAddCompanionInput_002, TestSize.Level1)
{
    // Invalid: enabledBusinessIds exceeds max (64)
    HostEndAddCompanionInput input;
    input.requestId = 1;
    input.secureProtocolId = SecureProtocolId::DEFAULT;
    input.companionStatus.templateId = 1;
    input.companionStatus.hostUserId = 1;
    for (int i = 0; i < 65; ++i) {
        input.companionStatus.enabledBusinessIds.push_back(static_cast<BusinessId>(i));
    }

    HostEndAddCompanionInputFfi ffi = {};
    EXPECT_FALSE(EncodeHostEndAddCompanionInput(input, ffi));
}

HWTEST_F(FfiUtilTest, EncodeHostEndCompanionCheckInput_Overflow, TestSize.Level1)
{
    // Invalid: protocolVersionList exceeds max (64)
    {
        HostEndCompanionCheckInput input;
        input.requestId = 1;
        input.templateId = 1;
        input.secureProtocolId = SecureProtocolId::DEFAULT;
        for (int i = 0; i < 65; ++i) {
            input.protocolVersionList.push_back(i);
        }

        HostEndCompanionCheckInputFfi ffi = {};
        EXPECT_FALSE(EncodeHostEndCompanionCheckInput(input, ffi));
    }

    // Invalid: capabilityList exceeds max (64)
    {
        HostEndCompanionCheckInput input;
        input.requestId = 1;
        input.templateId = 1;
        input.secureProtocolId = SecureProtocolId::DEFAULT;
        for (int i = 0; i < 65; ++i) {
            input.capabilityList.push_back(static_cast<uint16_t>(i));
        }

        HostEndCompanionCheckInputFfi ffi = {};
        EXPECT_FALSE(EncodeHostEndCompanionCheckInput(input, ffi));
    }

    // Invalid: companionCheckResponse exceeds max (1024)
    {
        HostEndCompanionCheckInput input;
        input.requestId = 1;
        input.templateId = 1;
        input.secureProtocolId = SecureProtocolId::DEFAULT;
        input.companionCheckResponse.resize(MAX_DATA_LEN_1024 + 1, UINT8_0XAA);

        HostEndCompanionCheckInputFfi ffi = {};
        EXPECT_FALSE(EncodeHostEndCompanionCheckInput(input, ffi));
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
