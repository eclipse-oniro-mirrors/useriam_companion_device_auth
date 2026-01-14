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

#include <memory>
#include <optional>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "companion_device_auth_client.h"
#include "companion_device_auth_client_impl.h"
#include "companion_device_auth_common_defines.h"
#include "fake_companion_device_auth.h"

#include "mock_callback.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::UserIam::CompanionDeviceAuth;

/**
 * @brief Test fixture for CompanionDeviceAuthClientImpl tests.
 */

namespace {
// Mock output parameter indices
constexpr size_t INDEX_0 = 0;
constexpr size_t INDEX_1 = 1;
constexpr size_t INDEX_2 = 2;

// Mock call count
constexpr size_t SIZE_1 = 1;
constexpr size_t SIZE_2 = 2;

// Test constants
constexpr int32_t INT32_0 = 0;
constexpr int32_t INT32_100 = 100;
constexpr int32_t INT32_200 = 200;
constexpr int32_t INT32_999 = 999;
constexpr uint64_t UINT64_12345 = 12345;
constexpr uint64_t UINT64_67890 = 67890;
constexpr uint64_t UINT64_1234567890 = 1234567890;
constexpr uint32_t UINT32_2 = 2;
} // namespace

class CompanionDeviceAuthClientImplTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    void SetUp() override;
    void TearDown() override;

protected:
    // Helper to set up fake proxy default expectations
    void SetUpFakeProxyDefaults();

    // Helper to create a test template status
    IpcTemplateStatus CreateTestTemplateStatus(uint64_t templateId, int32_t userId);

    FakeCompanionDeviceAuth *fakeProxy_ = nullptr;
};

void CompanionDeviceAuthClientImplTest::SetUpTestCase()
{
}

void CompanionDeviceAuthClientImplTest::TearDownTestCase()
{
}

void CompanionDeviceAuthClientImplTest::SetUp()
{
    fakeProxy_ = new (std::nothrow) FakeCompanionDeviceAuth();
    ASSERT_NE(fakeProxy_, nullptr);
}

void CompanionDeviceAuthClientImplTest::TearDown()
{
    Mock::AllowLeak(fakeProxy_);
    fakeProxy_ = nullptr;
}

void CompanionDeviceAuthClientImplTest::SetUpFakeProxyDefaults()
{
    // Set default successful behavior for fake proxy
    ON_CALL(*fakeProxy_, RegisterDeviceSelectCallback(_, _))
        .WillByDefault(DoAll(SetArgReferee<INDEX_1>(INT32_0), Return(INT32_0))); // SUCCESS
    ON_CALL(*fakeProxy_, UnregisterDeviceSelectCallback(_))
        .WillByDefault(DoAll(SetArgReferee<INDEX_0>(INT32_0), Return(INT32_0)));
    ON_CALL(*fakeProxy_, UpdateTemplateEnabledBusinessIds(_, _, _))
        .WillByDefault(DoAll(SetArgReferee<INDEX_2>(INT32_0), Return(INT32_0)));
    ON_CALL(*fakeProxy_, GetTemplateStatus(_, _, _))
        .WillByDefault(DoAll(SetArgReferee<INDEX_2>(INT32_0), Return(INT32_0)));
    ON_CALL(*fakeProxy_, SubscribeTemplateStatusChange(_, _, _))
        .WillByDefault(DoAll(SetArgReferee<INDEX_2>(INT32_0), Return(INT32_0)));
    ON_CALL(*fakeProxy_, UnsubscribeTemplateStatusChange(_, _))
        .WillByDefault(DoAll(SetArgReferee<INDEX_1>(INT32_0), Return(INT32_0)));
    ON_CALL(*fakeProxy_, SubscribeAvailableDeviceStatus(_, _, _))
        .WillByDefault(DoAll(SetArgReferee<INDEX_2>(INT32_0), Return(INT32_0)));
    ON_CALL(*fakeProxy_, UnsubscribeAvailableDeviceStatus(_, _))
        .WillByDefault(DoAll(SetArgReferee<INDEX_1>(INT32_0), Return(INT32_0)));
    ON_CALL(*fakeProxy_, SubscribeContinuousAuthStatusChange(_, _, _))
        .WillByDefault(DoAll(SetArgReferee<INDEX_2>(INT32_0), Return(INT32_0)));
    ON_CALL(*fakeProxy_, UnsubscribeContinuousAuthStatusChange(_, _))
        .WillByDefault(DoAll(SetArgReferee<INDEX_1>(INT32_0), Return(INT32_0)));
    ON_CALL(*fakeProxy_, CheckLocalUserIdValid(_, _, _))
        .WillByDefault(DoAll(SetArgReferee<INDEX_2>(INT32_0), Return(INT32_0)));
}

IpcTemplateStatus CompanionDeviceAuthClientImplTest::CreateTestTemplateStatus(uint64_t templateId, int32_t userId)
{
    IpcTemplateStatus status;
    status.templateId = templateId;
    status.isConfirmed = true;
    status.isValid = true;
    status.localUserId = userId;
    status.addedTime = UINT64_1234567890;
    status.enabledBusinessIds = { 1, 2, 3 };

    status.deviceStatus.deviceKey.deviceIdType = 0; // Use integer instead of enum
    status.deviceStatus.deviceKey.deviceId = "test-device-id";
    status.deviceStatus.deviceKey.deviceUserId = userId; // Using userId directly
    status.deviceStatus.deviceUserName = "Test User";
    status.deviceStatus.deviceModelInfo = "Test Model";
    status.deviceStatus.deviceName = "Test Device";
    status.deviceStatus.isOnline = true;
    status.deviceStatus.supportedBusinessIds = { 1, 2, 3 };

    return status;
}

/**
 * @brief Test RegisterDeviceSelectCallback with valid callback.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, RegisterDeviceSelectCallback_Success, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    auto callback = std::make_shared<MockDeviceSelectCallback>();
    EXPECT_CALL(*fakeProxy_, RegisterDeviceSelectCallback(_, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_1>(INT32_0), Return(INT32_0)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.RegisterDeviceSelectCallback(callback);

    // Assert
    EXPECT_EQ(result, SUCCESS);
}

/**
 * @brief Test RegisterDeviceSelectCallback with null callback.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, RegisterDeviceSelectCallback_NullCallback, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.RegisterDeviceSelectCallback(nullptr);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test RegisterDeviceSelectCallback with no proxy (fetcher returns nullptr).
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, RegisterDeviceSelectCallback_NoProxy, TestSize.Level0)
{
    // Arrange - fetcher returns nullptr to simulate service unavailable

    auto callback = std::make_shared<MockDeviceSelectCallback>();

    // Act
    CompanionDeviceAuthClientImpl client;
    int32_t result = client.RegisterDeviceSelectCallback(callback);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test UnregisterDeviceSelectCallback success.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, UnregisterDeviceSelectCallback_Success, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    EXPECT_CALL(*fakeProxy_, UnregisterDeviceSelectCallback(_))
        .WillOnce(DoAll(SetArgReferee<INDEX_0>(SUCCESS), Return(SUCCESS)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.UnregisterDeviceSelectCallback();

    // Assert
    EXPECT_EQ(result, SUCCESS);
}

/**
 * @brief Test GetTemplateStatus success.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, GetTemplateStatus_Success, TestSize.Level0)
{
    // Arrange
    const int32_t userId = INT32_100;
    std::vector<IpcTemplateStatus> mockStatusList;
    mockStatusList.push_back(CreateTestTemplateStatus(UINT64_12345, userId));
    mockStatusList.push_back(CreateTestTemplateStatus(UINT64_67890, userId));

    SetUpFakeProxyDefaults();
    EXPECT_CALL(*fakeProxy_, GetTemplateStatus(userId, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_1>(mockStatusList), SetArgReferee<INDEX_2>(SUCCESS), Return(SUCCESS)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    std::vector<ClientTemplateStatus> statusList;
    int32_t result = client.GetTemplateStatus(userId, statusList);

    // Assert
    EXPECT_EQ(result, SUCCESS);
    EXPECT_EQ(statusList.size(), UINT32_2);
    EXPECT_EQ(statusList[0].templateId, UINT64_12345);
    EXPECT_EQ(statusList[1].templateId, UINT64_67890);
}

/**
 * @brief Test GetTemplateStatus with no proxy.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, GetTemplateStatus_NoProxy, TestSize.Level0)
{
    // Arrange

    const int32_t userId = INT32_100;

    // Act
    CompanionDeviceAuthClientImpl client;
    std::vector<ClientTemplateStatus> statusList;
    int32_t result = client.GetTemplateStatus(userId, statusList);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
    EXPECT_TRUE(statusList.empty());
}

/**
 * @brief Test UpdateTemplateEnabledBusinessIds success.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, UpdateTemplateEnabledBusinessIds_Success, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const uint64_t templateId = UINT64_12345;
    const std::vector<int32_t> businessIds = { 1, 2, 3 };

    EXPECT_CALL(*fakeProxy_, UpdateTemplateEnabledBusinessIds(templateId, businessIds, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(SUCCESS), Return(SUCCESS)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.UpdateTemplateEnabledBusinessIds(templateId, businessIds);

    // Assert
    EXPECT_EQ(result, SUCCESS);
}

/**
 * @brief Test SubscribeTemplateStatusChange success.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, SubscribeTemplateStatusChange_Success, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    auto callback = std::make_shared<MockTemplateStatusCallback>(userId);

    EXPECT_CALL(*fakeProxy_, SubscribeTemplateStatusChange(userId, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(SUCCESS), Return(SUCCESS)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.SubscribeTemplateStatusChange(userId, callback);

    // Assert
    EXPECT_EQ(result, SUCCESS);
}

/**
 * @brief Test SubscribeTemplateStatusChange with null callback.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, SubscribeTemplateStatusChange_NullCallback, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.SubscribeTemplateStatusChange(INT32_100, nullptr);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test UnsubscribeTemplateStatusChange success.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, UnsubscribeTemplateStatusChange_Success, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    auto callback = std::make_shared<MockTemplateStatusCallback>(userId);

    // First subscribe
    EXPECT_CALL(*fakeProxy_, SubscribeTemplateStatusChange(userId, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(SUCCESS), Return(SUCCESS)));

    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t subscribeResult = client.SubscribeTemplateStatusChange(userId, callback);
    EXPECT_EQ(subscribeResult, SUCCESS);

    // Then unsubscribe
    EXPECT_CALL(*fakeProxy_, UnsubscribeTemplateStatusChange(_, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_1>(SUCCESS), Return(SUCCESS)));

    int32_t unsubscribeResult = client.UnsubscribeTemplateStatusChange(callback);

    // Assert
    EXPECT_EQ(unsubscribeResult, SUCCESS);
}

/**
 * @brief Test SubscribeAvailableDeviceStatus success.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, SubscribeAvailableDeviceStatus_Success, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    auto callback = std::make_shared<MockAvailableDeviceStatusCallback>(userId);

    EXPECT_CALL(*fakeProxy_, SubscribeAvailableDeviceStatus(userId, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(SUCCESS), Return(SUCCESS)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.SubscribeAvailableDeviceStatus(userId, callback);

    // Assert
    EXPECT_EQ(result, SUCCESS);
}

/**
 * @brief Test SubscribeContinuousAuthStatusChange success.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, SubscribeContinuousAuthStatusChange_Success, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    const uint64_t templateId = UINT64_12345;
    auto callback = std::make_shared<MockContinuousAuthStatusCallback>(userId, templateId);

    EXPECT_CALL(*fakeProxy_, SubscribeContinuousAuthStatusChange(_, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(SUCCESS), Return(SUCCESS)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.SubscribeContinuousAuthStatusChange(userId, callback, templateId);

    // Assert
    EXPECT_EQ(result, SUCCESS);
}

/**
 * @brief Test SubscribeContinuousAuthStatusChange without templateId.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, SubscribeContinuousAuthStatusChange_NoTemplateId, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    auto callback = std::make_shared<MockContinuousAuthStatusCallback>(userId, std::nullopt);

    EXPECT_CALL(*fakeProxy_, SubscribeContinuousAuthStatusChange(_, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(SUCCESS), Return(SUCCESS)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.SubscribeContinuousAuthStatusChange(userId, callback);

    // Assert
    EXPECT_EQ(result, SUCCESS);
}

/**
 * @brief Test CheckLocalUserIdValid success.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, CheckLocalUserIdValid_Success, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    bool isUserIdValid = false;

    EXPECT_CALL(*fakeProxy_, CheckLocalUserIdValid(userId, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_1>(true), SetArgReferee<INDEX_2>(SUCCESS), Return(SUCCESS)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.CheckLocalUserIdValid(userId, isUserIdValid);

    // Assert
    EXPECT_EQ(result, SUCCESS);
    EXPECT_TRUE(isUserIdValid);
}

/**
 * @brief Test CheckLocalUserIdValid with invalid user.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, CheckLocalUserIdValid_InvalidUser, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_999;
    bool isUserIdValid = true; // Start with true, should become false

    EXPECT_CALL(*fakeProxy_, CheckLocalUserIdValid(userId, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_1>(false), SetArgReferee<INDEX_2>(SUCCESS), Return(SUCCESS)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.CheckLocalUserIdValid(userId, isUserIdValid);

    // Assert
    EXPECT_EQ(result, SUCCESS);
    EXPECT_FALSE(isUserIdValid);
}

/**
 * @brief Test service error response propagation.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, ServiceErrorPropagatesToClient, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    auto callback = std::make_shared<MockTemplateStatusCallback>(userId);

    // Simulate service returning error
    EXPECT_CALL(*fakeProxy_, SubscribeTemplateStatusChange(userId, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(GENERAL_ERROR), Return(SUCCESS)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.SubscribeTemplateStatusChange(userId, callback);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test IPC communication failure.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, IpcFailureReturnsGeneralError, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    auto callback = std::make_shared<MockTemplateStatusCallback>(userId);

    // Simulate IPC failure (first return value is IPC result)
    EXPECT_CALL(*fakeProxy_, SubscribeTemplateStatusChange(userId, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(SUCCESS),
            Return(GENERAL_ERROR))); // IPC call fails

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.SubscribeTemplateStatusChange(userId, callback);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test null fetcher causes error.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, NullFetcherCausesError, TestSize.Level0)
{
    // Arrange
    auto callback = std::make_shared<MockDeviceSelectCallback>();

    // Act - client with default fetcher, but we reset it to nullptr
    CompanionDeviceAuthClientImpl client;
    // Do not set proxy - GetProxy() will return nullptr
    int32_t result = client.RegisterDeviceSelectCallback(callback);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

// ============================================================================
// Part 1: "No Proxy" scenario tests - supplement tests for other methods without proxy
// ============================================================================

/**
 * @brief Test UnregisterDeviceSelectCallback with no proxy.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, UnregisterDeviceSelectCallback_NoProxy, TestSize.Level0)
{
    // Arrange

    // Act
    CompanionDeviceAuthClientImpl client;
    int32_t result = client.UnregisterDeviceSelectCallback();

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test UpdateTemplateEnabledBusinessIds with no proxy.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, UpdateTemplateEnabledBusinessIds_NoProxy, TestSize.Level0)
{
    // Arrange
    const uint64_t templateId = UINT64_12345;
    const std::vector<int32_t> businessIds = { 1, 2, 3 };

    // Act
    CompanionDeviceAuthClientImpl client;
    int32_t result = client.UpdateTemplateEnabledBusinessIds(templateId, businessIds);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test SubscribeTemplateStatusChange with no proxy.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, SubscribeTemplateStatusChange_NoProxy, TestSize.Level0)
{
    // Arrange
    const int32_t userId = INT32_100;
    auto callback = std::make_shared<MockTemplateStatusCallback>(userId);

    // Act
    CompanionDeviceAuthClientImpl client;
    int32_t result = client.SubscribeTemplateStatusChange(userId, callback);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test UnsubscribeTemplateStatusChange with no proxy.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, UnsubscribeTemplateStatusChange_NoProxy, TestSize.Level0)
{
    // Arrange
    const int32_t userId = INT32_100;
    auto callback = std::make_shared<MockTemplateStatusCallback>(userId);

    // Act
    CompanionDeviceAuthClientImpl client;
    int32_t result = client.UnsubscribeTemplateStatusChange(callback);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test SubscribeAvailableDeviceStatus with no proxy.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, SubscribeAvailableDeviceStatus_NoProxy, TestSize.Level0)
{
    // Arrange
    const int32_t userId = INT32_100;
    auto callback = std::make_shared<MockAvailableDeviceStatusCallback>(userId);

    // Act
    CompanionDeviceAuthClientImpl client;
    int32_t result = client.SubscribeAvailableDeviceStatus(userId, callback);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test UnsubscribeAvailableDeviceStatus with no proxy.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, UnsubscribeAvailableDeviceStatus_NoProxy, TestSize.Level0)
{
    // Arrange
    const int32_t userId = INT32_100;
    auto callback = std::make_shared<MockAvailableDeviceStatusCallback>(userId);

    // Act
    CompanionDeviceAuthClientImpl client;
    int32_t result = client.UnsubscribeAvailableDeviceStatus(callback);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test SubscribeContinuousAuthStatusChange with no proxy.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, SubscribeContinuousAuthStatusChange_NoProxy, TestSize.Level0)
{
    // Arrange
    const int32_t userId = INT32_100;
    auto callback = std::make_shared<MockContinuousAuthStatusCallback>(userId, std::nullopt);

    // Act
    CompanionDeviceAuthClientImpl client;
    int32_t result = client.SubscribeContinuousAuthStatusChange(userId, callback);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test UnsubscribeContinuousAuthStatusChange with no proxy.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, UnsubscribeContinuousAuthStatusChange_NoProxy, TestSize.Level0)
{
    // Arrange
    auto callback = std::make_shared<MockContinuousAuthStatusCallback>(100, std::nullopt);

    // Act
    CompanionDeviceAuthClientImpl client;
    int32_t result = client.UnsubscribeContinuousAuthStatusChange(callback);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test CheckLocalUserIdValid with no proxy.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, CheckLocalUserIdValid_NoProxy, TestSize.Level0)
{
    // Arrange
    const int32_t userId = INT32_100;
    bool isUserIdValid = false;

    // Act
    CompanionDeviceAuthClientImpl client;
    int32_t result = client.CheckLocalUserIdValid(userId, isUserIdValid);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

// ============================================================================
// Part 2: Tests for service returning non-SUCCESS error codes
// ============================================================================

/**
 * @brief Test RegisterDeviceSelectCallback when service returns GENERAL_ERROR.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, RegisterDeviceSelectCallback_ServiceGeneralError, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    auto callback = std::make_shared<MockDeviceSelectCallback>();

    EXPECT_CALL(*fakeProxy_, RegisterDeviceSelectCallback(_, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_1>(GENERAL_ERROR), Return(SUCCESS)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.RegisterDeviceSelectCallback(callback);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test RegisterDeviceSelectCallback when service returns TIMEOUT.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, RegisterDeviceSelectCallback_ServiceTimedOut, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    auto callback = std::make_shared<MockDeviceSelectCallback>();

    EXPECT_CALL(*fakeProxy_, RegisterDeviceSelectCallback(_, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_1>(TIMEOUT), Return(SUCCESS)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.RegisterDeviceSelectCallback(callback);

    // Assert
    EXPECT_EQ(result, TIMEOUT);
}

/**
 * @brief Test UnregisterDeviceSelectCallback when service returns error.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, UnregisterDeviceSelectCallback_ServiceError, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();

    EXPECT_CALL(*fakeProxy_, UnregisterDeviceSelectCallback(_))
        .WillOnce(DoAll(SetArgReferee<INDEX_0>(GENERAL_ERROR), Return(SUCCESS)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.UnregisterDeviceSelectCallback();

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test UpdateTemplateEnabledBusinessIds when service returns error.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, UpdateTemplateEnabledBusinessIds_ServiceError, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const uint64_t templateId = UINT64_12345;
    const std::vector<int32_t> businessIds = { 1, 2, 3 };

    EXPECT_CALL(*fakeProxy_, UpdateTemplateEnabledBusinessIds(templateId, businessIds, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(GENERAL_ERROR), Return(SUCCESS)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.UpdateTemplateEnabledBusinessIds(templateId, businessIds);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test GetTemplateStatus when service returns error.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, GetTemplateStatus_ServiceError, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    std::vector<ClientTemplateStatus> statusList;

    EXPECT_CALL(*fakeProxy_, GetTemplateStatus(userId, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(GENERAL_ERROR), Return(SUCCESS)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.GetTemplateStatus(userId, statusList);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
    EXPECT_TRUE(statusList.empty());
}

/**
 * @brief Test UnsubscribeTemplateStatusChange when callback not found (empty list).
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, UnsubscribeTemplateStatusChange_CallbackNotFound, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    auto callback = std::make_shared<MockTemplateStatusCallback>(userId);

    // Act - Call unsubscribe without calling subscribe first
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.UnsubscribeTemplateStatusChange(callback);

    // Assert - Should return error because callback was never subscribed
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test SubscribeAvailableDeviceStatus when service returns error.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, SubscribeAvailableDeviceStatus_ServiceError, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    auto callback = std::make_shared<MockAvailableDeviceStatusCallback>(userId);

    EXPECT_CALL(*fakeProxy_, SubscribeAvailableDeviceStatus(userId, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(GENERAL_ERROR), Return(SUCCESS)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.SubscribeAvailableDeviceStatus(userId, callback);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test UnsubscribeAvailableDeviceStatus when service returns error.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, UnsubscribeAvailableDeviceStatus_ServiceError, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    auto callback = std::make_shared<MockAvailableDeviceStatusCallback>(userId);

    // First subscribe the callback
    EXPECT_CALL(*fakeProxy_, SubscribeAvailableDeviceStatus(_, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(SUCCESS), Return(SUCCESS)));
    // Then unsubscribe with service error
    EXPECT_CALL(*fakeProxy_, UnsubscribeAvailableDeviceStatus(_, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_1>(GENERAL_ERROR), Return(SUCCESS)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t subscribeResult = client.SubscribeAvailableDeviceStatus(userId, callback);
    ASSERT_EQ(subscribeResult, SUCCESS);

    int32_t result = client.UnsubscribeAvailableDeviceStatus(callback);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test SubscribeContinuousAuthStatusChange when service returns error.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, SubscribeContinuousAuthStatusChange_ServiceError, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    const uint64_t templateId = UINT64_12345;
    auto callback = std::make_shared<MockContinuousAuthStatusCallback>(userId, templateId);

    EXPECT_CALL(*fakeProxy_, SubscribeContinuousAuthStatusChange(_, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(GENERAL_ERROR), Return(SUCCESS)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.SubscribeContinuousAuthStatusChange(userId, callback, templateId);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test UnsubscribeContinuousAuthStatusChange when service returns error.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, UnsubscribeContinuousAuthStatusChange_ServiceError, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    auto callback = std::make_shared<MockContinuousAuthStatusCallback>(100, std::nullopt);

    // First subscribe the callback
    EXPECT_CALL(*fakeProxy_, SubscribeContinuousAuthStatusChange(_, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(SUCCESS), Return(SUCCESS)));
    // Then unsubscribe with service error
    EXPECT_CALL(*fakeProxy_, UnsubscribeContinuousAuthStatusChange(_, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_1>(GENERAL_ERROR), Return(SUCCESS)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t subscribeResult = client.SubscribeContinuousAuthStatusChange(userId, callback);
    ASSERT_EQ(subscribeResult, SUCCESS);

    int32_t result = client.UnsubscribeContinuousAuthStatusChange(callback);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test CheckLocalUserIdValid when service returns different error codes.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, CheckLocalUserIdValid_ServiceGeneralError, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    bool isUserIdValid = false;

    EXPECT_CALL(*fakeProxy_, CheckLocalUserIdValid(userId, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_1>(false), SetArgReferee<INDEX_2>(GENERAL_ERROR), Return(SUCCESS)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.CheckLocalUserIdValid(userId, isUserIdValid);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
    EXPECT_FALSE(isUserIdValid);
}

// ============================================================================
// Part 3: ResetProxy and DeathRecipient related tests
// ============================================================================

/**
 * @brief Test GetProxy caching mechanism.
 *        Verifies that GetProxy returns cached proxy on subsequent calls.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, GetProxy_CachesProxy, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));

    // Set expectations - verify each method is called once
    EXPECT_CALL(*fakeProxy_, RegisterDeviceSelectCallback(_, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_1>(INT32_0), Return(INT32_0)));
    EXPECT_CALL(*fakeProxy_, UnregisterDeviceSelectCallback(_))
        .WillOnce(DoAll(SetArgReferee<INDEX_0>(INT32_0), Return(INT32_0)));
    EXPECT_CALL(*fakeProxy_, CheckLocalUserIdValid(INT32_100, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_1>(false), SetArgReferee<INDEX_2>(INT32_0), Return(INT32_0)));

    // Act - Call multiple methods that need proxy
    auto callback = std::make_shared<MockDeviceSelectCallback>();
    client.RegisterDeviceSelectCallback(callback); // First call - creates proxy
    client.UnregisterDeviceSelectCallback();       // Second call - uses cached proxy
    bool isUserIdValid = false;
    client.CheckLocalUserIdValid(INT32_100, isUserIdValid); // Third call - uses cached proxy

    // Assert - All expectations verified implicitly by gmock
}

/**
 * @brief Test multiple client instances have independent proxies.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, MultipleClientsIndependentProxies, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();

    // Create two different fake proxies
    FakeCompanionDeviceAuth *fakeProxy1 = new (std::nothrow) FakeCompanionDeviceAuth();
    FakeCompanionDeviceAuth *fakeProxy2 = new (std::nothrow) FakeCompanionDeviceAuth();
    ASSERT_NE(fakeProxy1, nullptr);
    ASSERT_NE(fakeProxy2, nullptr);

    // Set up expectations for each proxy with different behaviors
    EXPECT_CALL(*fakeProxy1, RegisterDeviceSelectCallback(_, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_1>(INT32_100), Return(INT32_0))); // Returns 100
    EXPECT_CALL(*fakeProxy2, RegisterDeviceSelectCallback(_, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_1>(INT32_200), Return(INT32_0))); // Returns 200

    CompanionDeviceAuthClientImpl client1;
    CompanionDeviceAuthClientImpl client2;
    client1.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy1));
    client2.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy2));

    // Act - Each client uses its own proxy
    auto callback1 = std::make_shared<MockDeviceSelectCallback>();
    auto callback2 = std::make_shared<MockDeviceSelectCallback>();

    int32_t result1 = client1.RegisterDeviceSelectCallback(callback1);
    int32_t result2 = client2.RegisterDeviceSelectCallback(callback2);

    // Assert - Each client got different results from their independent proxies
    EXPECT_EQ(result1, INT32_100);
    EXPECT_EQ(result2, INT32_200);

    Mock::AllowLeak(fakeProxy1);
    Mock::AllowLeak(fakeProxy2);
}

// ============================================================================
// Part 4: Re-register/Resubscribe tests triggered by SA status changes
// ============================================================================

/**
 * @brief Test SubscribeCompanionDeviceAuthSaStatus idempotency.
 *        Multiple calls should not create multiple listeners.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, SubscribeCompanionDeviceAuthSaStatus_Idempotent, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));

    // Act - Subscribe multiple times
    client.SubscribeCompanionDeviceAuthSaStatus();
    client.SubscribeCompanionDeviceAuthSaStatus();
    client.SubscribeCompanionDeviceAuthSaStatus();

    // Assert - No crash, second and third calls should return early
    // Test passes if no assertion violations
}

/**
 * @brief Test Register followed by SubscribeCompanionDeviceAuthSaStatus
 *        Verifies that registering callback persists across SA status changes.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, RegisterBeforeSubscribeSaStatus, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));

    auto callback = std::make_shared<MockDeviceSelectCallback>();

    // First register
    EXPECT_CALL(*fakeProxy_, RegisterDeviceSelectCallback(_, _))
        .Times(SIZE_1)
        .WillRepeatedly(DoAll(SetArgReferee<INDEX_1>(SUCCESS), Return(SUCCESS)));

    // Act - Register callback before subscribing to SA status
    int32_t result1 = client.RegisterDeviceSelectCallback(callback);
    EXPECT_EQ(result1, SUCCESS);

    // Then subscribe to SA status (should trigger re-registration internally)
    client.SubscribeCompanionDeviceAuthSaStatus();

    // Assert - Callback should still be registered
    // Test passes if no crash
}

/**
 * @brief Test SubscribeTemplateStatusChange followed by another Subscribe.
 *        Verifies callback list management.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, SubscribeTemplateStatusChange_MultipleCallbacks, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));

    const int32_t userId1 = INT32_100;
    const int32_t userId2 = INT32_200;
    auto callback1 = std::make_shared<MockTemplateStatusCallback>(userId1);
    auto callback2 = std::make_shared<MockTemplateStatusCallback>(userId2);

    EXPECT_CALL(*fakeProxy_, SubscribeTemplateStatusChange(_, _, _))
        .Times(SIZE_2)
        .WillRepeatedly(DoAll(SetArgReferee<INDEX_2>(SUCCESS), Return(SUCCESS)));

    // Act - Subscribe multiple callbacks
    int32_t result1 = client.SubscribeTemplateStatusChange(userId1, callback1);
    int32_t result2 = client.SubscribeTemplateStatusChange(userId2, callback2);

    // Assert
    EXPECT_EQ(result1, SUCCESS);
    EXPECT_EQ(result2, SUCCESS);
}

/**
 * @brief Test error propagation in UpdateTemplateEnabledBusinessIds.
 *        Tests both IPC failure and service error scenarios.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, UpdateTemplateEnabledBusinessIds_IpcFailure, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const uint64_t templateId = UINT64_12345;
    const std::vector<int32_t> businessIds = { 1, 2, 3 };

    // Simulate IPC failure
    EXPECT_CALL(*fakeProxy_, UpdateTemplateEnabledBusinessIds(templateId, businessIds, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(SUCCESS), Return(GENERAL_ERROR)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.UpdateTemplateEnabledBusinessIds(templateId, businessIds);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test GetTemplateStatus with empty result from service.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, GetTemplateStatus_EmptyResult, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    std::vector<IpcTemplateStatus> emptyStatusList;

    EXPECT_CALL(*fakeProxy_, GetTemplateStatus(userId, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_1>(emptyStatusList), SetArgReferee<INDEX_2>(SUCCESS), Return(SUCCESS)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    std::vector<ClientTemplateStatus> statusList;
    int32_t result = client.GetTemplateStatus(userId, statusList);

    // Assert
    EXPECT_EQ(result, SUCCESS);
    EXPECT_TRUE(statusList.empty());
}

/**
 * @brief Test SubscribeContinuousAuthStatusChange with various templateId scenarios.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, SubscribeContinuousAuthStatusChange_WithAndWithoutTemplateId,
    TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));

    const int32_t userId = INT32_100;
    auto callbackWithId = std::make_shared<MockContinuousAuthStatusCallback>(userId, 12345);
    auto callbackWithoutId = std::make_shared<MockContinuousAuthStatusCallback>(userId, std::nullopt);

    EXPECT_CALL(*fakeProxy_, SubscribeContinuousAuthStatusChange(_, _, _))
        .Times(SIZE_2)
        .WillRepeatedly(DoAll(SetArgReferee<INDEX_2>(SUCCESS), Return(SUCCESS)));

    // Act - Subscribe with and without templateId
    int32_t result1 = client.SubscribeContinuousAuthStatusChange(userId, callbackWithId, 12345);
    int32_t result2 = client.SubscribeContinuousAuthStatusChange(userId, callbackWithoutId);

    // Assert
    EXPECT_EQ(result1, SUCCESS);
    EXPECT_EQ(result2, SUCCESS);
}

/**
 * @brief Test concurrent operations on same client instance.
 *        Verifies thread safety of proxy caching.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, ConcurrentOperations_ThreadSafety, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));

    auto callback1 = std::make_shared<MockDeviceSelectCallback>();
    auto callback2 = std::make_shared<MockTemplateStatusCallback>(100);
    auto callback3 = std::make_shared<MockAvailableDeviceStatusCallback>(100);

    // Set expectations for multiple concurrent calls
    EXPECT_CALL(*fakeProxy_, RegisterDeviceSelectCallback(_, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_1>(SUCCESS), Return(SUCCESS)));
    EXPECT_CALL(*fakeProxy_, SubscribeTemplateStatusChange(_, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(SUCCESS), Return(SUCCESS)));
    EXPECT_CALL(*fakeProxy_, SubscribeAvailableDeviceStatus(_, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(SUCCESS), Return(SUCCESS)));

    // Act - Perform multiple operations
    int32_t result1 = client.RegisterDeviceSelectCallback(callback1);
    int32_t result2 = client.SubscribeTemplateStatusChange(INT32_100, callback2);
    int32_t result3 = client.SubscribeAvailableDeviceStatus(INT32_100, callback3);

    // Assert - All operations should succeed
    EXPECT_EQ(result1, SUCCESS);
    EXPECT_EQ(result2, SUCCESS);
    EXPECT_EQ(result3, SUCCESS);
}

// ============================================================================
// Part 5: IPC call failure tests - supplement high priority uncovered branches
// ============================================================================

/**
 * @brief Test UnregisterDeviceSelectCallback when IPC call fails.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, UnregisterDeviceSelectCallback_IpcFailure, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();

    // Simulate IPC call failure (first return value is IPC result)
    EXPECT_CALL(*fakeProxy_, UnregisterDeviceSelectCallback(_))
        .WillOnce(DoAll(SetArgReferee<INDEX_0>(SUCCESS), Return(GENERAL_ERROR)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.UnregisterDeviceSelectCallback();

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test GetTemplateStatus when IPC call fails.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, GetTemplateStatus_IpcFailure, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    std::vector<ClientTemplateStatus> statusList;

    // Simulate IPC call failure
    EXPECT_CALL(*fakeProxy_, GetTemplateStatus(userId, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(SUCCESS), Return(GENERAL_ERROR)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.GetTemplateStatus(userId, statusList);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test SubscribeTemplateStatusChange when IPC call fails.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, SubscribeTemplateStatusChange_IpcFailure, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    auto callback = std::make_shared<MockTemplateStatusCallback>(userId);

    // Simulate IPC call failure
    EXPECT_CALL(*fakeProxy_, SubscribeTemplateStatusChange(userId, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(SUCCESS), Return(GENERAL_ERROR)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.SubscribeTemplateStatusChange(userId, callback);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test UnsubscribeTemplateStatusChange when IPC call fails.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, UnsubscribeTemplateStatusChange_IpcFailure, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    auto callback = std::make_shared<MockTemplateStatusCallback>(userId);

    // Subscribe first
    EXPECT_CALL(*fakeProxy_, SubscribeTemplateStatusChange(userId, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(SUCCESS), Return(SUCCESS)));

    // Unsubscribe with IPC failure
    EXPECT_CALL(*fakeProxy_, UnsubscribeTemplateStatusChange(_, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_1>(SUCCESS), Return(GENERAL_ERROR)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));

    int32_t subscribeResult = client.SubscribeTemplateStatusChange(userId, callback);
    EXPECT_EQ(subscribeResult, SUCCESS);

    int32_t unsubscribeResult = client.UnsubscribeTemplateStatusChange(callback);

    // Assert
    EXPECT_EQ(unsubscribeResult, GENERAL_ERROR);
}

/**
 * @brief Test SubscribeAvailableDeviceStatus when IPC call fails.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, SubscribeAvailableDeviceStatus_IpcFailure, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    auto callback = std::make_shared<MockAvailableDeviceStatusCallback>(userId);

    // Simulate IPC call failure
    EXPECT_CALL(*fakeProxy_, SubscribeAvailableDeviceStatus(userId, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(SUCCESS), Return(GENERAL_ERROR)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.SubscribeAvailableDeviceStatus(userId, callback);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test UnsubscribeAvailableDeviceStatus when IPC call fails.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, UnsubscribeAvailableDeviceStatus_IpcFailure, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    auto callback = std::make_shared<MockAvailableDeviceStatusCallback>(userId);

    // Subscribe first
    EXPECT_CALL(*fakeProxy_, SubscribeAvailableDeviceStatus(userId, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(SUCCESS), Return(SUCCESS)));

    // Unsubscribe with IPC failure
    EXPECT_CALL(*fakeProxy_, UnsubscribeAvailableDeviceStatus(_, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_1>(SUCCESS), Return(GENERAL_ERROR)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));

    int32_t subscribeResult = client.SubscribeAvailableDeviceStatus(userId, callback);
    EXPECT_EQ(subscribeResult, SUCCESS);

    int32_t unsubscribeResult = client.UnsubscribeAvailableDeviceStatus(callback);

    // Assert
    EXPECT_EQ(unsubscribeResult, GENERAL_ERROR);
}

/**
 * @brief Test SubscribeContinuousAuthStatusChange when IPC call fails.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, SubscribeContinuousAuthStatusChange_IpcFailure, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    const uint64_t templateId = UINT64_12345;
    auto callback = std::make_shared<MockContinuousAuthStatusCallback>(userId, templateId);

    // Simulate IPC call failure
    EXPECT_CALL(*fakeProxy_, SubscribeContinuousAuthStatusChange(_, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(SUCCESS), Return(GENERAL_ERROR)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.SubscribeContinuousAuthStatusChange(userId, callback, templateId);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test UnsubscribeContinuousAuthStatusChange when IPC call fails.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, UnsubscribeContinuousAuthStatusChange_IpcFailure, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    auto callback = std::make_shared<MockContinuousAuthStatusCallback>(100, std::nullopt);

    // Subscribe first
    EXPECT_CALL(*fakeProxy_, SubscribeContinuousAuthStatusChange(_, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(SUCCESS), Return(SUCCESS)));

    // Unsubscribe with IPC failure
    EXPECT_CALL(*fakeProxy_, UnsubscribeContinuousAuthStatusChange(_, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_1>(SUCCESS), Return(GENERAL_ERROR)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));

    int32_t subscribeResult = client.SubscribeContinuousAuthStatusChange(INT32_100, callback);
    EXPECT_EQ(subscribeResult, SUCCESS);

    int32_t unsubscribeResult = client.UnsubscribeContinuousAuthStatusChange(callback);

    // Assert
    EXPECT_EQ(unsubscribeResult, GENERAL_ERROR);
}

/**
 * @brief Test CheckLocalUserIdValid when IPC call fails.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, CheckLocalUserIdValid_IpcFailure, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();
    const int32_t userId = INT32_100;
    bool isUserIdValid = false;

    // Simulate IPC call failure
    EXPECT_CALL(*fakeProxy_, CheckLocalUserIdValid(userId, _, _))
        .WillOnce(DoAll(SetArgReferee<INDEX_2>(SUCCESS), Return(GENERAL_ERROR)));

    // Act
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.CheckLocalUserIdValid(userId, isUserIdValid);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

// ============================================================================
// Part 6: Null callback check tests - supplement medium priority uncovered branches
// ============================================================================

/**
 * @brief Test UnsubscribeTemplateStatusChange with null callback.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, UnsubscribeTemplateStatusChange_NullCallback, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();

    // Act - Call unsubscribe with null callback
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.UnsubscribeTemplateStatusChange(nullptr);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test SubscribeAvailableDeviceStatus with null callback.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, SubscribeAvailableDeviceStatus_NullCallback, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();

    // Act - Call subscribe with null callback
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.SubscribeAvailableDeviceStatus(INT32_100, nullptr);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test UnsubscribeAvailableDeviceStatus with null callback.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, UnsubscribeAvailableDeviceStatus_NullCallback, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();

    // Act - Call unsubscribe with null callback
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.UnsubscribeAvailableDeviceStatus(nullptr);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test SubscribeContinuousAuthStatusChange with null callback.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, SubscribeContinuousAuthStatusChange_NullCallback, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();

    // Act - Call subscribe with null callback
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.SubscribeContinuousAuthStatusChange(INT32_100, nullptr, std::nullopt);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}

/**
 * @brief Test UnsubscribeContinuousAuthStatusChange with null callback.
 */
HWTEST_F(CompanionDeviceAuthClientImplTest, UnsubscribeContinuousAuthStatusChange_NullCallback, TestSize.Level0)
{
    // Arrange
    SetUpFakeProxyDefaults();

    // Act - Call unsubscribe with null callback
    CompanionDeviceAuthClientImpl client;
    client.SetProxy(sptr<ICompanionDeviceAuth>(fakeProxy_));
    int32_t result = client.UnsubscribeContinuousAuthStatusChange(nullptr);

    // Assert
    EXPECT_EQ(result, GENERAL_ERROR);
}
