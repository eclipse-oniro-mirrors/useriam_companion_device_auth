/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "request_manager_impl.h"
#include "task_runner_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

// ============== Mock Request Configuration ==============

struct MockRequestConfig {
    RequestId id = 1;
    RequestType type = RequestType::HOST_TOKEN_AUTH_REQUEST;
    ScheduleId scheduleId = 0;
    std::optional<DeviceKey> peerDeviceKey = std::nullopt;
    uint32_t maxConcurrency = 1;
    bool shouldCancel = false;
    std::optional<RequestType> conflictingType;
    const char *description = "MockRequest";

    MockRequestConfig &WithId(RequestId newId)
    {
        id = newId;
        return *this;
    }

    MockRequestConfig &WithType(RequestType newType)
    {
        type = newType;
        return *this;
    }

    MockRequestConfig &WithScheduleId(ScheduleId newScheduleId)
    {
        scheduleId = newScheduleId;
        return *this;
    }

    MockRequestConfig &WithPeerDeviceKey(const std::optional<DeviceKey> &key)
    {
        peerDeviceKey = key;
        return *this;
    }

    MockRequestConfig &WithMaxConcurrency(uint32_t max)
    {
        maxConcurrency = max;
        return *this;
    }

    MockRequestConfig &WithShouldCancel(bool newShouldCancel)
    {
        shouldCancel = newShouldCancel;
        return *this;
    }

    MockRequestConfig &WithConflictingType(RequestType type)
    {
        conflictingType = type;
        return *this;
    }

    MockRequestConfig &WithDescription(const char *desc)
    {
        description = desc;
        return *this;
    }
};

// ============== Mock Request Definition ==============

class MockRequest : public IRequest {
public:
    MOCK_METHOD(void, Start, (), (override));
    MOCK_METHOD(bool, Cancel, (ResultCode resultCode), (override));
    MOCK_METHOD(RequestType, GetRequestType, (), (const, override));
    MOCK_METHOD(const char *, GetDescription, (), (const, override));
    MOCK_METHOD(RequestId, GetRequestId, (), (const, override));
    MOCK_METHOD(ScheduleId, GetScheduleId, (), (const, override));
    MOCK_METHOD(std::optional<DeviceKey>, GetPeerDeviceKey, (), (const, override));
    MOCK_METHOD(std::optional<TemplateId>, GetTemplateId, (), (const, override));
    MOCK_METHOD(uint32_t, GetMaxConcurrency, (), (const, override));
    MOCK_METHOD(bool, ShouldCancelOnNewRequest, (const IRequest &, uint32_t), (const, override));

    bool CanStart(const std::vector<std::shared_ptr<IRequest>> &prevRequests) const override
    {
        uint32_t sameTypeCount = 0;
        for (const auto &req : prevRequests) {
            if (req != nullptr && req->GetRequestType() == GetRequestType()) {
                sameTypeCount++;
            }
        }
        if (sameTypeCount >= GetMaxConcurrency()) {
            return false;
        }
        for (const auto &req : prevRequests) {
            if (req != nullptr && conflictingType_.has_value() && req->GetRequestType() == conflictingType_.value()) {
                return false;
            }
        }
        return true;
    }

    void SetConflictingType(std::optional<RequestType> type)
    {
        conflictingType_ = type;
    }

private:
    std::optional<RequestType> conflictingType_;
};

// ============== Mock Request Factory ==============

std::shared_ptr<NiceMock<MockRequest>> CreateMockRequest(const MockRequestConfig &config)
{
    auto request = std::make_shared<NiceMock<MockRequest>>();
    ON_CALL(*request, GetRequestId).WillByDefault(Return(config.id));
    ON_CALL(*request, GetRequestType).WillByDefault(Return(config.type));
    ON_CALL(*request, GetScheduleId).WillByDefault(Return(config.scheduleId));
    ON_CALL(*request, GetDescription).WillByDefault(Return(config.description));
    ON_CALL(*request, GetPeerDeviceKey).WillByDefault(Return(config.peerDeviceKey));
    ON_CALL(*request, GetMaxConcurrency).WillByDefault(Return(config.maxConcurrency));
    ON_CALL(*request, ShouldCancelOnNewRequest).WillByDefault(Return(config.shouldCancel));
    ON_CALL(*request, Start).WillByDefault(Return());
    ON_CALL(*request, Cancel(_)).WillByDefault(Return(true));
    request->SetConflictingType(config.conflictingType);
    return request;
}

class RequestManagerImplTest : public Test {
public:
    void SetUp() override
    {
        manager_ = RequestManagerImpl::Create();
        ASSERT_NE(manager_, nullptr);
    }

    void TearDown() override
    {
        // Automatically execute all pending PostTask items submitted during the test.
        // This ensures that all async logic (Cancel, Start, etc.) posted via PostTaskOnResident
        // is executed and verified, even if not explicitly called in the test body.
        // Tests can also call ExecuteAll() mid-test to verify logic at specific points.
        TaskRunnerManager::GetInstance().ExecuteAll();
        manager_.reset();
    }

protected:
    std::shared_ptr<RequestManagerImpl> manager_;
};

// ============== Basic Start Tests ==============

HWTEST_F(RequestManagerImplTest, Start_NullRequest_ReturnsFalse, TestSize.Level0)
{
    bool result = manager_->Start(nullptr);
    EXPECT_FALSE(result);
}

HWTEST_F(RequestManagerImplTest, Start_ValidRequest_ReturnsTrue, TestSize.Level0)
{
    auto request = CreateMockRequest(MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST));

    bool result = manager_->Start(request);

    EXPECT_TRUE(result);
}

HWTEST_F(RequestManagerImplTest, Start_ValidRequest_CallsStartOnRequest, TestSize.Level0)
{
    auto request = CreateMockRequest(MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST));

    EXPECT_CALL(*request, Start()).Times(1);

    manager_->Start(request);
    ASSERT_NO_THROW(TaskRunnerManager::GetInstance().ExecuteAll());
}

HWTEST_F(RequestManagerImplTest, Start_DuplicateRequestId_ReturnsFalse, TestSize.Level0)
{
    auto request1 = CreateMockRequest(MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST));
    auto request2 = CreateMockRequest(MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_DELEGATE_AUTH_REQUEST));

    EXPECT_TRUE(manager_->Start(request1));
    EXPECT_FALSE(manager_->Start(request2));
}

// ============== Preemption Tests (ShouldCancelOnNewRequest) ==============

HWTEST_F(RequestManagerImplTest, Start_PreemptsRunningRequest_WhenShouldCancelReturnsTrue, TestSize.Level0)
{
    auto existingRequest = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithShouldCancel(true));

    auto newRequest = CreateMockRequest(MockRequestConfig {}.WithId(2).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST));

    EXPECT_CALL(*existingRequest, Cancel(_)).Times(1).WillOnce(Return(true));

    manager_->Start(existingRequest);
    manager_->Start(newRequest);
    ASSERT_NO_THROW(TaskRunnerManager::GetInstance().ExecuteAll());
}

HWTEST_F(RequestManagerImplTest, Start_DoesNotPreemptRunningRequest_WhenShouldCancelReturnsFalse, TestSize.Level0)
{
    auto existingRequest = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithShouldCancel(false));

    auto newRequest =
        CreateMockRequest(MockRequestConfig {}.WithId(2).WithType(RequestType::HOST_DELEGATE_AUTH_REQUEST));

    EXPECT_CALL(*existingRequest, Cancel(_)).Times(0);

    manager_->Start(existingRequest);
    manager_->Start(newRequest);
    ASSERT_NO_THROW(TaskRunnerManager::GetInstance().ExecuteAll());
}

HWTEST_F(RequestManagerImplTest, Start_PreemptsWaitingRequest_WhenShouldCancelReturnsTrue, TestSize.Level0)
{
    auto runningRequest = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    auto waitingRequest = CreateMockRequest(MockRequestConfig {}
                                                .WithId(2)
                                                .WithType(RequestType::HOST_TOKEN_AUTH_REQUEST)
                                                .WithMaxConcurrency(1)
                                                .WithShouldCancel(true));

    auto newRequest =
        CreateMockRequest(MockRequestConfig {}.WithId(3).WithType(RequestType::HOST_DELEGATE_AUTH_REQUEST));

    EXPECT_TRUE(manager_->Start(runningRequest));
    EXPECT_TRUE(manager_->Start(waitingRequest));

    EXPECT_CALL(*waitingRequest, Cancel(_)).Times(1).WillOnce(Return(true));

    manager_->Start(newRequest);
    TaskRunnerManager::GetInstance().ExecuteAll();
}

HWTEST_F(RequestManagerImplTest, Start_PreemptsMultipleRequests_WhenShouldCancelReturnsTrue, TestSize.Level0)
{
    auto existingRequest1 = CreateMockRequest(MockRequestConfig {}
                                                  .WithId(1)
                                                  .WithType(RequestType::HOST_TOKEN_AUTH_REQUEST)
                                                  .WithShouldCancel(true)
                                                  .WithMaxConcurrency(10));

    auto existingRequest2 = CreateMockRequest(MockRequestConfig {}
                                                  .WithId(2)
                                                  .WithType(RequestType::HOST_TOKEN_AUTH_REQUEST)
                                                  .WithShouldCancel(true)
                                                  .WithMaxConcurrency(10));

    auto newRequest =
        CreateMockRequest(MockRequestConfig {}.WithId(3).WithType(RequestType::HOST_DELEGATE_AUTH_REQUEST));

    EXPECT_CALL(*existingRequest1, Cancel(_)).Times(2).WillRepeatedly(Return(true));
    EXPECT_CALL(*existingRequest2, Cancel(_)).Times(1).WillOnce(Return(true));

    manager_->Start(existingRequest1);
    manager_->Start(existingRequest2);
    manager_->Start(newRequest);
    ASSERT_NO_THROW(TaskRunnerManager::GetInstance().ExecuteAll());
}

// ============== Concurrency Control Tests (MaxConcurrency) ==============

HWTEST_F(RequestManagerImplTest, Start_AddsToRunningQueue_WhenBelowMaxConcurrency, TestSize.Level0)
{
    auto request1 = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(2));

    auto request2 = CreateMockRequest(
        MockRequestConfig {}.WithId(2).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(2));

    EXPECT_CALL(*request1, Start()).Times(1);
    EXPECT_CALL(*request2, Start()).Times(1);

    manager_->Start(request1);
    manager_->Start(request2);
    ASSERT_NO_THROW(TaskRunnerManager::GetInstance().ExecuteAll());
}

HWTEST_F(RequestManagerImplTest, Start_AddsToWaitingQueue_WhenAtMaxConcurrency, TestSize.Level0)
{
    auto request1 = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    auto request2 = CreateMockRequest(
        MockRequestConfig {}.WithId(2).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    EXPECT_CALL(*request1, Start()).Times(1);
    EXPECT_CALL(*request2, Start()).Times(0);

    EXPECT_TRUE(manager_->Start(request1));
    EXPECT_TRUE(manager_->Start(request2));
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_NE(manager_->Get(1), nullptr);
    EXPECT_NE(manager_->Get(2), nullptr);
}

HWTEST_F(RequestManagerImplTest, Start_CountsBothRunningAndWaiting_ForConcurrencyCheck, TestSize.Level0)
{
    auto request1 = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(2));

    auto request2 = CreateMockRequest(
        MockRequestConfig {}.WithId(2).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(2));

    auto request3 = CreateMockRequest(
        MockRequestConfig {}.WithId(3).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(2));

    EXPECT_CALL(*request1, Start()).Times(1);
    EXPECT_CALL(*request2, Start()).Times(1);
    EXPECT_CALL(*request3, Start()).Times(0);

    manager_->Start(request1);
    manager_->Start(request2);
    manager_->Start(request3);
    ASSERT_NO_THROW(TaskRunnerManager::GetInstance().ExecuteAll());
}

HWTEST_F(RequestManagerImplTest, Start_DifferentRequestTypes_HaveSeparateConcurrencyLimits, TestSize.Level0)
{
    auto tokenRequest1 = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    auto delegateRequest = CreateMockRequest(
        MockRequestConfig {}.WithId(2).WithType(RequestType::HOST_DELEGATE_AUTH_REQUEST).WithMaxConcurrency(1));

    EXPECT_CALL(*tokenRequest1, Start()).Times(1);
    EXPECT_CALL(*delegateRequest, Start()).Times(1);

    manager_->Start(tokenRequest1);
    manager_->Start(delegateRequest);
    ASSERT_NO_THROW(TaskRunnerManager::GetInstance().ExecuteAll());
}

// ============== Remove Tests (Waiting Queue Scheduling) ==============

HWTEST_F(RequestManagerImplTest, Remove_RemovesFromRunningQueue, TestSize.Level0)
{
    auto request = CreateMockRequest(MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST));

    manager_->Start(request);
    EXPECT_NE(manager_->Get(1), nullptr);

    manager_->Remove(1);
    EXPECT_EQ(manager_->Get(1), nullptr);
}

HWTEST_F(RequestManagerImplTest, Remove_RemovesFromWaitingQueue, TestSize.Level0)
{
    auto request1 = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    auto request2 = CreateMockRequest(
        MockRequestConfig {}.WithId(2).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    manager_->Start(request1);
    manager_->Start(request2);

    EXPECT_NE(manager_->Get(2), nullptr);

    manager_->Remove(2);
    EXPECT_EQ(manager_->Get(2), nullptr);
}

HWTEST_F(RequestManagerImplTest, Remove_StartsWaitingRequest_WhenRunningRequestRemoved, TestSize.Level0)
{
    auto request1 = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    auto request2 = CreateMockRequest(
        MockRequestConfig {}.WithId(2).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    manager_->Start(request1);
    manager_->Start(request2);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_CALL(*request2, Start()).Times(1);

    manager_->Remove(1);
    ASSERT_NO_THROW(TaskRunnerManager::GetInstance().ExecuteAll());
}

HWTEST_F(RequestManagerImplTest, Remove_DoesNotStartWaitingRequest_WhenWaitingRequestRemoved, TestSize.Level0)
{
    auto request1 = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    auto request2 = CreateMockRequest(
        MockRequestConfig {}.WithId(2).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    auto request3 = CreateMockRequest(
        MockRequestConfig {}.WithId(3).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    manager_->Start(request1);
    manager_->Start(request2);
    manager_->Start(request3);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_CALL(*request3, Start()).Times(0);

    manager_->Remove(2);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_NE(manager_->Get(1), nullptr);
    EXPECT_EQ(manager_->Get(2), nullptr);
    EXPECT_NE(manager_->Get(3), nullptr);
}

HWTEST_F(RequestManagerImplTest, Remove_StartsOnlyMatchingTypeFromWaitingQueue, TestSize.Level0)
{
    auto tokenRequest1 = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    auto tokenRequest2 = CreateMockRequest(
        MockRequestConfig {}.WithId(2).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    auto delegateRequest = CreateMockRequest(
        MockRequestConfig {}.WithId(3).WithType(RequestType::HOST_DELEGATE_AUTH_REQUEST).WithMaxConcurrency(1));

    manager_->Start(tokenRequest1);
    manager_->Start(delegateRequest);
    manager_->Start(tokenRequest2);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_CALL(*tokenRequest2, Start()).Times(1);
    EXPECT_CALL(*delegateRequest, Start()).Times(0);

    manager_->Remove(1);
    ASSERT_NO_THROW(TaskRunnerManager::GetInstance().ExecuteAll());
}

HWTEST_F(RequestManagerImplTest, Remove_StartsMultipleWaitingRequests_WhenMultipleSlotsAvailable, TestSize.Level0)
{
    auto request1 = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(2));

    auto request2 = CreateMockRequest(
        MockRequestConfig {}.WithId(2).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(2));

    auto request3 = CreateMockRequest(
        MockRequestConfig {}.WithId(3).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(2));

    manager_->Start(request1);
    manager_->Start(request2);
    manager_->Start(request3);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_CALL(*request3, Start()).Times(1);

    manager_->Remove(1);
    ASSERT_NO_THROW(TaskRunnerManager::GetInstance().ExecuteAll());
}

HWTEST_F(RequestManagerImplTest, Remove_NonExistentRequest_DoesNothing, TestSize.Level0)
{
    auto request = CreateMockRequest(MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST));

    manager_->Start(request);

    manager_->Remove(999);

    EXPECT_NE(manager_->Get(1), nullptr);
}

HWTEST_F(RequestManagerImplTest, Remove_CountsOnlyRunningRequestsOfSameType, TestSize.Level0)
{
    auto tokenRequest1 = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(2));

    auto delegateRequest1 = CreateMockRequest(
        MockRequestConfig {}.WithId(2).WithType(RequestType::HOST_DELEGATE_AUTH_REQUEST).WithMaxConcurrency(1));

    auto tokenRequest2 = CreateMockRequest(
        MockRequestConfig {}.WithId(3).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(2));

    auto delegateRequest2 = CreateMockRequest(
        MockRequestConfig {}.WithId(4).WithType(RequestType::HOST_DELEGATE_AUTH_REQUEST).WithMaxConcurrency(1));

    manager_->Start(tokenRequest1);
    manager_->Start(delegateRequest1);
    manager_->Start(tokenRequest2);
    manager_->Start(delegateRequest2);
    TaskRunnerManager::GetInstance().ExecuteAll();

    manager_->Remove(1);
    ASSERT_NO_THROW(TaskRunnerManager::GetInstance().ExecuteAll());
}

// ============== Cancel Tests ==============

HWTEST_F(RequestManagerImplTest, Cancel_ExistingRequest_CallsCancelOnRequest, TestSize.Level0)
{
    auto request = CreateMockRequest(MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST));

    EXPECT_CALL(*request, Cancel(_)).Times(1).WillOnce(Return(true));

    manager_->Start(request);
    bool result = manager_->Cancel(1);

    EXPECT_TRUE(result);
}

HWTEST_F(RequestManagerImplTest, Cancel_NonExistentRequest_ReturnsFalse, TestSize.Level0)
{
    bool result = manager_->Cancel(999);
    EXPECT_FALSE(result);
}

HWTEST_F(RequestManagerImplTest, Cancel_WaitingRequest_CallsCancelOnRequest, TestSize.Level0)
{
    auto request1 = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    auto request2 = CreateMockRequest(
        MockRequestConfig {}.WithId(2).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    EXPECT_CALL(*request2, Cancel(_)).Times(1).WillOnce(Return(true));

    manager_->Start(request1);
    manager_->Start(request2);

    bool result = manager_->Cancel(2);
    EXPECT_TRUE(result);
}

// ============== CancelRequestByScheduleId Tests ==============

HWTEST_F(RequestManagerImplTest, CancelByScheduleId_ValidScheduleId_CancelsRequest, TestSize.Level0)
{
    auto request = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithScheduleId(12345));

    EXPECT_CALL(*request, Cancel(_)).Times(1).WillOnce(Return(true));

    manager_->Start(request);
    bool result = manager_->CancelRequestByScheduleId(12345);

    EXPECT_TRUE(result);
}

HWTEST_F(RequestManagerImplTest, CancelByScheduleId_ZeroScheduleId_ReturnsFalse, TestSize.Level0)
{
    bool result = manager_->CancelRequestByScheduleId(0);
    EXPECT_FALSE(result);
}

HWTEST_F(RequestManagerImplTest, CancelByScheduleId_NonExistentScheduleId_ReturnsFalse, TestSize.Level0)
{
    auto request = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithScheduleId(12345));

    manager_->Start(request);
    bool result = manager_->CancelRequestByScheduleId(99999);

    EXPECT_FALSE(result);
}

HWTEST_F(RequestManagerImplTest, CancelByScheduleId_WaitingRequest_CancelsRequest, TestSize.Level0)
{
    auto request1 = CreateMockRequest(MockRequestConfig {}
                                          .WithId(1)
                                          .WithType(RequestType::HOST_TOKEN_AUTH_REQUEST)
                                          .WithScheduleId(111)
                                          .WithMaxConcurrency(1));

    auto request2 = CreateMockRequest(MockRequestConfig {}
                                          .WithId(2)
                                          .WithType(RequestType::HOST_TOKEN_AUTH_REQUEST)
                                          .WithScheduleId(222)
                                          .WithMaxConcurrency(1));

    EXPECT_CALL(*request2, Cancel(_)).Times(1).WillOnce(Return(true));

    manager_->Start(request1);
    manager_->Start(request2);

    bool result = manager_->CancelRequestByScheduleId(222);
    EXPECT_TRUE(result);
}

HWTEST_F(RequestManagerImplTest, CancelByScheduleId_WaitingRequest_NonExistentScheduleId, TestSize.Level0)
{
    auto request1 = CreateMockRequest(MockRequestConfig {}
                                          .WithId(1)
                                          .WithType(RequestType::HOST_TOKEN_AUTH_REQUEST)
                                          .WithScheduleId(111)
                                          .WithMaxConcurrency(1));

    auto request2 = CreateMockRequest(MockRequestConfig {}
                                          .WithId(2)
                                          .WithType(RequestType::HOST_TOKEN_AUTH_REQUEST)
                                          .WithScheduleId(222)
                                          .WithMaxConcurrency(1));

    manager_->Start(request1);
    manager_->Start(request2);

    bool result = manager_->CancelRequestByScheduleId(333);
    EXPECT_FALSE(result);
}

// ============== CancelAll Tests ==============

HWTEST_F(RequestManagerImplTest, CancelAll_CancelsAllRunningRequests, TestSize.Level0)
{
    auto request1 = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(10));

    auto request2 = CreateMockRequest(
        MockRequestConfig {}.WithId(2).WithType(RequestType::HOST_DELEGATE_AUTH_REQUEST).WithMaxConcurrency(10));

    EXPECT_CALL(*request1, Cancel(_)).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*request2, Cancel(_)).Times(1).WillOnce(Return(true));

    manager_->Start(request1);
    manager_->Start(request2);

    ASSERT_NO_THROW(manager_->CancelAll());
}

HWTEST_F(RequestManagerImplTest, CancelAll_CancelsAllWaitingRequests, TestSize.Level0)
{
    auto request1 = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    auto request2 = CreateMockRequest(
        MockRequestConfig {}.WithId(2).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    EXPECT_CALL(*request1, Cancel(_)).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*request2, Cancel(_)).Times(1).WillOnce(Return(true));

    manager_->Start(request1);
    manager_->Start(request2);

    ASSERT_NO_THROW(manager_->CancelAll());
}

HWTEST_F(RequestManagerImplTest, CancelAll_EmptyManager_DoesNothing, TestSize.Level0)
{
    ASSERT_NO_THROW(manager_->CancelAll());
}

HWTEST_F(RequestManagerImplTest, CancelAll_WithFailedCancel, TestSize.Level0)
{
    auto request1 = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));
    auto request2 = CreateMockRequest(
        MockRequestConfig {}.WithId(2).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    manager_->Start(request1);
    manager_->Start(request2);

    EXPECT_CALL(*request1, Cancel(_)).Times(1).WillOnce(Return(false));
    EXPECT_CALL(*request2, Cancel(_)).Times(1).WillOnce(Return(false));

    ASSERT_NO_THROW(manager_->CancelAll());
}

// ============== Get Tests ==============

HWTEST_F(RequestManagerImplTest, Get_ExistingRunningRequest_ReturnsRequest, TestSize.Level0)
{
    auto request = CreateMockRequest(MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST));

    manager_->Start(request);

    auto result = manager_->Get(1);
    EXPECT_EQ(result, request);
}

HWTEST_F(RequestManagerImplTest, Get_ExistingWaitingRequest_ReturnsRequest, TestSize.Level0)
{
    auto request1 = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    auto request2 = CreateMockRequest(
        MockRequestConfig {}.WithId(2).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    manager_->Start(request1);
    manager_->Start(request2);

    auto result = manager_->Get(2);
    EXPECT_EQ(result, request2);
}

HWTEST_F(RequestManagerImplTest, Get_NonExistentRequest_ReturnsNullptr, TestSize.Level0)
{
    auto result = manager_->Get(999);
    EXPECT_EQ(result, nullptr);
}

// ============== Create Tests ==============

HWTEST_F(RequestManagerImplTest, Create_ReturnsValidManager, TestSize.Level0)
{
    auto manager = RequestManagerImpl::Create();
    EXPECT_NE(manager, nullptr);
}

// ============== Complex Scenario Tests ==============

HWTEST_F(RequestManagerImplTest, ComplexScenario_PreemptionAndConcurrency, TestSize.Level0)
{
    auto existingToken1 = CreateMockRequest(MockRequestConfig {}
                                                .WithId(1)
                                                .WithType(RequestType::HOST_TOKEN_AUTH_REQUEST)
                                                .WithMaxConcurrency(2)
                                                .WithShouldCancel(false));

    auto existingToken2 = CreateMockRequest(MockRequestConfig {}
                                                .WithId(2)
                                                .WithType(RequestType::HOST_TOKEN_AUTH_REQUEST)
                                                .WithMaxConcurrency(2)
                                                .WithShouldCancel(true));

    auto existingDelegate = CreateMockRequest(MockRequestConfig {}
                                                  .WithId(3)
                                                  .WithType(RequestType::HOST_DELEGATE_AUTH_REQUEST)
                                                  .WithMaxConcurrency(1)
                                                  .WithShouldCancel(true));

    auto newToken = CreateMockRequest(
        MockRequestConfig {}.WithId(4).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(2));

    manager_->Start(existingToken1);
    manager_->Start(existingToken2);
    manager_->Start(existingDelegate);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_CALL(*existingToken2, Cancel(_)).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*existingDelegate, Cancel(_)).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*existingToken1, Cancel(_)).Times(0);

    manager_->Start(newToken);
    ASSERT_NO_THROW(TaskRunnerManager::GetInstance().ExecuteAll());
}

HWTEST_F(RequestManagerImplTest, ComplexScenario_WaitingQueueSchedulingOrder, TestSize.Level0)
{
    auto running = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    auto waiting1 = CreateMockRequest(
        MockRequestConfig {}.WithId(2).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    auto waiting2 = CreateMockRequest(
        MockRequestConfig {}.WithId(3).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    manager_->Start(running);
    manager_->Start(waiting1);
    manager_->Start(waiting2);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_CALL(*waiting1, Start()).Times(1);

    manager_->Remove(1);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_CALL(*waiting2, Start()).Times(1);

    manager_->Remove(2);
    ASSERT_NO_THROW(TaskRunnerManager::GetInstance().ExecuteAll());
}

HWTEST_F(RequestManagerImplTest, ComplexScenario_PreemptedRequestNotStartedFromWaiting, TestSize.Level0)
{
    auto running = CreateMockRequest(MockRequestConfig {}
                                         .WithId(1)
                                         .WithType(RequestType::HOST_TOKEN_AUTH_REQUEST)
                                         .WithMaxConcurrency(1)
                                         .WithShouldCancel(true));

    auto waiting = CreateMockRequest(
        MockRequestConfig {}.WithId(2).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(1));

    manager_->Start(running);
    manager_->Start(waiting);
    TaskRunnerManager::GetInstance().ExecuteAll();

    auto newRequest = CreateMockRequest(
        MockRequestConfig {}.WithId(3).WithType(RequestType::HOST_DELEGATE_AUTH_REQUEST).WithMaxConcurrency(1));

    EXPECT_CALL(*running, Cancel(_)).Times(1).WillOnce(Return(true));
    EXPECT_CALL(*waiting, Start()).Times(0);

    manager_->Start(newRequest);
    ASSERT_NO_THROW(TaskRunnerManager::GetInstance().ExecuteAll());
}

// ============== Cross-Type Mutual Exclusion Tests ==============

HWTEST_F(RequestManagerImplTest, MutualExclusion_IssueTokenWaits_WhenTokenAuthRunning, TestSize.Level0)
{
    auto tokenAuth = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(10));

    auto issueToken = CreateMockRequest(MockRequestConfig {}
                                            .WithId(2)
                                            .WithType(RequestType::HOST_ISSUE_TOKEN_REQUEST)
                                            .WithMaxConcurrency(10)
                                            .WithConflictingType(RequestType::HOST_TOKEN_AUTH_REQUEST));

    EXPECT_CALL(*tokenAuth, Start()).Times(1);
    EXPECT_CALL(*issueToken, Start()).Times(0);

    manager_->Start(tokenAuth);
    manager_->Start(issueToken);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_NE(manager_->Get(1), nullptr);
    EXPECT_NE(manager_->Get(2), nullptr);
}

HWTEST_F(RequestManagerImplTest, MutualExclusion_TokenAuthWaits_WhenIssueTokenRunning, TestSize.Level0)
{
    auto issueToken = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_ISSUE_TOKEN_REQUEST).WithMaxConcurrency(10));

    auto tokenAuth = CreateMockRequest(MockRequestConfig {}
                                           .WithId(2)
                                           .WithType(RequestType::HOST_TOKEN_AUTH_REQUEST)
                                           .WithMaxConcurrency(10)
                                           .WithConflictingType(RequestType::HOST_ISSUE_TOKEN_REQUEST));

    EXPECT_CALL(*issueToken, Start()).Times(1);
    EXPECT_CALL(*tokenAuth, Start()).Times(0);

    manager_->Start(issueToken);
    manager_->Start(tokenAuth);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_NE(manager_->Get(1), nullptr);
    EXPECT_NE(manager_->Get(2), nullptr);
}

HWTEST_F(RequestManagerImplTest, MutualExclusion_IssueTokenPromoted_WhenTokenAuthFinishes, TestSize.Level0)
{
    auto tokenAuth = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(10));

    auto issueToken = CreateMockRequest(MockRequestConfig {}
                                            .WithId(2)
                                            .WithType(RequestType::HOST_ISSUE_TOKEN_REQUEST)
                                            .WithMaxConcurrency(10)
                                            .WithConflictingType(RequestType::HOST_TOKEN_AUTH_REQUEST));

    EXPECT_CALL(*tokenAuth, Start()).Times(1);

    manager_->Start(tokenAuth);
    manager_->Start(issueToken);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_CALL(*issueToken, Start()).Times(1);

    manager_->Remove(1);
    ASSERT_NO_THROW(TaskRunnerManager::GetInstance().ExecuteAll());
}

HWTEST_F(RequestManagerImplTest, MutualExclusion_TokenAuthPromoted_WhenIssueTokenFinishes, TestSize.Level0)
{
    auto issueToken = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_ISSUE_TOKEN_REQUEST).WithMaxConcurrency(10));

    auto tokenAuth = CreateMockRequest(MockRequestConfig {}
                                           .WithId(2)
                                           .WithType(RequestType::HOST_TOKEN_AUTH_REQUEST)
                                           .WithMaxConcurrency(10)
                                           .WithConflictingType(RequestType::HOST_ISSUE_TOKEN_REQUEST));

    EXPECT_CALL(*issueToken, Start()).Times(1);

    manager_->Start(issueToken);
    manager_->Start(tokenAuth);
    TaskRunnerManager::GetInstance().ExecuteAll();

    EXPECT_CALL(*tokenAuth, Start()).Times(1);

    manager_->Remove(1);
    ASSERT_NO_THROW(TaskRunnerManager::GetInstance().ExecuteAll());
}

HWTEST_F(RequestManagerImplTest, MutualExclusion_IssueTokenWaitsForAll_TokenAuthMultipleRunning, TestSize.Level0)
{
    auto tokenAuth1 = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(10));

    auto tokenAuth2 = CreateMockRequest(
        MockRequestConfig {}.WithId(2).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(10));

    auto issueToken = CreateMockRequest(MockRequestConfig {}
                                            .WithId(3)
                                            .WithType(RequestType::HOST_ISSUE_TOKEN_REQUEST)
                                            .WithMaxConcurrency(10)
                                            .WithConflictingType(RequestType::HOST_TOKEN_AUTH_REQUEST));

    EXPECT_CALL(*tokenAuth1, Start()).Times(1);
    EXPECT_CALL(*tokenAuth2, Start()).Times(1);

    manager_->Start(tokenAuth1);
    manager_->Start(tokenAuth2);
    manager_->Start(issueToken);
    TaskRunnerManager::GetInstance().ExecuteAll();

    // Remove first TokenAuth → IssueToken still blocked by second TokenAuth
    EXPECT_CALL(*issueToken, Start()).Times(0);
    manager_->Remove(1);
    TaskRunnerManager::GetInstance().ExecuteAll();

    // Remove second TokenAuth → IssueToken can now start
    EXPECT_CALL(*issueToken, Start()).Times(1);
    manager_->Remove(2);
    ASSERT_NO_THROW(TaskRunnerManager::GetInstance().ExecuteAll());
}

HWTEST_F(RequestManagerImplTest, MutualExclusion_FIFO_NewTokenAuthWaits_WhenIssueTokenWaiting, TestSize.Level0)
{
    auto tokenAuth1 = CreateMockRequest(
        MockRequestConfig {}.WithId(1).WithType(RequestType::HOST_TOKEN_AUTH_REQUEST).WithMaxConcurrency(10));

    auto issueToken = CreateMockRequest(MockRequestConfig {}
                                            .WithId(2)
                                            .WithType(RequestType::HOST_ISSUE_TOKEN_REQUEST)
                                            .WithMaxConcurrency(10)
                                            .WithConflictingType(RequestType::HOST_TOKEN_AUTH_REQUEST));

    auto tokenAuth2 = CreateMockRequest(MockRequestConfig {}
                                            .WithId(3)
                                            .WithType(RequestType::HOST_TOKEN_AUTH_REQUEST)
                                            .WithMaxConcurrency(10)
                                            .WithConflictingType(RequestType::HOST_ISSUE_TOKEN_REQUEST));

    EXPECT_CALL(*tokenAuth1, Start()).Times(1);

    manager_->Start(tokenAuth1);
    manager_->Start(issueToken); // blocked by tokenAuth1, goes to waiting
    manager_->Start(tokenAuth2); // sees issueToken in prevRequests, also goes to waiting
    TaskRunnerManager::GetInstance().ExecuteAll();

    // tokenAuth1 finishes → issueToken (ahead in queue) promoted first
    EXPECT_CALL(*issueToken, Start()).Times(1);
    EXPECT_CALL(*tokenAuth2, Start()).Times(0);

    manager_->Remove(1);
    ASSERT_NO_THROW(TaskRunnerManager::GetInstance().ExecuteAll());
}

// ============== maxTotalRequests Limit Tests ==============

HWTEST_F(RequestManagerImplTest, Start_RejectsNewRequest_WhenTotalRequestsReachLimit, TestSize.Level0)
{
    // Fill runningRequests_ up to 200 (all different types to avoid concurrency blocking).
    constexpr size_t maxTotalRequests = 200;
    constexpr uint32_t unlimited = 200;

    for (size_t i = 0; i < maxTotalRequests; ++i) {
        auto request =
            CreateMockRequest(MockRequestConfig {}.WithId(static_cast<RequestId>(i + 1)).WithMaxConcurrency(unlimited));
        ASSERT_TRUE(manager_->Start(request));
    }

    ASSERT_EQ(manager_->runningRequests_.size() + manager_->waitingRequests_.size(), maxTotalRequests);

    // The 201st request should be rejected.
    auto overflowRequest = CreateMockRequest(MockRequestConfig {}.WithId(static_cast<RequestId>(maxTotalRequests + 1)));
    bool result = manager_->Start(overflowRequest);
    EXPECT_FALSE(result);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
