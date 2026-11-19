/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "mock_guard.h"

#include "binding_signature_message.h"
#include "companion_get_binding_signature_challenge_handler.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr int32_t INT32_200 = 200;
constexpr int32_t INT32_201 = 201;
constexpr int32_t SUB_PROFILE_2 = 2;
constexpr int32_t SUB_PROFILE_3 = 3;

class CompanionGetBindingSignatureChallengeHandlerTest : public Test {
protected:
    void SetUp() override
    {
        // shared ownership: the disconnect callback captures weak_from_this(), which stays empty
        // without a control block
        handler_ = std::make_shared<CompanionGetBindingSignatureChallengeHandler>();
    }

    // Builds a request with the host identity; companionUserKey std::nullopt means the target fields
    // are omitted so the companion falls back to its active user.
    void BuildRequest(Attributes &request, const std::optional<UserKey> &companionUserKey,
        const std::string &connectionName = "challenge_connection")
    {
        GetBindingSignatureChallengeRequest challengeRequest = { .hostDeviceKey = hostDeviceKey_,
            .companionUserKey = companionUserKey };
        EncodeGetBindingSignatureChallengeRequest(challengeRequest, request);
        // the channel layer stamps the source identity on real inbound messages
        request.SetInt32Value(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER_TYPE, static_cast<int32_t>(hostDeviceKey_.idType));
        request.SetStringValue(Attributes::ATTR_CDA_SA_SRC_IDENTIFIER, hostDeviceKey_.deviceId);
        request.SetStringValue(Attributes::ATTR_CDA_SA_CONNECTION_NAME, connectionName);
    }

    static ResultCode ReadReplyResult(const Attributes &reply)
    {
        int32_t replyResult = 0;
        EXPECT_TRUE(reply.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, replyResult));
        return static_cast<ResultCode>(replyResult);
    }

    std::shared_ptr<CompanionGetBindingSignatureChallengeHandler> handler_;
    DeviceKey hostDeviceKey_ = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "host_device_id",
        .deviceUserId = 100 };
    UserKey activeUserKey_ = { .userId = INT32_200, .subProfileId = SUB_PROFILE_2 };
};

HWTEST_F(CompanionGetBindingSignatureChallengeHandlerTest, HandleRequest_001, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Invoke(
            [](const std::string &, OnConnectionStatusChange &&) { return std::make_unique<Subscription>([]() {}); }));
    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey()).WillOnce(Return(activeUserKey_));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionGenerateBindingSignatureChallenge)
        .WillOnce([](CompanionGenerateBindingSignatureChallengeOutput &output) {
            output.challenge = std::vector<uint8_t>(BINDING_SIGNATURE_CHALLENGE_LEN, 0xAB);
            return ResultCode::SUCCESS;
        });

    Attributes request;
    BuildRequest(request, std::nullopt);

    Attributes reply;
    handler_->HandleRequest(request, reply);

    EXPECT_EQ(ReadReplyResult(reply), ResultCode::SUCCESS);
    auto replyOpt = DecodeGetBindingSignatureChallengeReply(reply);
    ASSERT_TRUE(replyOpt.has_value());
    EXPECT_EQ(replyOpt->companionUserKey, activeUserKey_);
    EXPECT_EQ(replyOpt->challenge.size(), BINDING_SIGNATURE_CHALLENGE_LEN);
}

HWTEST_F(CompanionGetBindingSignatureChallengeHandlerTest, HandleRequest_002, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Invoke(
            [](const std::string &, OnConnectionStatusChange &&) { return std::make_unique<Subscription>([]() {}); }));
    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey()).WillOnce(Return(activeUserKey_));
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::make_optional(HostBindingStatus {})));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionGenerateBindingSignatureChallenge)
        .WillOnce([](CompanionGenerateBindingSignatureChallengeOutput &output) {
            output.challenge = std::vector<uint8_t>(BINDING_SIGNATURE_CHALLENGE_LEN, 0xAB);
            return ResultCode::SUCCESS;
        });

    Attributes request;
    BuildRequest(request, activeUserKey_);

    Attributes reply;
    handler_->HandleRequest(request, reply);

    EXPECT_EQ(ReadReplyResult(reply), ResultCode::SUCCESS);
    auto replyOpt = DecodeGetBindingSignatureChallengeReply(reply);
    ASSERT_TRUE(replyOpt.has_value());
    EXPECT_EQ(replyOpt->companionUserKey, activeUserKey_);
}

HWTEST_F(CompanionGetBindingSignatureChallengeHandlerTest, HandleRequest_003, TestSize.Level0)
{
    MockGuard guard;
    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey()).WillOnce(Return(activeUserKey_));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionGenerateBindingSignatureChallenge).Times(0);

    Attributes request;
    BuildRequest(request, UserKey { .userId = INT32_201, .subProfileId = SUB_PROFILE_2 });

    Attributes reply;
    handler_->HandleRequest(request, reply);

    EXPECT_EQ(ReadReplyResult(reply), ResultCode::TARGET_USER_MISMATCH);
}

HWTEST_F(CompanionGetBindingSignatureChallengeHandlerTest, HandleRequest_004, TestSize.Level0)
{
    MockGuard guard;
    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey()).WillOnce(Return(activeUserKey_));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionGenerateBindingSignatureChallenge).Times(0);

    Attributes request;
    BuildRequest(request, UserKey { .userId = INT32_200, .subProfileId = SUB_PROFILE_3 });

    Attributes reply;
    handler_->HandleRequest(request, reply);

    EXPECT_EQ(ReadReplyResult(reply), ResultCode::TARGET_USER_MISMATCH);
}

HWTEST_F(CompanionGetBindingSignatureChallengeHandlerTest, HandleRequest_005, TestSize.Level0)
{
    MockGuard guard;
    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey())
        .WillOnce(Return(UserKey { .userId = INVALID_USER_ID, .subProfileId = INVALID_SUB_PROFILE_ID }));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionGenerateBindingSignatureChallenge).Times(0);

    Attributes request;
    BuildRequest(request, std::nullopt);

    Attributes reply;
    handler_->HandleRequest(request, reply);

    EXPECT_EQ(ReadReplyResult(reply), ResultCode::TARGET_USER_MISMATCH);
}

HWTEST_F(CompanionGetBindingSignatureChallengeHandlerTest, HandleRequest_006, TestSize.Level0)
{
    MockGuard guard;
    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey())
        .WillOnce(Return(UserKey { .userId = INVALID_USER_ID, .subProfileId = INVALID_SUB_PROFILE_ID }));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionGenerateBindingSignatureChallenge).Times(0);

    // An explicit target with no unlocked active user is also an identity mismatch.
    Attributes request;
    BuildRequest(request, activeUserKey_);

    Attributes reply;
    handler_->HandleRequest(request, reply);

    EXPECT_EQ(ReadReplyResult(reply), ResultCode::TARGET_USER_MISMATCH);
}

// Every request on a connection re-issues a fresh challenge from the agent and re-subscribes to
// the connection status; the superseded challenge is purged from the Rust pool right away.
HWTEST_F(CompanionGetBindingSignatureChallengeHandlerTest, HandleRequest_007, TestSize.Level0)
{
    MockGuard guard;
    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey()).WillRepeatedly(Return(activeUserKey_));
    int32_t issueCount = 0;
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionGenerateBindingSignatureChallenge)
        .WillRepeatedly([&issueCount](CompanionGenerateBindingSignatureChallengeOutput &output) {
            ++issueCount;
            output.challenge = std::vector<uint8_t>(BINDING_SIGNATURE_CHALLENGE_LEN, 0xA0 + issueCount);
            return ResultCode::SUCCESS;
        });
    std::vector<uint8_t> firstChallenge(BINDING_SIGNATURE_CHALLENGE_LEN, 0xA1);
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionPurgeBindingSignatureChallenge(ElementsAreArray(firstChallenge)))
        .Times(1)
        .WillOnce(Return(ResultCode::SUCCESS));

    int32_t subscribeCount = 0;
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Invoke([&subscribeCount](const std::string &, OnConnectionStatusChange &&) {
            ++subscribeCount;
            return std::make_unique<Subscription>([]() {});
        }));

    Attributes firstRequest;
    BuildRequest(firstRequest, std::nullopt);
    Attributes firstReply;
    handler_->HandleRequest(firstRequest, firstReply);
    EXPECT_EQ(ReadReplyResult(firstReply), ResultCode::SUCCESS);
    auto firstReplyOpt = DecodeGetBindingSignatureChallengeReply(firstReply);
    ASSERT_TRUE(firstReplyOpt.has_value());

    Attributes secondRequest;
    BuildRequest(secondRequest, std::nullopt);
    Attributes secondReply;
    handler_->HandleRequest(secondRequest, secondReply);
    EXPECT_EQ(ReadReplyResult(secondReply), ResultCode::SUCCESS);
    auto secondReplyOpt = DecodeGetBindingSignatureChallengeReply(secondReply);
    ASSERT_TRUE(secondReplyOpt.has_value());

    EXPECT_EQ(firstReplyOpt->challenge, std::vector<uint8_t>(BINDING_SIGNATURE_CHALLENGE_LEN, 0xA1));
    EXPECT_EQ(secondReplyOpt->challenge, std::vector<uint8_t>(BINDING_SIGNATURE_CHALLENGE_LEN, 0xA2));
    EXPECT_EQ(issueCount, 2);
    EXPECT_EQ(subscribeCount, 2);
}

// A superseded challenge is purged when its record is replaced, and the disconnect purge still
// targets the latest challenge: no orphaned entry is left to the Rust pool TTL.
HWTEST_F(CompanionGetBindingSignatureChallengeHandlerTest, HandleRequest_009, TestSize.Level0)
{
    MockGuard guard;
    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey()).WillRepeatedly(Return(activeUserKey_));
    int32_t issueCount = 0;
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionGenerateBindingSignatureChallenge)
        .WillRepeatedly([&issueCount](CompanionGenerateBindingSignatureChallengeOutput &output) {
            ++issueCount;
            output.challenge = std::vector<uint8_t>(BINDING_SIGNATURE_CHALLENGE_LEN, 0xA0 + issueCount);
            return ResultCode::SUCCESS;
        });
    std::vector<uint8_t> firstChallenge(BINDING_SIGNATURE_CHALLENGE_LEN, 0xA1);
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionPurgeBindingSignatureChallenge(ElementsAreArray(firstChallenge)))
        .Times(1)
        .WillOnce(Return(ResultCode::SUCCESS));
    std::vector<uint8_t> latestChallenge(BINDING_SIGNATURE_CHALLENGE_LEN, 0xA2);
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionPurgeBindingSignatureChallenge(ElementsAreArray(latestChallenge)))
        .Times(1)
        .WillOnce(Return(ResultCode::SUCCESS));

    OnConnectionStatusChange statusCb = nullptr;
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Invoke([&statusCb](const std::string &, OnConnectionStatusChange &&onStatusChange) {
            statusCb = std::move(onStatusChange);
            return std::make_unique<Subscription>([]() {});
        }));

    Attributes firstRequest;
    BuildRequest(firstRequest, std::nullopt);
    Attributes firstReply;
    handler_->HandleRequest(firstRequest, firstReply);
    EXPECT_EQ(ReadReplyResult(firstReply), ResultCode::SUCCESS);

    Attributes secondRequest;
    BuildRequest(secondRequest, std::nullopt);
    Attributes secondReply;
    handler_->HandleRequest(secondRequest, secondReply);
    EXPECT_EQ(ReadReplyResult(secondReply), ResultCode::SUCCESS);
    auto secondReplyOpt = DecodeGetBindingSignatureChallengeReply(secondReply);
    ASSERT_TRUE(secondReplyOpt.has_value());
    EXPECT_EQ(secondReplyOpt->challenge, latestChallenge);

    ASSERT_TRUE(statusCb != nullptr);
    statusCb("challenge_connection", ConnectionStatus::DISCONNECTED, "shutdown");
}

// Connection records are a recency-ordered vector capped at the capacity: admitting a new
// connection evicts the oldest record (purging its challenge), and the evicted connection
// re-issues on its next request.
HWTEST_F(CompanionGetBindingSignatureChallengeHandlerTest, HandleRequest_010, TestSize.Level0)
{
    MockGuard guard;
    constexpr size_t connectionCapacity = 100;
    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey()).WillRepeatedly(Return(activeUserKey_));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionGenerateBindingSignatureChallenge)
        .Times(connectionCapacity + 2)
        .WillRepeatedly([](CompanionGenerateBindingSignatureChallengeOutput &output) {
            output.challenge = std::vector<uint8_t>(BINDING_SIGNATURE_CHALLENGE_LEN, 0xAB);
            return ResultCode::SUCCESS;
        });
    std::vector<uint8_t> issuedChallenge(BINDING_SIGNATURE_CHALLENGE_LEN, 0xAB);
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionPurgeBindingSignatureChallenge(ElementsAreArray(issuedChallenge)))
        .Times(2)
        .WillRepeatedly(Return(ResultCode::SUCCESS));
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Invoke(
            [](const std::string &, OnConnectionStatusChange &&) { return std::make_unique<Subscription>([]() {}); }));

    for (size_t i = 0; i < connectionCapacity; ++i) {
        Attributes request;
        BuildRequest(request, std::nullopt, "challenge_connection_" + std::to_string(i));
        Attributes reply;
        handler_->HandleRequest(request, reply);
        EXPECT_EQ(ReadReplyResult(reply), ResultCode::SUCCESS);
    }

    Attributes overflowRequest;
    BuildRequest(overflowRequest, std::nullopt, "challenge_connection_overflow");
    Attributes overflowReply;
    handler_->HandleRequest(overflowRequest, overflowReply);
    EXPECT_EQ(ReadReplyResult(overflowReply), ResultCode::SUCCESS);

    Attributes evictedRequest;
    BuildRequest(evictedRequest, std::nullopt, "challenge_connection_0");
    Attributes evictedReply;
    handler_->HandleRequest(evictedRequest, evictedReply);
    EXPECT_EQ(ReadReplyResult(evictedReply), ResultCode::SUCCESS);
}

// DISCONNECTED purges the pool entry exactly once; other statuses are ignored.
HWTEST_F(CompanionGetBindingSignatureChallengeHandlerTest, HandleRequest_008, TestSize.Level0)
{
    MockGuard guard;
    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey()).WillOnce(Return(activeUserKey_));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionGenerateBindingSignatureChallenge)
        .WillOnce([](CompanionGenerateBindingSignatureChallengeOutput &output) {
            output.challenge = std::vector<uint8_t>(BINDING_SIGNATURE_CHALLENGE_LEN, 0xAB);
            return ResultCode::SUCCESS;
        });
    std::vector<uint8_t> issuedChallenge(BINDING_SIGNATURE_CHALLENGE_LEN, 0xAB);
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionPurgeBindingSignatureChallenge(ElementsAreArray(issuedChallenge)))
        .Times(1)
        .WillOnce(Return(ResultCode::SUCCESS));

    OnConnectionStatusChange statusCb = nullptr;
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Invoke([&statusCb](const std::string &, OnConnectionStatusChange &&onStatusChange) {
            statusCb = std::move(onStatusChange);
            return std::make_unique<Subscription>([]() {});
        }));

    Attributes request;
    BuildRequest(request, std::nullopt);
    Attributes reply;
    handler_->HandleRequest(request, reply);
    ASSERT_EQ(ReadReplyResult(reply), ResultCode::SUCCESS);
    ASSERT_TRUE(statusCb != nullptr);

    statusCb("challenge_connection", ConnectionStatus::CONNECTED, "connected");
    statusCb("challenge_connection", ConnectionStatus::DISCONNECTED, "shutdown");
    // a repeated disconnect notification for the already-purged connection is a no-op
    statusCb("challenge_connection", ConnectionStatus::DISCONNECTED, "shutdown");
}

// An asserted identity must have a host binding: rejecting before the agent saves a pool challenge.
HWTEST_F(CompanionGetBindingSignatureChallengeHandlerTest, HandleRequest_011, TestSize.Level0)
{
    MockGuard guard;
    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey()).WillOnce(Return(activeUserKey_));
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::optional<HostBindingStatus>()));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionGenerateBindingSignatureChallenge).Times(0);

    Attributes request;
    BuildRequest(request, activeUserKey_);

    Attributes reply;
    handler_->HandleRequest(request, reply);

    EXPECT_EQ(ReadReplyResult(reply), ResultCode::NOT_ENROLLED);
}

// The ask mode carries no identity claim and no binding requirement: the discovery query is
// answered even without a host binding.
HWTEST_F(CompanionGetBindingSignatureChallengeHandlerTest, HandleRequest_012, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Invoke(
            [](const std::string &, OnConnectionStatusChange &&) { return std::make_unique<Subscription>([]() {}); }));
    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey()).WillOnce(Return(activeUserKey_));
    ON_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _))
        .WillByDefault(Return(std::optional<HostBindingStatus>()));
    EXPECT_CALL(guard.GetHostBindingManager(), GetHostBindingStatus(_, _)).Times(0);
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionGenerateBindingSignatureChallenge)
        .WillOnce([](CompanionGenerateBindingSignatureChallengeOutput &output) {
            output.challenge = std::vector<uint8_t>(BINDING_SIGNATURE_CHALLENGE_LEN, 0xAB);
            return ResultCode::SUCCESS;
        });

    Attributes request;
    BuildRequest(request, std::nullopt);

    Attributes reply;
    handler_->HandleRequest(request, reply);

    EXPECT_EQ(ReadReplyResult(reply), ResultCode::SUCCESS);
}

// Without a connection status subscription the disconnect purge can never fire, so the freshly
// issued challenge is returned to the pool immediately and the request fails.
HWTEST_F(CompanionGetBindingSignatureChallengeHandlerTest, HandleRequest_013, TestSize.Level0)
{
    MockGuard guard;
    EXPECT_CALL(guard.GetUserKeyManager(), GetUnlockedActiveUserkey()).WillOnce(Return(activeUserKey_));
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionGenerateBindingSignatureChallenge)
        .WillOnce([](CompanionGenerateBindingSignatureChallengeOutput &output) {
            output.challenge = std::vector<uint8_t>(BINDING_SIGNATURE_CHALLENGE_LEN, 0xAB);
            return ResultCode::SUCCESS;
        });
    std::vector<uint8_t> issuedChallenge(BINDING_SIGNATURE_CHALLENGE_LEN, 0xAB);
    EXPECT_CALL(guard.GetSecurityAgent(), CompanionPurgeBindingSignatureChallenge(ElementsAreArray(issuedChallenge)))
        .Times(1)
        .WillOnce(Return(ResultCode::SUCCESS));
    // override the MockGuard default subscription with a null one
    ON_CALL(guard.GetCrossDeviceCommManager(), SubscribeConnectionStatus(_, _))
        .WillByDefault(Invoke([](const std::string &, OnConnectionStatusChange &&) { return nullptr; }));

    Attributes request;
    BuildRequest(request, std::nullopt);

    Attributes reply;
    handler_->HandleRequest(request, reply);

    EXPECT_EQ(ReadReplyResult(reply), ResultCode::GENERAL_ERROR);
}
} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
