/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "mock_guard.h"

#include "binding_signature_message.h"
#include "host_binding_proof_obtainer.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

constexpr int32_t HOST_USER_ID = 100;
constexpr int32_t COMPANION_USER_ID = 200;
constexpr int32_t OTHER_USER_ID = 201;
constexpr TemplateId TEMPLATE_ID = 1;
// arbitrary byte length within the DER signature upper bound
constexpr size_t TEST_BINDING_SIGNATURE_LEN = 64;

const DeviceKey PEER_DEVICE_KEY = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
    .deviceId = "peer_device_id",
    .deviceUserId = COMPANION_USER_ID,
    .deviceSubProfileId = 0 };

Attributes BuildBusinessRequest()
{
    Attributes attributes = {};
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, HOST_USER_ID);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_SUB_PROFILE_ID, 0);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, COMPANION_USER_ID);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_SUB_PROFILE_ID, 0);
    return attributes;
}

Attributes BuildChallengeReply(ResultCode result, int32_t companionUserId)
{
    GetBindingSignatureChallengeReply reply = {};
    reply.result = result;
    reply.companionUserKey = UserKey { companionUserId, 0 };
    reply.challenge = std::vector<uint8_t>(BINDING_SIGNATURE_CHALLENGE_LEN, 0x5A);
    Attributes attributes = {};
    EncodeGetBindingSignatureChallengeReply(reply, attributes);
    // a genuine peer reply was dispatched to the handler; only undelivered messages lack this mark
    return attributes;
}

class HostBindingProofObtainerTest : public Test {
protected:
    void SetUp() override
    {
        // shared ownership: the challenge reply callback captures weak_from_this(), which stays
        // empty without a control block
        obtainer_ = std::make_shared<HostBindingProofObtainer>();
    }

    void MockMatchingBinding(MockGuard &guard)
    {
        CompanionStatus companionStatus = {};
        companionStatus.companionDeviceStatus.deviceKey = PEER_DEVICE_KEY;
        ON_CALL(guard.GetCompanionManager(), GetCompanionStatus(An<TemplateId>()))
            .WillByDefault(Return(std::make_optional(companionStatus)));
    }

    void MockSignSuccess(MockGuard &guard)
    {
        ON_CALL(guard.GetSecurityAgent(), HostBindingSign(_, _))
            .WillByDefault(Invoke([](const HostBindingSignInput &, HostBindingSignOutput &output) {
                output.signature = std::vector<uint8_t>(TEST_BINDING_SIGNATURE_LEN, 0xEE);
                return ResultCode::SUCCESS;
            }));
    }

    // Answers GET_BINDING_SIGNATURE_CHALLENGE inline with the given reply attributes.
    // replyAttributes is captured by value: callers pass temporaries.
    void MockInlineChallengeReply(MockGuard &guard, const Attributes &replyAttributes)
    {
        ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _))
            .WillByDefault(Invoke(
                [replyAttributes](const std::string &, MessageType msgType, Attributes &, OnMessageReply &&onReply) {
                    if (msgType != MessageType::GET_BINDING_SIGNATURE_CHALLENGE) {
                        return true;
                    }
                    onReply(replyAttributes);
                    return true;
                }));
    }

    std::shared_ptr<HostBindingProofObtainer> obtainer_;
};

// A successful challenge round caches the proof and attaches it into the business request;
// AttachProof then serves later protected sends without another round trip.
HWTEST_F(HostBindingProofObtainerTest, ObtainAndAttach_Success_CachesAndAttaches, TestSize.Level0)
{
    MockGuard guard;
    MockMatchingBinding(guard);
    MockSignSuccess(guard);
    MockInlineChallengeReply(guard, BuildChallengeReply(ResultCode::SUCCESS, COMPANION_USER_ID));

    auto request = std::make_shared<Attributes>(BuildBusinessRequest());
    int32_t readyCount = 0;
    ResultCode readyValue = ResultCode::GENERAL_ERROR;
    obtainer_->ObtainAndAttach("test-conn", TEMPLATE_ID, MessageType::PRE_ISSUE_TOKEN, request,
        [&readyCount, &readyValue](ResultCode result) {
            ++readyCount;
            readyValue = result;
        });

    EXPECT_EQ(readyCount, 1);
    EXPECT_EQ(readyValue, ResultCode::SUCCESS);
    EXPECT_TRUE(obtainer_->HasProof());

    std::vector<uint8_t> attachedChallenge;
    std::vector<uint8_t> attachedSignature;
    EXPECT_TRUE(request->GetUint8ArrayValue(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE_CHALLENGE, attachedChallenge));
    EXPECT_TRUE(request->GetUint8ArrayValue(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE, attachedSignature));
    EXPECT_EQ(attachedChallenge, std::vector<uint8_t>(BINDING_SIGNATURE_CHALLENGE_LEN, 0x5A));
    EXPECT_EQ(attachedSignature, std::vector<uint8_t>(TEST_BINDING_SIGNATURE_LEN, 0xEE));

    Attributes laterRequest = BuildBusinessRequest();
    EXPECT_TRUE(obtainer_->AttachProof(laterRequest));
    EXPECT_TRUE(laterRequest.GetUint8ArrayValue(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE, attachedSignature));
    EXPECT_EQ(attachedSignature, std::vector<uint8_t>(TEST_BINDING_SIGNATURE_LEN, 0xEE));
}

// AttachProof without prior proof reports false so the caller falls back to acquisition.
HWTEST_F(HostBindingProofObtainerTest, AttachProof_NoProof_ReturnsFalse, TestSize.Level0)
{
    Attributes request = BuildBusinessRequest();
    EXPECT_FALSE(obtainer_->AttachProof(request));
    EXPECT_FALSE(request.HasAttribute(Attributes::ATTR_CDA_SA_BINDING_SIGNATURE));
}

// The reply identity must match the binding resolved by templateId; a mismatch fails without
// reaching HostBindingSign.
HWTEST_F(HostBindingProofObtainerTest, ObtainAndAttach_ReplyIdentityMismatch_FailsWithoutSign, TestSize.Level0)
{
    MockGuard guard;
    MockMatchingBinding(guard);
    MockInlineChallengeReply(guard, BuildChallengeReply(ResultCode::SUCCESS, OTHER_USER_ID));
    EXPECT_CALL(guard.GetSecurityAgent(), HostBindingSign(_, _)).Times(0);

    auto request = std::make_shared<Attributes>(BuildBusinessRequest());
    ResultCode received = ResultCode::SUCCESS;
    obtainer_->ObtainAndAttach("test-conn", TEMPLATE_ID, MessageType::PRE_ISSUE_TOKEN, request,
        [&received](ResultCode result) { received = result; });

    EXPECT_EQ(received, ResultCode::TARGET_USER_MISMATCH);
    EXPECT_FALSE(obtainer_->HasProof());
}

// No local binding for the templateId fails acquisition.
HWTEST_F(HostBindingProofObtainerTest, ObtainAndAttach_NoLocalBinding_Fails, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetCompanionManager(), GetCompanionStatus(An<TemplateId>()))
        .WillByDefault(Return(std::optional<CompanionStatus>()));
    MockInlineChallengeReply(guard, BuildChallengeReply(ResultCode::SUCCESS, COMPANION_USER_ID));
    EXPECT_CALL(guard.GetSecurityAgent(), HostBindingSign(_, _)).Times(0);

    auto request = std::make_shared<Attributes>(BuildBusinessRequest());
    ResultCode received = ResultCode::SUCCESS;
    obtainer_->ObtainAndAttach("test-conn", TEMPLATE_ID, MessageType::PRE_ISSUE_TOKEN, request,
        [&received](ResultCode result) { received = result; });

    EXPECT_EQ(received, ResultCode::NOT_ENROLLED);
}

// A peer error reply fails acquisition.
HWTEST_F(HostBindingProofObtainerTest, ObtainAndAttach_PeerError_Fails, TestSize.Level0)
{
    MockGuard guard;
    MockInlineChallengeReply(guard, BuildChallengeReply(ResultCode::GENERAL_ERROR, COMPANION_USER_ID));
    EXPECT_CALL(guard.GetSecurityAgent(), HostBindingSign(_, _)).Times(0);

    auto request = std::make_shared<Attributes>(BuildBusinessRequest());
    ResultCode received = ResultCode::SUCCESS;
    obtainer_->ObtainAndAttach("test-conn", TEMPLATE_ID, MessageType::PRE_ISSUE_TOKEN, request,
        [&received](ResultCode result) { received = result; });

    EXPECT_EQ(received, ResultCode::GENERAL_ERROR);
}

// The router synthesizes the timeout reply locally without the dispatch mark; the result is
// passed through untouched so transport timeouts never invalidate healthy V2 bindings.
HWTEST_F(HostBindingProofObtainerTest, ObtainAndAttach_TimeoutReply_PassesThrough, TestSize.Level0)
{
    MockGuard guard;
    Attributes timeoutReply = {};
    timeoutReply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, ResultCode::TIMEOUT);
    MockInlineChallengeReply(guard, timeoutReply);
    EXPECT_CALL(guard.GetSecurityAgent(), HostBindingSign(_, _)).Times(0);

    auto request = std::make_shared<Attributes>(BuildBusinessRequest());
    ResultCode received = ResultCode::SUCCESS;
    obtainer_->ObtainAndAttach("test-conn", TEMPLATE_ID, MessageType::PRE_ISSUE_TOKEN, request,
        [&received](ResultCode result) { received = result; });

    EXPECT_EQ(received, ResultCode::TIMEOUT);
    EXPECT_FALSE(obtainer_->HasProof());
}

// A reply without the dispatch mark carries no routing metadata: the result code is taken at
// face value and no reinterpretation is applied.
HWTEST_F(HostBindingProofObtainerTest, ObtainAndAttach_UnmarkedPeerError_PassesResultThrough, TestSize.Level0)
{
    MockGuard guard;
    Attributes unmarkedReply = {};
    unmarkedReply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, ResultCode::GENERAL_ERROR);
    MockInlineChallengeReply(guard, unmarkedReply);
    EXPECT_CALL(guard.GetSecurityAgent(), HostBindingSign(_, _)).Times(0);

    auto request = std::make_shared<Attributes>(BuildBusinessRequest());
    ResultCode received = ResultCode::SUCCESS;
    obtainer_->ObtainAndAttach("test-conn", TEMPLATE_ID, MessageType::PRE_ISSUE_TOKEN, request,
        [&received](ResultCode result) { received = result; });

    EXPECT_EQ(received, ResultCode::GENERAL_ERROR);
    EXPECT_FALSE(obtainer_->HasProof());
}

// A failing HostBindingSign fails acquisition.
HWTEST_F(HostBindingProofObtainerTest, ObtainAndAttach_SignFailed_Fails, TestSize.Level0)
{
    MockGuard guard;
    MockMatchingBinding(guard);
    MockInlineChallengeReply(guard, BuildChallengeReply(ResultCode::SUCCESS, COMPANION_USER_ID));
    ON_CALL(guard.GetSecurityAgent(), HostBindingSign(_, _)).WillByDefault(Return(ResultCode::GENERAL_ERROR));

    auto request = std::make_shared<Attributes>(BuildBusinessRequest());
    ResultCode received = ResultCode::SUCCESS;
    obtainer_->ObtainAndAttach("test-conn", TEMPLATE_ID, MessageType::PRE_ISSUE_TOKEN, request,
        [&received](ResultCode result) { received = result; });

    EXPECT_EQ(received, ResultCode::GENERAL_ERROR);
    EXPECT_FALSE(obtainer_->HasProof());
}

// A failed GET send settles the caller synchronously instead of leaving it to a timeout.
HWTEST_F(HostBindingProofObtainerTest, ObtainAndAttach_SendFailed_FailsSynchronously, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).WillByDefault(Return(false));

    auto request = std::make_shared<Attributes>(BuildBusinessRequest());
    ResultCode received = ResultCode::SUCCESS;
    obtainer_->ObtainAndAttach("test-conn", TEMPLATE_ID, MessageType::PRE_ISSUE_TOKEN, request,
        [&received](ResultCode result) { received = result; });

    EXPECT_EQ(received, ResultCode::COMMUNICATION_ERROR);
}

// Identity fields come from the business message itself: a request without them fails before any
// send.
HWTEST_F(HostBindingProofObtainerTest, ObtainAndAttach_MissingHostIdentity_FailsWithoutSend, TestSize.Level0)
{
    MockGuard guard;
    EXPECT_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _)).Times(0);

    auto request = std::make_shared<Attributes>();
    ResultCode received = ResultCode::SUCCESS;
    obtainer_->ObtainAndAttach("test-conn", TEMPLATE_ID, MessageType::PRE_ISSUE_TOKEN, request,
        [&received](ResultCode result) { received = result; });

    EXPECT_EQ(received, ResultCode::INVALID_PARAMETERS);
}

// A claimed companion identity counts only when complete: a lone companion user id is not a
// claim, so the challenge goes out untargeted instead of failing.
HWTEST_F(HostBindingProofObtainerTest, ObtainAndAttach_MissingCompanionSubProfile_SendsUntargeted, TestSize.Level0)
{
    MockGuard guard;
    Attributes sent = {};
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _))
        .WillByDefault(Invoke([&sent](const std::string &, MessageType, Attributes &request, OnMessageReply &&) {
            sent = request;
            return false;
        }));

    Attributes partial = {};
    partial.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, HOST_USER_ID);
    partial.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_SUB_PROFILE_ID, 0);
    partial.SetInt32Value(Attributes::ATTR_CDA_SA_COMPANION_USER_ID, COMPANION_USER_ID);
    auto request = std::make_shared<Attributes>(partial);
    ResultCode received = ResultCode::SUCCESS;
    obtainer_->ObtainAndAttach("test-conn", TEMPLATE_ID, MessageType::PRE_ISSUE_TOKEN, request,
        [&received](ResultCode result) { received = result; });

    EXPECT_FALSE(sent.HasAttribute(Attributes::ATTR_CDA_SA_COMPANION_USER_ID));
    EXPECT_EQ(received, ResultCode::COMMUNICATION_ERROR);
}

// The reply callback holds only a weak reference: an obtainer destroyed before the reply lands is
// a no-op, not a use-after-free.
HWTEST_F(HostBindingProofObtainerTest, ObtainAndAttach_ObtainerDestroyedBeforeReply_NoCallback, TestSize.Level0)
{
    MockGuard guard;
    OnMessageReply pendingReply;
    ON_CALL(guard.GetCrossDeviceCommManager(), SendMessage(_, _, _, _))
        .WillByDefault(
            Invoke([&pendingReply](const std::string &, MessageType, Attributes &, OnMessageReply &&onReply) {
                pendingReply = std::move(onReply);
                return true;
            }));

    auto request = std::make_shared<Attributes>(BuildBusinessRequest());
    bool isReadyCalled = false;
    obtainer_->ObtainAndAttach("test-conn", TEMPLATE_ID, MessageType::PRE_ISSUE_TOKEN, request,
        [&isReadyCalled](ResultCode) { isReadyCalled = true; });

    obtainer_.reset();
    ASSERT_TRUE(pendingReply != nullptr);
    pendingReply(BuildChallengeReply(ResultCode::SUCCESS, COMPANION_USER_ID));

    EXPECT_FALSE(isReadyCalled);
}

// The gate keys on both the message type and the binding's enrolled signature flag.
HWTEST_F(HostBindingProofObtainerTest, NeedBindingSignature_Gate, TestSize.Level0)
{
    MockGuard guard;
    ON_CALL(guard.GetCompanionManager(), IsBindingSignatureRequired(An<TemplateId>())).WillByDefault(Return(true));

    EXPECT_TRUE(HostBindingProofObtainer::NeedBindingSignature(MessageType::PRE_ISSUE_TOKEN,
        std::optional<TemplateId>(TEMPLATE_ID)));
    EXPECT_FALSE(HostBindingProofObtainer::NeedBindingSignature(MessageType::REMOVE_HOST_BINDING,
        std::optional<TemplateId>(TEMPLATE_ID)));
    EXPECT_FALSE(HostBindingProofObtainer::NeedBindingSignature(MessageType::PRE_ISSUE_TOKEN, std::nullopt));

    ON_CALL(guard.GetCompanionManager(), IsBindingSignatureRequired(An<TemplateId>())).WillByDefault(Return(false));
    EXPECT_FALSE(HostBindingProofObtainer::NeedBindingSignature(MessageType::PRE_ISSUE_TOKEN,
        std::optional<TemplateId>(TEMPLATE_ID)));
}
} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
