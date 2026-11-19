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

#include <cstdint>
#include <cstring>
#include <memory>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "adapter_manager.h"
#include "binding_signature_message.h"
#include "companion_device_auth_ffi.h"
#include "companion_device_auth_ffi_types.h"
#include "mock_guard.h"
#include "mock_user_key_manager.h"
#include "security_agent_impl.h"
#include "security_command_adapter.h"
#include "singleton_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {

// Mock implementation of ISecurityCommandAdapter that allows controlling InvokeCommand behavior.
class MockSecurityCommandAdapter : public ISecurityCommandAdapter {
public:
    MOCK_METHOD(ResultCode, InvokeCommand,
        (int32_t commandId, const uint8_t *inputData, uint32_t inputDataLen, uint8_t *outputData,
            uint32_t outputDataLen),
        (override));
};

class SecurityAgentImplTest : public testing::Test {
public:
    void SetUp() override
    {
        guard_ = std::make_unique<MockGuard>();
        mockCmdAdapter_ = std::make_shared<MockSecurityCommandAdapter>();
        AdapterManager::GetInstance().SetSecurityCommandAdapter(mockCmdAdapter_);
        // SecurityAgentImpl::Create issues SET_ACTIVE_USER_ID through this adapter. A catch-all
        // EXPECT_CALL absorbs it; per-test expectations are declared later and match first.
        EXPECT_CALL(*mockCmdAdapter_, InvokeCommand(_, _, _, _, _)).WillRepeatedly(Return(ResultCode::SUCCESS));
    }

    void TearDown() override
    {
        AdapterManager::GetInstance().SetSecurityCommandAdapter(nullptr);
        guard_.reset();
    }

protected:
    std::unique_ptr<MockGuard> guard_;
    std::shared_ptr<MockSecurityCommandAdapter> mockCmdAdapter_;
};

// ============== HostBeginCompanionCheck Salt Length Validation ==============

HWTEST_F(SecurityAgentImplTest, HostBeginCompanionCheck_ReturnsGeneralError_WhenSaltLenExceedsMax, TestSize.Level0)
{
    constexpr uint64_t testChallenge = 12345;
    constexpr int32_t testRequestId = 1;
    constexpr int32_t testUserId = 100;
    // Setup: InvokeCommand for HOST_BEGIN_COMPANION_CHECK writes a salt.len exceeding MAX_DATA_LEN_32
    EXPECT_CALL(*mockCmdAdapter_, InvokeCommand(_, _, _, _, _))
        .WillRepeatedly(Invoke(
            [testChallenge](int32_t commandId, const uint8_t *, uint32_t, uint8_t *outputData, uint32_t outputDataLen) {
                // Only handle HOST_BEGIN_COMPANION_CHECK, let ON_CALL handle other commands
                if (commandId == CommandId::HOST_BEGIN_COMPANION_CHECK) {
                    EXPECT_GE(outputDataLen, sizeof(HostBeginCompanionCheckOutputFfi));
                    auto *ffiOutput = reinterpret_cast<HostBeginCompanionCheckOutputFfi *>(outputData);
                    ffiOutput->challenge = testChallenge;
                    ffiOutput->salt.len = MAX_DATA_LEN_32 + 1; // Exceed the upper bound
                }
                return ResultCode::SUCCESS;
            }));

    auto agent = SecurityAgentImpl::Create();
    ASSERT_NE(agent, nullptr);

    HostBeginCompanionCheckInput input {};
    input.requestId = testRequestId;
    input.userId = testUserId;
    HostBeginCompanionCheckOutput output {};

    ResultCode result = agent->HostBeginCompanionCheck(input, output);
    EXPECT_EQ(result, ResultCode::GENERAL_ERROR);
}

// ============== CompanionGenerateBindingSignatureChallenge ==============

// The challenge is generated inside the TA pool; the SA only round-trips it through the FFI output.
HWTEST_F(SecurityAgentImplTest, CompanionGenerateBindingSignatureChallenge_ReturnsChallengeFromTa, TestSize.Level0)
{
    EXPECT_CALL(*mockCmdAdapter_, InvokeCommand(CommandId::COMPANION_GENERATE_BINDING_SIGNATURE_CHALLENGE, _, _, _, _))
        .WillOnce(Invoke([](int32_t /*commandId*/, const uint8_t *inputData, uint32_t inputLen, uint8_t *outputData,
                             uint32_t) -> ResultCode {
            EXPECT_EQ(inputLen, sizeof(CompanionGenerateBindingSignatureChallengeInputFfi));
            EXPECT_NE(inputData, nullptr);

            auto *ffiOutput = reinterpret_cast<CompanionGenerateBindingSignatureChallengeOutputFfi *>(outputData);
            for (uint32_t i = 0; i < BINDING_SIGNATURE_CHALLENGE_LEN; ++i) {
                ffiOutput->challenge.data[i] = static_cast<uint8_t>(i);
            }
            ffiOutput->challenge.len = BINDING_SIGNATURE_CHALLENGE_LEN;
            return ResultCode::SUCCESS;
        }));

    auto agent = SecurityAgentImpl::Create();
    ASSERT_NE(agent, nullptr);

    CompanionGenerateBindingSignatureChallengeOutput output {};
    EXPECT_EQ(agent->CompanionGenerateBindingSignatureChallenge(output), ResultCode::SUCCESS);
    ASSERT_EQ(output.challenge.size(), BINDING_SIGNATURE_CHALLENGE_LEN);
    for (uint32_t i = 0; i < BINDING_SIGNATURE_CHALLENGE_LEN; ++i) {
        EXPECT_EQ(output.challenge[i], static_cast<uint8_t>(i));
    }
}

// A TA-side failure is propagated to the caller without touching the output.
HWTEST_F(SecurityAgentImplTest, CompanionGenerateBindingSignatureChallenge_PropagatesInvokeFailure, TestSize.Level0)
{
    EXPECT_CALL(*mockCmdAdapter_, InvokeCommand(CommandId::COMPANION_GENERATE_BINDING_SIGNATURE_CHALLENGE, _, _, _, _))
        .WillOnce(Return(ResultCode::GENERAL_ERROR));

    auto agent = SecurityAgentImpl::Create();
    ASSERT_NE(agent, nullptr);

    CompanionGenerateBindingSignatureChallengeOutput output {};
    EXPECT_EQ(agent->CompanionGenerateBindingSignatureChallenge(output), ResultCode::GENERAL_ERROR);
    EXPECT_TRUE(output.challenge.empty());
}

// ============== CompanionPurgeBindingSignatureChallenge ==============

// The disconnect cleanup passes the issued challenge back to the TA pool as the pool key.
HWTEST_F(SecurityAgentImplTest, CompanionPurgeBindingSignatureChallenge_EncodesChallengeToFfi, TestSize.Level0)
{
    const std::vector<uint8_t> challenge(BINDING_SIGNATURE_CHALLENGE_LEN, 0xAB);
    std::vector<uint8_t> capturedChallenge;
    EXPECT_CALL(*mockCmdAdapter_, InvokeCommand(CommandId::COMPANION_PURGE_BINDING_SIGNATURE_CHALLENGE, _, _, _, _))
        .WillOnce(Invoke([&challenge, &capturedChallenge](int32_t /*commandId*/, const uint8_t *inputData,
                             uint32_t inputLen, uint8_t *, uint32_t) -> ResultCode {
            EXPECT_EQ(inputLen, sizeof(CompanionPurgeBindingSignatureChallengeInputFfi));
            auto *ffiInput = reinterpret_cast<const CompanionPurgeBindingSignatureChallengeInputFfi *>(inputData);
            capturedChallenge.assign(ffiInput->challenge.data, ffiInput->challenge.data + ffiInput->challenge.len);
            return ResultCode::SUCCESS;
        }));

    auto agent = SecurityAgentImpl::Create();
    ASSERT_NE(agent, nullptr);

    EXPECT_EQ(agent->CompanionPurgeBindingSignatureChallenge(challenge), ResultCode::SUCCESS);
    EXPECT_EQ(capturedChallenge, challenge);
}

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
