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
#include "companion_device_auth_ffi.h"
#include "companion_device_auth_ffi_types.h"
#include "mock_guard.h"
#include "mock_user_id_manager.h"
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
    // Setup default behavior for InvokeCommand to handle SET_ACTIVE_USER_ID during initialization
    ON_CALL(*mockCmdAdapter_, InvokeCommand(_, _, _, _, _)).WillByDefault(Return(ResultCode::SUCCESS));

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

} // namespace
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
