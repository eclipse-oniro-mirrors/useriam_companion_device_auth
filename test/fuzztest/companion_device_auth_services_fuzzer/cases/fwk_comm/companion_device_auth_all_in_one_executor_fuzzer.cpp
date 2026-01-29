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
#include <memory>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"

#include "companion_device_auth_all_in_one_executor.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "fwk_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// Mock callback for testing
class MockExecuteCallback : public FwkIExecuteCallback {
public:
    void OnResult(FwkResultCode result, const std::vector<uint8_t> &extraInfo) override
    {
        (void)result;
        (void)extraInfo;
    }

    // Also implement the base interface version
    void OnResult(ResultCode result) override
    {
        (void)result;
    }

    void OnAcquireInfo(int32_t acquire, const std::vector<uint8_t> &extraInfo) override
    {
        (void)acquire;
        (void)extraInfo;
    }

    void OnMessage(int destRole, const std::vector<uint8_t> &msg) override
    {
        (void)destRole;
        (void)msg;
    }
};

using CompanionDeviceAuthAllInOneExecutorFuzzFunction = void (*)(
    std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &exec, FuzzedDataProvider &);

static void FuzzOp0(std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &exec, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test GetExecutorInfo
    FwkExecutorInfo info;
    (void)exec->GetExecutorInfo(info);
}

static void FuzzOp1(std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &exec, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test OnRegisterFinish
    uint8_t templateCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 5);
    std::vector<uint64_t> templateIdList;
    for (uint8_t j = 0; j < templateCount; ++j) {
        templateIdList.push_back(fuzzData.ConsumeIntegral<uint64_t>());
    }
    uint32_t pubKeySize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_KEY_LENGTH);
    std::vector<uint8_t> frameworkPublicKey = fuzzData.ConsumeBytes<uint8_t>(pubKeySize);
    uint32_t extraInfoSize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> extraInfo = fuzzData.ConsumeBytes<uint8_t>(extraInfoSize);
    (void)exec->OnRegisterFinish(templateIdList, frameworkPublicKey, extraInfo);
}

static void FuzzOp2(std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &exec, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test SendMessage
    uint64_t scheduleId = fuzzData.ConsumeIntegral<uint64_t>();
    int32_t srcRole = fuzzData.ConsumeIntegral<int32_t>();
    uint32_t msgSize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> msg = fuzzData.ConsumeBytes<uint8_t>(msgSize);
    (void)exec->SendMessage(scheduleId, srcRole, msg);
}

static void FuzzOp3(std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &exec, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test Enroll
    uint64_t scheduleId = fuzzData.ConsumeIntegral<uint64_t>();
    FwkEnrollParam param;
    param.userId = fuzzData.ConsumeIntegral<int32_t>();
    param.tokenId = fuzzData.ConsumeIntegral<uint64_t>();
    auto callback = std::make_shared<MockExecuteCallback>();
    (void)exec->Enroll(scheduleId, param, callback);
}

static void FuzzOp4(std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &exec, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test Authenticate
    uint64_t scheduleId = fuzzData.ConsumeIntegral<uint64_t>();
    FwkAuthenticateParam param;
    param.userId = fuzzData.ConsumeIntegral<int32_t>();
    param.tokenId = fuzzData.ConsumeIntegral<uint64_t>();
    uint8_t templateCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 5);
    for (uint8_t j = 0; j < templateCount; ++j) {
        param.templateIdList.push_back(fuzzData.ConsumeIntegral<uint64_t>());
    }
    auto callback = std::make_shared<MockExecuteCallback>();
    (void)exec->Authenticate(scheduleId, param, callback);
}

static void FuzzOp5(std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &exec, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test Delete
    uint8_t templateCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 5);
    std::vector<uint64_t> templateIdList;
    for (uint8_t j = 0; j < templateCount; ++j) {
        templateIdList.push_back(fuzzData.ConsumeIntegral<uint64_t>());
    }
    (void)exec->Delete(templateIdList);
}

static void FuzzOp6(std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &exec, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test Cancel
    uint64_t scheduleId = fuzzData.ConsumeIntegral<uint64_t>();
    (void)exec->Cancel(scheduleId);
}

static void FuzzOp7(std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &exec, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test SendCommand
    FwkPropertyMode commandId = static_cast<FwkPropertyMode>(fuzzData.ConsumeIntegral<int32_t>());
    uint32_t extraInfoSize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> extraInfo = fuzzData.ConsumeBytes<uint8_t>(extraInfoSize);
    auto callback = std::make_shared<MockExecuteCallback>();
    (void)exec->SendCommand(commandId, extraInfo, callback);
}

static void FuzzOp8(std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &exec, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test GetProperty
    uint8_t templateCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 5);
    std::vector<uint64_t> templateIdList;
    for (uint8_t j = 0; j < templateCount; ++j) {
        templateIdList.push_back(fuzzData.ConsumeIntegral<uint64_t>());
    }
    uint8_t keyCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 5);
    std::vector<FwkAttributeKey> keys;
    for (uint8_t j = 0; j < keyCount; ++j) {
        keys.push_back(static_cast<FwkAttributeKey>(fuzzData.ConsumeIntegral<uint32_t>()));
    }
    FwkProperty property;
    (void)exec->GetProperty(templateIdList, keys, property);
}

static void FuzzOp9(std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &exec, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    // Test SetCachedTemplates
    uint8_t templateCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 5);
    std::vector<uint64_t> templateIdList;
    for (uint8_t j = 0; j < templateCount; ++j) {
        templateIdList.push_back(fuzzData.ConsumeIntegral<uint64_t>());
    }
    (void)exec->SetCachedTemplates(templateIdList);
}

static const CompanionDeviceAuthAllInOneExecutorFuzzFunction g_fuzzFuncs[] = { FuzzOp0, FuzzOp1, FuzzOp2, FuzzOp3,
    FuzzOp4, FuzzOp5, FuzzOp6, FuzzOp7, FuzzOp8, FuzzOp9 };
constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(CompanionDeviceAuthAllInOneExecutorFuzzFunction);

void FuzzCompanionDeviceAuthAllInOneExecutor(FuzzedDataProvider &fuzzData)
{
    auto exec = CompanionDeviceAuthAllInOneExecutor::Create();
    if (!exec) {
        return;
    }

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);

    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](exec, fuzzData);
    }

    EnsureAllTaskExecuted();
}

} // namespace CompanionDeviceAuth

FUZZ_REGISTER(CompanionDeviceAuthAllInOneExecutor)

} // namespace UserIam
} // namespace OHOS
