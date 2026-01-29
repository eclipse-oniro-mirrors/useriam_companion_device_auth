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

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using AllInOneExecutorFuzzFunction = void (*)(std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &executor,
    FuzzedDataProvider &fuzzData);

static void FuzzGetExecutorInfo(std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &executor,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    FwkExecutorInfo info;
    (void)executor->GetExecutorInfo(info);
}

static void FuzzOnRegisterFinish(std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &executor,
    FuzzedDataProvider &fuzzData)
{
    std::vector<uint64_t> templateIdList;
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_CAPABILITIES_COUNT);
    for (uint8_t i = 0; i < count; ++i) {
        templateIdList.push_back(fuzzData.ConsumeIntegral<uint64_t>());
    }

    std::vector<uint8_t> frameworkPublicKey =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    std::vector<uint8_t> extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    (void)executor->OnRegisterFinish(templateIdList, frameworkPublicKey, extraInfo);
}

static void FuzzSendMessage(std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &executor,
    FuzzedDataProvider &fuzzData)
{
    uint64_t scheduleId = fuzzData.ConsumeIntegral<uint64_t>();
    int32_t srcRole = fuzzData.ConsumeIntegral<int32_t>();
    std::vector<uint8_t> msg =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    (void)executor->SendMessage(scheduleId, srcRole, msg);
}

static void FuzzEnroll(std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &executor, FuzzedDataProvider &fuzzData)
{
    uint64_t scheduleId = fuzzData.ConsumeIntegral<uint64_t>();
    FwkEnrollParam param;
    param.tokenId = fuzzData.ConsumeIntegral<uint32_t>();
    param.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    param.userId = fuzzData.ConsumeIntegral<int32_t>();

    class FakeCallback : public FwkIExecuteCallback {
    public:
        void OnResult(FwkResultCode result, const std::vector<uint8_t> &extraInfo) override
        {
            (void)result;
            (void)extraInfo;
        }
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
    auto callback = std::make_shared<FakeCallback>();
    (void)executor->Enroll(scheduleId, param, callback);
}

static void FuzzAuthenticate(std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &executor,
    FuzzedDataProvider &fuzzData)
{
    uint64_t scheduleId = fuzzData.ConsumeIntegral<uint64_t>();
    FwkAuthenticateParam param;
    param.tokenId = fuzzData.ConsumeIntegral<uint32_t>();
    param.extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    param.endAfterFirstFail = fuzzData.ConsumeBool();
    param.authIntent = fuzzData.ConsumeIntegral<int32_t>();
    param.userId = fuzzData.ConsumeIntegral<int32_t>();

    uint8_t templateCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_CAPABILITIES_COUNT);
    for (uint8_t i = 0; i < templateCount; ++i) {
        param.templateIdList.push_back(fuzzData.ConsumeIntegral<uint64_t>());
    }

    class FakeCallback : public FwkIExecuteCallback {
    public:
        void OnResult(FwkResultCode result, const std::vector<uint8_t> &extraInfo) override
        {
            (void)result;
            (void)extraInfo;
        }
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
    auto callback = std::make_shared<FakeCallback>();
    (void)executor->Authenticate(scheduleId, param, callback);
}

static void FuzzDelete(std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &executor, FuzzedDataProvider &fuzzData)
{
    std::vector<uint64_t> templateIdList;
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_CAPABILITIES_COUNT);
    for (uint8_t i = 0; i < count; ++i) {
        templateIdList.push_back(fuzzData.ConsumeIntegral<uint64_t>());
    }
    (void)executor->Delete(templateIdList);
}

static void FuzzCancel(std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &executor, FuzzedDataProvider &fuzzData)
{
    uint64_t scheduleId = fuzzData.ConsumeIntegral<uint64_t>();
    (void)executor->Cancel(scheduleId);
}

static void FuzzSendCommand(std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &executor,
    FuzzedDataProvider &fuzzData)
{
    FwkPropertyMode commandId = static_cast<FwkPropertyMode>(fuzzData.ConsumeIntegral<uint32_t>());
    std::vector<uint8_t> extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));

    class FakeCallback : public FwkIExecuteCallback {
    public:
        void OnResult(FwkResultCode result, const std::vector<uint8_t> &extraInfo) override
        {
            (void)result;
            (void)extraInfo;
        }
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
    auto callback = std::make_shared<FakeCallback>();
    (void)executor->SendCommand(commandId, extraInfo, callback);
}

static void FuzzGetProperty(std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &executor,
    FuzzedDataProvider &fuzzData)
{
    std::vector<uint64_t> templateIdList;
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_CAPABILITIES_COUNT);
    for (uint8_t i = 0; i < count; ++i) {
        templateIdList.push_back(fuzzData.ConsumeIntegral<uint64_t>());
    }

    std::vector<FwkAttributeKey> keys;
    uint8_t keyCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 5);
    for (uint8_t i = 0; i < keyCount; ++i) {
        keys.push_back(static_cast<FwkAttributeKey>(fuzzData.ConsumeIntegral<uint32_t>()));
    }

    FwkProperty property;
    (void)executor->GetProperty(templateIdList, keys, property);
}

static void FuzzSetCachedTemplates(std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &executor,
    FuzzedDataProvider &fuzzData)
{
    std::vector<uint64_t> templateIdList;
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_CAPABILITIES_COUNT);
    for (uint8_t i = 0; i < count; ++i) {
        templateIdList.push_back(fuzzData.ConsumeIntegral<uint64_t>());
    }
    (void)executor->SetCachedTemplates(templateIdList);
}

static void FuzzHandleFreezeRelatedCommand(std::shared_ptr<CompanionDeviceAuthAllInOneExecutor> &executor,
    FuzzedDataProvider &fuzzData)
{
    FwkPropertyMode commandId = static_cast<FwkPropertyMode>(fuzzData.ConsumeIntegral<uint32_t>());
    std::vector<uint8_t> extraInfo =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));

    class FakeCallback : public FwkIExecuteCallback {
    public:
        void OnResult(FwkResultCode result, const std::vector<uint8_t> &extraInfo) override
        {
            (void)result;
            (void)extraInfo;
        }
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
    auto callback = std::make_shared<FakeCallback>();
    (void)executor->SendCommand(commandId, extraInfo, callback);
}

static const AllInOneExecutorFuzzFunction g_fuzzFuncs[] = {
    FuzzGetExecutorInfo,
    FuzzOnRegisterFinish,
    FuzzSendMessage,
    FuzzEnroll,
    FuzzAuthenticate,
    FuzzDelete,
    FuzzCancel,
    FuzzSendCommand,
    FuzzGetProperty,
    FuzzSetCachedTemplates,
    FuzzHandleFreezeRelatedCommand,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(AllInOneExecutorFuzzFunction);

void FuzzAllInOneExecutor(FuzzedDataProvider &fuzzData)
{
    auto executor = CompanionDeviceAuthAllInOneExecutor::Create();
    if (!executor) {
        return;
    }

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](executor, fuzzData);
        EnsureAllTaskExecuted();
    }
}

} // namespace CompanionDeviceAuth

FUZZ_REGISTER(AllInOneExecutor)

} // namespace UserIam
} // namespace OHOS
