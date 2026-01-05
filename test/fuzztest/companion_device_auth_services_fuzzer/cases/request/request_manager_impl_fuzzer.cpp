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

#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "request_factory_impl.h"
#include "request_manager_impl.h"
#include "service_fuzz_entry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using FuzzFunction = void (*)(std::shared_ptr<RequestManagerImpl> &mgr, std::shared_ptr<RequestFactoryImpl> &factory,
    FuzzedDataProvider &fuzzData);

static void FuzzStartHostTokenAuth(std::shared_ptr<RequestManagerImpl> &mgr,
    std::shared_ptr<RequestFactoryImpl> &factory, FuzzedDataProvider &fuzzData)
{
    ScheduleId scheduleId = fuzzData.ConsumeIntegral<ScheduleId>();
    std::vector<uint8_t> fwkMsg =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    UserId hostUserId = fuzzData.ConsumeIntegral<UserId>();
    TemplateId templateId = fuzzData.ConsumeIntegral<TemplateId>();
    FwkResultCallback callback = [](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        (void)result;
        (void)extraInfo;
    };
    auto request = factory->CreateHostTokenAuthRequest(scheduleId, fwkMsg, hostUserId, templateId, std::move(callback));
    if (request) {
        mgr->Start(request);
    }
}

static void FuzzStartHostAddCompanion(std::shared_ptr<RequestManagerImpl> &mgr,
    std::shared_ptr<RequestFactoryImpl> &factory, FuzzedDataProvider &fuzzData)
{
    ScheduleId scheduleId = fuzzData.ConsumeIntegral<ScheduleId>();
    std::vector<uint8_t> fwkMsg =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();
    FwkResultCallback callback = [](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        (void)result;
        (void)extraInfo;
    };
    auto request = factory->CreateHostAddCompanionRequest(scheduleId, fwkMsg, tokenId, std::move(callback));
    if (request) {
        mgr->Start(request);
    }
}

static void FuzzStartHostDelegateAuth(std::shared_ptr<RequestManagerImpl> &mgr,
    std::shared_ptr<RequestFactoryImpl> &factory, FuzzedDataProvider &fuzzData)
{
    ScheduleId scheduleId = fuzzData.ConsumeIntegral<ScheduleId>();
    std::vector<uint8_t> fwkMsg =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    UserId hostUserId = fuzzData.ConsumeIntegral<UserId>();
    TemplateId templateId = fuzzData.ConsumeIntegral<TemplateId>();
    FwkResultCallback callback = [](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        (void)result;
        (void)extraInfo;
    };
    auto request =
        factory->CreateHostDelegateAuthRequest(scheduleId, fwkMsg, hostUserId, templateId, std::move(callback));
    if (request) {
        mgr->Start(request);
    }
}

static void FuzzCancel(std::shared_ptr<RequestManagerImpl> &mgr, std::shared_ptr<RequestFactoryImpl> &factory,
    FuzzedDataProvider &fuzzData)
{
    (void)factory;
    RequestId requestId = fuzzData.ConsumeIntegral<RequestId>();
    bool result = mgr->Cancel(requestId);
    (void)result;
}

static void FuzzCancelRequestByScheduleId(std::shared_ptr<RequestManagerImpl> &mgr,
    std::shared_ptr<RequestFactoryImpl> &factory, FuzzedDataProvider &fuzzData)
{
    (void)factory;
    ScheduleId scheduleId = fuzzData.ConsumeIntegral<ScheduleId>();
    bool result = mgr->CancelRequestByScheduleId(scheduleId);
    (void)result;
}

static void FuzzCancelAll(std::shared_ptr<RequestManagerImpl> &mgr, std::shared_ptr<RequestFactoryImpl> &factory,
    FuzzedDataProvider &fuzzData)
{
    (void)factory;
    (void)fuzzData;
    mgr->CancelAll();
}

static void FuzzGet(std::shared_ptr<RequestManagerImpl> &mgr, std::shared_ptr<RequestFactoryImpl> &factory,
    FuzzedDataProvider &fuzzData)
{
    (void)factory;
    RequestId requestId = fuzzData.ConsumeIntegral<RequestId>();
    auto request = mgr->Get(requestId);
    (void)request;
}

static void FuzzRemove(std::shared_ptr<RequestManagerImpl> &mgr, std::shared_ptr<RequestFactoryImpl> &factory,
    FuzzedDataProvider &fuzzData)
{
    (void)factory;
    RequestId requestId = fuzzData.ConsumeIntegral<RequestId>();
    mgr->Remove(requestId);
}

static const FuzzFunction g_fuzzFuncs[] = {
    FuzzStartHostTokenAuth,
    FuzzStartHostAddCompanion,
    FuzzStartHostDelegateAuth,
    FuzzCancel,
    FuzzCancelRequestByScheduleId,
    FuzzCancelAll,
    FuzzGet,
    FuzzRemove,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(FuzzFunction);

void FuzzRequestManagerImpl(FuzzedDataProvider &fuzzData)
{
    auto mgr = RequestManagerImpl::Create();
    if (!mgr) {
        return;
    }

    auto factory = RequestFactoryImpl::Create();
    if (!factory) {
        return;
    }

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);

    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](mgr, factory, fuzzData);
        EnsureAllTaskExecuted();
    }

    EnsureAllTaskExecuted();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
