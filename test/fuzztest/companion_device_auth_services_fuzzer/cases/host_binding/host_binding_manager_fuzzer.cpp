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
#include "fuzz_registry.h"
#include "host_binding_manager_impl.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using HostBindingManagerFuzzFunction = void (*)(std::shared_ptr<HostBindingManagerImpl> &manager,
    FuzzedDataProvider &fuzzData);

static void FuzzGetHostBindingStatusById(std::shared_ptr<HostBindingManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    BindingId bindingId = fuzzData.ConsumeIntegral<BindingId>();
    auto status = manager->GetHostBindingStatus(bindingId);
    (void)status;
}

static void FuzzGetHostBindingStatusByDeviceUser(std::shared_ptr<HostBindingManagerImpl> &manager,
    FuzzedDataProvider &fuzzData)
{
    UserId companionUserId = fuzzData.ConsumeIntegral<UserId>();
    DeviceKey hostDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    auto status = manager->GetHostBindingStatus(companionUserId, hostDeviceKey);
    (void)status;
}

static void FuzzBeginAddHostBinding(std::shared_ptr<HostBindingManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    BeginAddHostBindingInput input = {};
    input.requestId = fuzzData.ConsumeIntegral<RequestId>();
    input.companionUserId = fuzzData.ConsumeIntegral<UserId>();
    input.secureProtocolId = GenerateFuzzSecureProtocolId(fuzzData);
    input.addHostBindingRequest =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    BeginAddHostBindingOutput output = {};
    auto result = manager->BeginAddHostBinding(input, output);
    (void)result;
    (void)output;
}

static void FuzzEndAddHostBinding(std::shared_ptr<HostBindingManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    EndAddHostBindingInput input = {};
    input.requestId = fuzzData.ConsumeIntegral<RequestId>();
    input.resultCode = GenerateFuzzResultCode(fuzzData);
    input.bindingId = fuzzData.ConsumeIntegral<BindingId>();
    input.tokenData =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    EndAddHostBindingOutput output = {};
    auto result = manager->EndAddHostBinding(input, output);
    (void)result;
    (void)output;
}

static void FuzzRemoveHostBinding(std::shared_ptr<HostBindingManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    UserId companionUserId = fuzzData.ConsumeIntegral<UserId>();
    DeviceKey hostDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    auto result = manager->RemoveHostBinding(companionUserId, hostDeviceKey);
    (void)result;
}

static void FuzzSetHostBindingTokenValid(std::shared_ptr<HostBindingManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    BindingId bindingId = fuzzData.ConsumeIntegral<BindingId>();
    bool isTokenValid = fuzzData.ConsumeBool();
    auto result = manager->SetHostBindingTokenValid(bindingId, isTokenValid);
    (void)result;
}

static void FuzzStartObtainTokenRequests(std::shared_ptr<HostBindingManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    UserId userId = fuzzData.ConsumeIntegral<UserId>();
    uint32_t lockStateAuthTypeValue = fuzzData.ConsumeIntegral<uint32_t>();
    std::vector<uint8_t> fwkUnlockMsg =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    manager->StartObtainTokenRequests(userId, lockStateAuthTypeValue, fwkUnlockMsg);
}

static void FuzzRevokeTokens(std::shared_ptr<HostBindingManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    UserId userId = fuzzData.ConsumeIntegral<UserId>();
    manager->RevokeTokens(userId);
}

static void FuzzGetAllHostBindingStatus(std::shared_ptr<HostBindingManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto allStatus = manager->GetAllHostBindingStatus();
    (void)allStatus;
}

static void FuzzFindBindingById(std::shared_ptr<HostBindingManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    BindingId bindingId = fuzzData.ConsumeIntegral<BindingId>();
    auto binding = manager->FindBindingById(bindingId);
    (void)binding;
}

static void FuzzFindBindingByDeviceUser(std::shared_ptr<HostBindingManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    UserId userId = fuzzData.ConsumeIntegral<UserId>();
    DeviceKey deviceKey = GenerateFuzzDeviceKey(fuzzData);
    auto binding = manager->FindBindingByDeviceUser(userId, deviceKey);
    (void)binding;
}

static void FuzzAddBindingInternal(std::shared_ptr<HostBindingManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    PersistedHostBindingStatus persistedStatus;
    persistedStatus.bindingId = fuzzData.ConsumeIntegral<BindingId>();
    persistedStatus.companionUserId = fuzzData.ConsumeIntegral<UserId>();
    persistedStatus.hostDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    persistedStatus.isTokenValid = fuzzData.ConsumeBool();
    persistedStatus.companionSubProfileId = fuzzData.ConsumeIntegral<int32_t>();
    auto binding = HostBinding::Create(persistedStatus);
    if (binding) {
        (void)manager->AddBindingInternal(binding);
    }
}

static void FuzzRemoveBindingInternal(std::shared_ptr<HostBindingManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    BindingId bindingId = fuzzData.ConsumeIntegral<BindingId>();
    (void)manager->RemoveBindingInternal(bindingId);
}

static const HostBindingManagerFuzzFunction g_fuzzFuncs[] = {
    FuzzGetHostBindingStatusById,
    FuzzGetHostBindingStatusByDeviceUser,
    FuzzBeginAddHostBinding,
    FuzzEndAddHostBinding,
    FuzzRemoveHostBinding,
    FuzzSetHostBindingTokenValid,
    FuzzStartObtainTokenRequests,
    FuzzRevokeTokens,
    FuzzGetAllHostBindingStatus,
    FuzzFindBindingById,
    FuzzFindBindingByDeviceUser,
    FuzzAddBindingInternal,
    FuzzRemoveBindingInternal,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(HostBindingManagerFuzzFunction);

void FuzzHostBindingManager(FuzzedDataProvider &fuzzData)
{
    auto manager = HostBindingManagerImpl::Create();
    if (!manager) {
        return;
    }

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](manager, fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](manager, fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzHostBindingManager)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
