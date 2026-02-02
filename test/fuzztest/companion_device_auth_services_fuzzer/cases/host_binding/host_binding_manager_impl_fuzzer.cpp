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

using HostBindingManagerImplFuzzFunction = void (*)(std::shared_ptr<HostBindingManagerImpl> &manager,
    FuzzedDataProvider &fuzzData);

static void FuzzGetHostBindingStatusById(std::shared_ptr<HostBindingManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    BindingId bindingId = fuzzData.ConsumeIntegral<uint64_t>();
    auto status = manager->GetHostBindingStatus(bindingId);
    (void)status;
}

static void FuzzGetHostBindingStatusByUserDevice(std::shared_ptr<HostBindingManagerImpl> &manager,
    FuzzedDataProvider &fuzzData)
{
    UserId companionUserId = fuzzData.ConsumeIntegral<UserId>();
    DeviceKey hostDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    auto status = manager->GetHostBindingStatus(companionUserId, hostDeviceKey);
    (void)status;
}

static void FuzzBeginAddHostBinding(std::shared_ptr<HostBindingManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    RequestId requestId = fuzzData.ConsumeIntegral<RequestId>();
    UserId companionUserId = fuzzData.ConsumeIntegral<UserId>();
    SecureProtocolId secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint16_t>());
    uint32_t requestSize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    std::vector<uint8_t> addHostBindingRequest = fuzzData.ConsumeBytes<uint8_t>(requestSize);
    std::vector<uint8_t> outAddHostBindingReply;
    ResultCode result = manager->BeginAddHostBinding(requestId, companionUserId, secureProtocolId,
        addHostBindingRequest, outAddHostBindingReply);
    (void)result;
}

static void FuzzEndAddHostBinding(std::shared_ptr<HostBindingManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    RequestId requestId = fuzzData.ConsumeIntegral<RequestId>();
    ResultCode resultCode = GenerateFuzzResultCode(fuzzData);
    uint32_t tokenDataSize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_TOKEN_LENGTH);
    std::vector<uint8_t> tokenData = fuzzData.ConsumeBytes<uint8_t>(tokenDataSize);
    ResultCode result = manager->EndAddHostBinding(requestId, resultCode, tokenData);
    (void)result;
}

static void FuzzRemoveHostBinding(std::shared_ptr<HostBindingManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    UserId companionUserId = fuzzData.ConsumeIntegral<UserId>();
    DeviceKey hostDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    ResultCode result = manager->RemoveHostBinding(companionUserId, hostDeviceKey);
    (void)result;
}

static void FuzzSetHostBindingTokenValid(std::shared_ptr<HostBindingManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    BindingId bindingId = fuzzData.ConsumeIntegral<BindingId>();
    bool isTokenValid = fuzzData.ConsumeBool();
    bool result = manager->SetHostBindingTokenValid(bindingId, isTokenValid);
    (void)result;
}

static void FuzzStartObtainTokenRequests(std::shared_ptr<HostBindingManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    UserId userId = fuzzData.ConsumeIntegral<UserId>();
    uint32_t msgSize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_FWK_MESSAGE_LENGTH);
    std::vector<uint8_t> fwkUnlockMsg = fuzzData.ConsumeBytes<uint8_t>(msgSize);
    manager->StartObtainTokenRequests(userId, fwkUnlockMsg);
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

static void FuzzInitialize(std::shared_ptr<HostBindingManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    manager->Initialize();
}

static void FuzzOnActiveUserIdChanged(std::shared_ptr<HostBindingManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    UserId userId = fuzzData.ConsumeIntegral<UserId>();
    manager->OnActiveUserIdChanged(userId);
}

static void FuzzCreate(std::shared_ptr<HostBindingManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    (void)manager;
    auto newMgr = HostBindingManagerImpl::Create();
    (void)newMgr;
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
    PersistedHostBindingStatus persistedStatus = GenerateFuzzPersistedHostBindingStatus(fuzzData);
    auto binding = HostBinding::Create(persistedStatus);
    if (binding) {
        manager->AddBindingInternal(binding);
    }
}

static void FuzzRemoveBindingInternal(std::shared_ptr<HostBindingManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    BindingId bindingId = fuzzData.ConsumeIntegral<BindingId>();
    manager->RemoveBindingInternal(bindingId);
}

static const HostBindingManagerImplFuzzFunction g_fuzzFuncs[] = {
    FuzzGetHostBindingStatusById,
    FuzzGetHostBindingStatusByUserDevice,
    FuzzBeginAddHostBinding,
    FuzzEndAddHostBinding,
    FuzzRemoveHostBinding,
    FuzzSetHostBindingTokenValid,
    FuzzStartObtainTokenRequests,
    FuzzRevokeTokens,
    FuzzGetAllHostBindingStatus,
    FuzzInitialize,
    FuzzOnActiveUserIdChanged,
    FuzzCreate,
    FuzzFindBindingById,
    FuzzFindBindingByDeviceUser,
    FuzzAddBindingInternal,
    FuzzRemoveBindingInternal,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(HostBindingManagerImplFuzzFunction);

void FuzzHostBindingManagerImpl(FuzzedDataProvider &fuzzData)
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

    EnsureAllTaskExecuted();
}

FUZZ_REGISTER(FuzzHostBindingManagerImpl)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
