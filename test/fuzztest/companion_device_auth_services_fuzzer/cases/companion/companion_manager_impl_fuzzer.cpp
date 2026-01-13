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

#include "companion_manager_impl.h"
#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using CompanionManagerImplFuzzFunction = void (*)(std::shared_ptr<CompanionManagerImpl> &manager,
    FuzzedDataProvider &fuzzData);

static void FuzzReload(std::shared_ptr<CompanionManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_BUSINESS_IDS_COUNT);
    std::vector<PersistedCompanionStatus> companionList;
    for (uint8_t i = 0; i < count; ++i) {
        PersistedCompanionStatus status;
        status.templateId = fuzzData.ConsumeIntegral<TemplateId>();
        status.hostUserId = fuzzData.ConsumeIntegral<UserId>();
        status.companionDeviceKey = GenerateFuzzDeviceKey(fuzzData);
        status.isValid = fuzzData.ConsumeBool();
        companionList.push_back(status);
    }
    manager->Reload(companionList);
}

static void FuzzGetCompanionStatusByTemplate(std::shared_ptr<CompanionManagerImpl> &manager,
    FuzzedDataProvider &fuzzData)
{
    TemplateId templateId = fuzzData.ConsumeIntegral<TemplateId>();
    auto status = manager->GetCompanionStatus(templateId);
    (void)status;
}

static void FuzzGetCompanionStatusByUserAndDevice(std::shared_ptr<CompanionManagerImpl> &manager,
    FuzzedDataProvider &fuzzData)
{
    UserId hostUserId = fuzzData.ConsumeIntegral<UserId>();
    DeviceKey companionDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    auto status = manager->GetCompanionStatus(hostUserId, companionDeviceKey);
    (void)status;
}

static void FuzzGetAllCompanionStatus(std::shared_ptr<CompanionManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto allStatus = manager->GetAllCompanionStatus();
    (void)allStatus;
}

static void FuzzSubscribeCompanionDeviceStatusChange(std::shared_ptr<CompanionManagerImpl> &manager,
    FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    OnCompanionDeviceStatusChange callback = [](const std::vector<CompanionStatus> &statusList) { (void)statusList; };
    auto subscription = manager->SubscribeCompanionDeviceStatusChange(std::move(callback));
    (void)subscription;
}

static void FuzzUpdateCompanionStatus(std::shared_ptr<CompanionManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    TemplateId templateId = fuzzData.ConsumeIntegral<TemplateId>();
    std::string deviceName = GenerateFuzzString(fuzzData, 64);
    std::string deviceUserName = GenerateFuzzString(fuzzData, 64);
    ResultCode result = manager->UpdateCompanionStatus(templateId, deviceName, deviceUserName);
    (void)result;
}

static void FuzzUpdateCompanionEnabledBusinessIds(std::shared_ptr<CompanionManagerImpl> &manager,
    FuzzedDataProvider &fuzzData)
{
    TemplateId templateId = fuzzData.ConsumeIntegral<TemplateId>();
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_BUSINESS_IDS_COUNT);
    std::vector<BusinessId> businessIds;
    for (uint8_t j = 0; j < count; ++j) {
        businessIds.push_back(static_cast<BusinessId>(fuzzData.ConsumeIntegral<int32_t>()));
    }
    ResultCode result = manager->UpdateCompanionEnabledBusinessIds(templateId, businessIds);
    (void)result;
}

static void FuzzSetCompanionTokenAtl(std::shared_ptr<CompanionManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    TemplateId templateId = fuzzData.ConsumeIntegral<TemplateId>();
    if (fuzzData.ConsumeBool()) {
        Atl atl = fuzzData.ConsumeIntegral<Atl>();
        bool result = manager->SetCompanionTokenAtl(templateId, atl);
        (void)result;
    } else {
        bool result = manager->SetCompanionTokenAtl(templateId, std::nullopt);
        (void)result;
    }
}

static void FuzzHandleCompanionCheckFail(std::shared_ptr<CompanionManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    TemplateId templateId = fuzzData.ConsumeIntegral<TemplateId>();
    ResultCode result = manager->HandleCompanionCheckFail(templateId);
    (void)result;
}

static void FuzzStartIssueTokenRequests(std::shared_ptr<CompanionManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_DEVICE_STATUS_COUNT);
    std::vector<TemplateId> templateIds;
    for (uint8_t j = 0; j < count; ++j) {
        templateIds.push_back(fuzzData.ConsumeIntegral<TemplateId>());
    }
    uint32_t msgSize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_FWK_MESSAGE_LENGTH);
    std::vector<uint8_t> fwkMsg = fuzzData.ConsumeBytes<uint8_t>(msgSize);
    manager->StartIssueTokenRequests(templateIds, fwkMsg);
}

static void FuzzRevokeTokens(std::shared_ptr<CompanionManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_DEVICE_STATUS_COUNT);
    std::vector<TemplateId> templateIds;
    for (uint8_t j = 0; j < count; ++j) {
        templateIds.push_back(fuzzData.ConsumeIntegral<TemplateId>());
    }
    manager->RevokeTokens(templateIds);
}

static void FuzzFindCompanionByTemplateId(std::shared_ptr<CompanionManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    TemplateId templateId = fuzzData.ConsumeIntegral<TemplateId>();
    auto companion = manager->FindCompanionByTemplateId(templateId);
    (void)companion;
}

static void FuzzFindCompanionByDeviceUser(std::shared_ptr<CompanionManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    UserId userId = fuzzData.ConsumeIntegral<UserId>();
    DeviceKey deviceKey = GenerateFuzzDeviceKey(fuzzData);
    auto companion = manager->FindCompanionByDeviceUser(userId, deviceKey);
    (void)companion;
}

static void FuzzBeginAddCompanion(std::shared_ptr<CompanionManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    BeginAddCompanionParams params;
    params.requestId = fuzzData.ConsumeIntegral<RequestId>();
    params.scheduleId = fuzzData.ConsumeIntegral<ScheduleId>();
    params.hostDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    params.companionDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    uint32_t fwkMsgSize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_FWK_MESSAGE_LENGTH);
    params.fwkMsg = fuzzData.ConsumeBytes<uint8_t>(fwkMsgSize);
    params.secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint8_t>());
    uint32_t replySize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    params.initKeyNegotiationReply = fuzzData.ConsumeBytes<uint8_t>(replySize);
    std::vector<uint8_t> outAddHostBindingRequest;
    manager->BeginAddCompanion(params, outAddHostBindingRequest);
}

static void FuzzEndAddCompanion(std::shared_ptr<CompanionManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    EndAddCompanionInput input;
    input.requestId = fuzzData.ConsumeIntegral<RequestId>();
    input.companionStatus.templateId = fuzzData.ConsumeIntegral<TemplateId>();
    input.companionStatus.hostUserId = fuzzData.ConsumeIntegral<UserId>();
    input.companionStatus.companionDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    input.companionStatus.isValid = fuzzData.ConsumeBool();
    input.secureProtocolId = static_cast<SecureProtocolId>(fuzzData.ConsumeIntegral<uint8_t>());
    uint32_t replySize = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_MESSAGE_LENGTH);
    input.addHostBindingReply = fuzzData.ConsumeBytes<uint8_t>(replySize);
    EndAddCompanionOutput output;
    manager->EndAddCompanion(input, output);
}

static void FuzzRemoveCompanion(std::shared_ptr<CompanionManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    TemplateId templateId = fuzzData.ConsumeIntegral<TemplateId>();
    manager->RemoveCompanion(templateId);
}

static void FuzzOnActiveUserIdChanged(std::shared_ptr<CompanionManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    UserId userId = fuzzData.ConsumeIntegral<UserId>();
    manager->OnActiveUserIdChanged(userId);
}

static void FuzzInitialize(std::shared_ptr<CompanionManagerImpl> &manager, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    manager->Initialize();
}

static const CompanionManagerImplFuzzFunction g_fuzzFuncs[] = {
    FuzzReload,
    FuzzGetCompanionStatusByTemplate,
    FuzzGetCompanionStatusByUserAndDevice,
    FuzzGetAllCompanionStatus,
    FuzzSubscribeCompanionDeviceStatusChange,
    FuzzUpdateCompanionStatus,
    FuzzUpdateCompanionEnabledBusinessIds,
    FuzzSetCompanionTokenAtl,
    FuzzHandleCompanionCheckFail,
    FuzzStartIssueTokenRequests,
    FuzzRevokeTokens,
    FuzzFindCompanionByTemplateId,
    FuzzFindCompanionByDeviceUser,
    FuzzBeginAddCompanion,
    FuzzEndAddCompanion,
    FuzzRemoveCompanion,
    FuzzOnActiveUserIdChanged,
    FuzzInitialize,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(CompanionManagerImplFuzzFunction);

void FuzzCompanionManagerImpl(FuzzedDataProvider &fuzzData)
{
    auto manager = std::make_shared<CompanionManagerImpl>();
    if (!manager) {
        return;
    }

    uint32_t loopCount = fuzzData.ConsumeIntegralInRange<uint32_t>(0, FUZZ_MAX_LOOP_COUNT);
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }
        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](manager, fuzzData);
        EnsureAllTaskExecuted();
    }
}

} // namespace CompanionDeviceAuth

FUZZ_REGISTER(CompanionManagerImpl)

} // namespace UserIam
} // namespace OHOS
