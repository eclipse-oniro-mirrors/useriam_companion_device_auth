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
#include "request_factory_impl.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
constexpr uint32_t SIZE_64 = 64;
}

using RequestFactoryImplFuzzFunction = void (*)(std::shared_ptr<RequestFactoryImpl> &factory,
    FuzzedDataProvider &fuzzData);

static void FuzzCreateHostAddCompanionRequest(std::shared_ptr<RequestFactoryImpl> &factory,
    FuzzedDataProvider &fuzzData)
{
    ScheduleId scheduleId = fuzzData.ConsumeIntegral<ScheduleId>();
    std::vector<uint8_t> fwkMsg =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();
    std::string additionalInfo = fuzzData.ConsumeRandomLengthString(FUZZ_MAX_MESSAGE_LENGTH);
    FwkResultCallback callback = [](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        (void)result;
        (void)extraInfo;
    };
    auto request =
        factory->CreateHostAddCompanionRequest(scheduleId, fwkMsg, tokenId, additionalInfo, std::move(callback));
    (void)request;
}

static void FuzzCreateHostTokenAuthRequest(std::shared_ptr<RequestFactoryImpl> &factory, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    ScheduleId scheduleId = fuzzData.ConsumeIntegral<ScheduleId>();
    std::vector<uint8_t> fwkMsg =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    UserId hostUserId = fuzzData.ConsumeIntegral<UserId>();
    TemplateId templateId = fuzzData.ConsumeIntegral<TemplateId>();
    int32_t authIntent = fuzzData.ConsumeIntegral<int32_t>();
    FwkResultCallback callback = [](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        (void)result;
        (void)extraInfo;
    };
    AuthRequestParams params = { .scheduleId = scheduleId,
        .fwkMsg = fwkMsg,
        .hostUserId = hostUserId,
        .templateId = templateId,
        .authIntent = authIntent };
    auto request = factory->CreateHostTokenAuthRequest(params, std::move(callback));
    (void)request;
}

static void FuzzCreateHostRemoveHostBindingRequest(std::shared_ptr<RequestFactoryImpl> &factory,
    FuzzedDataProvider &fuzzData)
{
    UserId hostUserId = fuzzData.ConsumeIntegral<UserId>();
    TemplateId templateId = fuzzData.ConsumeIntegral<TemplateId>();
    DeviceKey companionDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    auto request = factory->CreateHostRemoveHostBindingRequest(hostUserId, templateId, companionDeviceKey);
    (void)request;
}

static void FuzzCreateHostSyncDeviceStatusRequest(std::shared_ptr<RequestFactoryImpl> &factory,
    FuzzedDataProvider &fuzzData)
{
    UserId hostUserId = fuzzData.ConsumeIntegral<UserId>();
    DeviceKey companionDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    std::string deviceName = GenerateFuzzString(fuzzData, SIZE_64);
    SyncDeviceStatusCallback callback = [](ResultCode result, const SyncDeviceStatus &status) {
        (void)result;
        (void)status;
    };
    auto request =
        factory->CreateHostSyncDeviceStatusRequest(hostUserId, companionDeviceKey, deviceName, std::move(callback));
    (void)request;
}

static void FuzzCreateHostIssueTokenRequest(std::shared_ptr<RequestFactoryImpl> &factory, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    UserId hostUserId = fuzzData.ConsumeIntegral<UserId>();
    TemplateId templateId = fuzzData.ConsumeIntegral<TemplateId>();
    uint32_t lockStateAuthTypeValue = fuzzData.ConsumeIntegral<uint32_t>();
    std::vector<uint8_t> msg =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    auto request = factory->CreateHostIssueTokenRequest(hostUserId, templateId, lockStateAuthTypeValue, msg);
    (void)request;
}

static void FuzzCreateHostDelegateAuthRequest(std::shared_ptr<RequestFactoryImpl> &factory,
    FuzzedDataProvider &fuzzData)
{
    ScheduleId scheduleId = fuzzData.ConsumeIntegral<ScheduleId>();
    std::vector<uint8_t> fwkMsg =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    UserId hostUserId = fuzzData.ConsumeIntegral<UserId>();
    TemplateId templateId = fuzzData.ConsumeIntegral<TemplateId>();
    int32_t authIntent = fuzzData.ConsumeIntegral<int32_t>();
    FwkResultCallback callback = [](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        (void)result;
        (void)extraInfo;
    };
    AuthRequestParams params = { .scheduleId = scheduleId,
        .fwkMsg = fwkMsg,
        .hostUserId = hostUserId,
        .templateId = templateId,
        .authIntent = authIntent };
    auto request = factory->CreateHostDelegateAuthRequest(params, std::move(callback));
    (void)request;
}

static void FuzzCreateCompanionAddCompanionRequest(std::shared_ptr<RequestFactoryImpl> &factory,
    FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, SIZE_64);
    Attributes request = GenerateFuzzAttributes(fuzzData);
    OnMessageReply firstReply = [](const Attributes &reply) { (void)reply; };
    DeviceKey hostDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    auto req =
        factory->CreateCompanionAddCompanionRequest(connectionName, request, std::move(firstReply), hostDeviceKey);
    (void)req;
}

static void FuzzCreateCompanionIssueTokenRequest(std::shared_ptr<RequestFactoryImpl> &factory,
    FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, SIZE_64);
    Attributes request = GenerateFuzzAttributes(fuzzData);
    OnMessageReply firstReply = [](const Attributes &reply) { (void)reply; };
    DeviceKey hostDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    auto req = factory->CreateCompanionIssueTokenRequest(connectionName, request, std::move(firstReply), hostDeviceKey);
    (void)req;
}

static void FuzzCreateHostObtainTokenRequest(std::shared_ptr<RequestFactoryImpl> &factory, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    std::string connectionName = GenerateFuzzString(fuzzData, SIZE_64);
    Attributes attr = GenerateFuzzAttributes(fuzzData);
    OnMessageReply callback = [](const Attributes &reply) { (void)reply; };
    DeviceKey companionDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    auto request = factory->CreateHostObtainTokenRequest(connectionName, attr, std::move(callback), companionDeviceKey);
    (void)request;
}

static void FuzzCreateCompanionObtainTokenRequest(std::shared_ptr<RequestFactoryImpl> &factory,
    FuzzedDataProvider &fuzzData)
{
    DeviceKey hostDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    uint32_t lockStateAuthTypeValue = fuzzData.ConsumeIntegral<uint32_t>();
    std::vector<uint8_t> fwkUnlockMsg =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    auto request = factory->CreateCompanionObtainTokenRequest(hostDeviceKey, lockStateAuthTypeValue, fwkUnlockMsg);
    (void)request;
}

static void FuzzCreateCompanionDelegateAuthRequest(std::shared_ptr<RequestFactoryImpl> &factory,
    FuzzedDataProvider &fuzzData)
{
    std::string connectionName = GenerateFuzzString(fuzzData, SIZE_64);
    UserId companionUserId = fuzzData.ConsumeIntegral<UserId>();
    DeviceKey hostDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    std::vector<uint8_t> startDelegateAuthRequest =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    ComapionDelegateAuthParam delegateAuthParam = { .remoteTokenId = fuzzData.ConsumeIntegral<uint32_t>() };
    auto request = factory->CreateCompanionDelegateAuthRequest(connectionName, companionUserId, hostDeviceKey,
        startDelegateAuthRequest, delegateAuthParam);
    (void)request;
}

static void FuzzCreateCompanionRevokeTokenRequest(std::shared_ptr<RequestFactoryImpl> &factory,
    FuzzedDataProvider &fuzzData)
{
    UserId companionUserId = fuzzData.ConsumeIntegral<UserId>();
    DeviceKey hostDeviceKey = GenerateFuzzDeviceKey(fuzzData);
    std::string triggerReason = GenerateFuzzString(fuzzData, 64);
    auto request = factory->CreateCompanionRevokeTokenRequest(companionUserId, hostDeviceKey, triggerReason);
    (void)request;
}

static void FuzzCreateHostMixAuthRequest(std::shared_ptr<RequestFactoryImpl> &factory, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    ScheduleId scheduleId = fuzzData.ConsumeIntegral<ScheduleId>();
    std::vector<uint8_t> fwkMsg =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    UserId hostUserId = fuzzData.ConsumeIntegral<UserId>();
    std::vector<TemplateId> templateIdList;
    uint8_t count = fuzzData.ConsumeIntegralInRange<uint8_t>(0, 10);
    for (uint8_t j = 0; j < count; ++j) {
        templateIdList.push_back(fuzzData.ConsumeIntegral<TemplateId>());
    }
    uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();
    std::optional<uint32_t> optionalTokenId = fuzzData.ConsumeBool() ? std::optional<uint32_t>(tokenId) : std::nullopt;
    int32_t authIntent = fuzzData.ConsumeIntegral<int32_t>();
    FwkResultCallback callback = [](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        (void)result;
        (void)extraInfo;
    };
    int32_t authScene = fuzzData.ConsumeIntegral<int32_t>();
    std::string title = fuzzData.ConsumeRandomLengthString(FUZZ_MAX_MESSAGE_LENGTH);
    HostMixAuthParams params = { scheduleId, fwkMsg, hostUserId, templateIdList, optionalTokenId, std::nullopt,
        authIntent, static_cast<UserAuth::AuthScene>(authScene), title };
    auto request = factory->CreateHostMixAuthRequest(params, std::move(callback));
    (void)request;
}

static void FuzzCreateHostSingleMixAuthRequest(std::shared_ptr<RequestFactoryImpl> &factory,
    FuzzedDataProvider &fuzzData)
{
    ScheduleId scheduleId = fuzzData.ConsumeIntegral<ScheduleId>();
    std::vector<uint8_t> fwkMsg =
        fuzzData.ConsumeBytes<uint8_t>(fuzzData.ConsumeIntegralInRange<size_t>(0, FUZZ_MAX_MESSAGE_LENGTH));
    UserId hostUserId = fuzzData.ConsumeIntegral<UserId>();
    TemplateId templateId = fuzzData.ConsumeIntegral<TemplateId>();
    int32_t authIntent = fuzzData.ConsumeIntegral<int32_t>();
    FwkResultCallback callback = [](ResultCode result, const std::vector<uint8_t> &extraInfo) {
        (void)result;
        (void)extraInfo;
    };
    AuthRequestParams params = { .scheduleId = scheduleId,
        .fwkMsg = fwkMsg,
        .hostUserId = hostUserId,
        .templateId = templateId,
        .authIntent = authIntent };
    DeviceKey companionDeviceKey = { .idType = DeviceIdType::UNIFIED_DEVICE_ID,
        .deviceId = "fuzz_device_id",
        .deviceUserId = fuzzData.ConsumeIntegral<UserId>() };
    auto request = factory->CreateHostSingleMixAuthRequest(params, companionDeviceKey, std::move(callback));
    (void)request;
}

static void FuzzCreate(std::shared_ptr<RequestFactoryImpl> &factory, FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto newFactory = RequestFactoryImpl::Create();
    (void)newFactory;
}

static const RequestFactoryImplFuzzFunction g_fuzzFuncs[] = {
    FuzzCreateHostAddCompanionRequest,
    FuzzCreateHostTokenAuthRequest,
    FuzzCreateHostRemoveHostBindingRequest,
    FuzzCreateHostSyncDeviceStatusRequest,
    FuzzCreateHostIssueTokenRequest,
    FuzzCreateHostDelegateAuthRequest,
    FuzzCreateCompanionAddCompanionRequest,
    FuzzCreateCompanionIssueTokenRequest,
    FuzzCreateHostObtainTokenRequest,
    FuzzCreateCompanionObtainTokenRequest,
    FuzzCreateCompanionDelegateAuthRequest,
    FuzzCreateCompanionRevokeTokenRequest,
    FuzzCreateHostMixAuthRequest,
    FuzzCreateHostSingleMixAuthRequest,
    FuzzCreate,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(RequestFactoryImplFuzzFunction);

void FuzzRequestFactoryImpl(FuzzedDataProvider &fuzzData)
{
    auto factory = RequestFactoryImpl::Create();
    if (!factory) {
        return;
    }

    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](factory, fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](factory, fuzzData);
        EnsureAllTaskExecuted();
    }
}

FUZZ_REGISTER(FuzzRequestFactoryImpl)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
