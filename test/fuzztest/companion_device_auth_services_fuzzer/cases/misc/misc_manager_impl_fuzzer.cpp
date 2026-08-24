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
#include <new>
#include <vector>

#include "fuzzer/FuzzedDataProvider.h"
#include "ipc_object_stub.h"
#include "iremote_object.h"

#include "fuzz_constants.h"
#include "fuzz_data_generator.h"
#include "fuzz_registry.h"
#include "misc_manager_impl.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
constexpr int32_t INT32_3 = 3;
constexpr int32_t INT32_10 = 10;
constexpr size_t FUZZ_CALLBACK_PAYLOAD_MAX_SIZE = 64;

class FuzzRemoteObject : public IPCObjectStub {
public:
    FuzzRemoteObject() : IPCObjectStub(u"FuzzRemoteObject")
    {
    }
    ~FuzzRemoteObject() override = default;
};

IpcDeviceSelectResult GenerateFuzzIpcDeviceSelectResult(FuzzedDataProvider &fuzzData)
{
    IpcDeviceSelectResult result;
    uint8_t keyCount = fuzzData.ConsumeIntegralInRange<uint8_t>(0, FUZZ_MAX_DEVICE_KEY_COUNT);
    for (uint8_t i = 0; i < keyCount; ++i) {
        IpcDeviceKey deviceKey;
        deviceKey.deviceIdType = static_cast<int32_t>(GenerateFuzzDeviceIdType(fuzzData));
        deviceKey.deviceId = GenerateFuzzString(fuzzData);
        deviceKey.deviceUserId = fuzzData.ConsumeIntegral<int32_t>();
        result.deviceKeys.push_back(deviceKey);
    }
    result.hasSelectionContext = fuzzData.ConsumeBool();
    if (result.hasSelectionContext) {
        result.selectionContext = GenerateFuzzVector<uint8_t>(fuzzData, FUZZ_CALLBACK_PAYLOAD_MAX_SIZE);
    }
    return result;
}

// Stands in for the app-side IPC callback: replies immediately with fuzzed payload, delivers the
// result twice, or returns a fuzzed error code, mimicking hostile or misbehaving callers.
class FuzzIpcDeviceSelectCallback : public IIpcDeviceSelectCallback {
public:
    explicit FuzzIpcDeviceSelectCallback(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData)
    {
    }

    ErrCode OnDeviceSelect(int32_t selectPurpose,
        const sptr<IIpcSetDeviceSelectResultCallback> &setDeviceSelectResultCallback) override
    {
        (void)selectPurpose;
        uint8_t behavior = fuzzData_.ConsumeIntegralInRange<uint8_t>(0, 3);
        if (behavior == 0) {
            return static_cast<ErrCode>(fuzzData_.ConsumeIntegral<int32_t>());
        }
        if (setDeviceSelectResultCallback == nullptr) {
            return ERR_OK;
        }
        ErrCode ret =
            setDeviceSelectResultCallback->OnSetDeviceSelectResult(GenerateFuzzIpcDeviceSelectResult(fuzzData_));
        if (behavior == 1) {
            (void)setDeviceSelectResultCallback->OnSetDeviceSelectResult(GenerateFuzzIpcDeviceSelectResult(fuzzData_));
        }
        return ret;
    }

    sptr<IRemoteObject> AsObject() override
    {
        if (obj_ == nullptr) {
            obj_ = new (std::nothrow) FuzzRemoteObject();
        }
        return obj_;
    }

private:
    FuzzedDataProvider &fuzzData_;
    sptr<IRemoteObject> obj_;
};

class FuzzIpcPasscodePromptCallback : public IIpcPasscodePromptCallback {
public:
    explicit FuzzIpcPasscodePromptCallback(FuzzedDataProvider &fuzzData) : fuzzData_(fuzzData)
    {
    }

    ErrCode OnPasscodePrompt(const sptr<IIpcPasscodeSubmitCallback> &submitCallback,
        const IpcPasscodePromptParam &param) override
    {
        (void)param;
        uint8_t behavior = fuzzData_.ConsumeIntegralInRange<uint8_t>(0, 3);
        if (behavior == 0) {
            return static_cast<ErrCode>(fuzzData_.ConsumeIntegral<int32_t>());
        }
        if (submitCallback == nullptr) {
            return ERR_OK;
        }
        std::vector<uint8_t> passcode = GenerateFuzzVector<uint8_t>(fuzzData_, FUZZ_CALLBACK_PAYLOAD_MAX_SIZE);
        ErrCode ret = submitCallback->OnPasscodeSubmit(passcode);
        if (behavior == 1) {
            (void)submitCallback->OnPasscodeSubmit(passcode);
        }
        return ret;
    }

    sptr<IRemoteObject> AsObject() override
    {
        if (obj_ == nullptr) {
            obj_ = new (std::nothrow) FuzzRemoteObject();
        }
        return obj_;
    }

private:
    FuzzedDataProvider &fuzzData_;
    sptr<IRemoteObject> obj_;
};
} // namespace

using MiscManagerImplFuzzFunction = void (*)(FuzzedDataProvider &fuzzData);

static void FuzzCreate(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto manager = MiscManagerImpl::Create();
    (void)manager;
}

static void FuzzGetNextGlobalId(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto manager = MiscManagerImpl::Create();
    int num = INT32_10;
    if (manager) {
        for (int i = 0; i < num; ++i) {
            (void)manager->GetNextGlobalId();
        }
    }
}

static void FuzzGetLocalUdid(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto manager = MiscManagerImpl::Create();
    if (manager) {
        auto udid = manager->GetLocalUdid();
        (void)udid;
    }
}

static void FuzzClearDeviceSelectCallback(FuzzedDataProvider &fuzzData)
{
    uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();
    auto manager = MiscManagerImpl::Create();
    if (manager) {
        manager->ClearDeviceSelectCallback(tokenId);
    }
}

static void FuzzSetDeviceSelectCallback(FuzzedDataProvider &fuzzData)
{
    uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();
    auto manager = MiscManagerImpl::Create();
    if (!manager) {
        return;
    }
    if (fuzzData.ConsumeBool()) {
        sptr<IIpcDeviceSelectCallback> callback = new (std::nothrow) FuzzIpcDeviceSelectCallback(fuzzData);
        (void)manager->SetDeviceSelectCallback(tokenId, callback);
    } else {
        (void)manager->SetDeviceSelectCallback(tokenId, sptr<IIpcDeviceSelectCallback>());
    }
}

static void FuzzGetDeviceSelectResult(FuzzedDataProvider &fuzzData)
{
    uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();
    SelectPurpose selectPurpose = static_cast<SelectPurpose>(fuzzData.ConsumeIntegralInRange<uint8_t>(0, INT32_3));
    auto manager = MiscManagerImpl::Create();
    if (!manager) {
        return;
    }
    sptr<IIpcDeviceSelectCallback> callback = new (std::nothrow) FuzzIpcDeviceSelectCallback(fuzzData);
    if (callback == nullptr || !manager->SetDeviceSelectCallback(tokenId, callback)) {
        return;
    }
    DeviceSelectResultHandler resultHandler = [](const std::vector<DeviceKey> &devices,
                                                  const std::optional<std::vector<uint8_t>> &selectContext) {
        (void)devices;
        (void)selectContext;
    };
    (void)manager->GetDeviceDeviceSelectResult(tokenId, selectPurpose, std::move(resultHandler));
}

static void FuzzSetPasscodePromptCallback(FuzzedDataProvider &fuzzData)
{
    uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();
    auto manager = MiscManagerImpl::Create();
    if (!manager) {
        return;
    }
    if (fuzzData.ConsumeBool()) {
        sptr<IIpcPasscodePromptCallback> callback = new (std::nothrow) FuzzIpcPasscodePromptCallback(fuzzData);
        (void)manager->SetPasscodePromptCallback(tokenId, callback);
    } else {
        (void)manager->SetPasscodePromptCallback(tokenId, sptr<IIpcPasscodePromptCallback>());
    }
}

static void FuzzClearPasscodePromptCallback(FuzzedDataProvider &fuzzData)
{
    uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();
    auto manager = MiscManagerImpl::Create();
    if (manager) {
        manager->ClearPasscodePromptCallback(tokenId);
    }
}

static void FuzzPromptPasscode(FuzzedDataProvider &fuzzData)
{
    uint32_t tokenId = fuzzData.ConsumeIntegral<uint32_t>();
    auto manager = MiscManagerImpl::Create();
    if (!manager) {
        return;
    }
    sptr<IIpcPasscodePromptCallback> callback = new (std::nothrow) FuzzIpcPasscodePromptCallback(fuzzData);
    if (callback == nullptr || !manager->SetPasscodePromptCallback(tokenId, callback)) {
        return;
    }
    std::vector<uint8_t> challenge = GenerateFuzzVector<uint8_t>(fuzzData, FUZZ_CALLBACK_PAYLOAD_MAX_SIZE);
    std::vector<uint8_t> publicKey = GenerateFuzzVector<uint8_t>(fuzzData, FUZZ_CALLBACK_PAYLOAD_MAX_SIZE);
    AsymEncryptAlgorithm algorithm = static_cast<AsymEncryptAlgorithm>(fuzzData.ConsumeIntegral<uint8_t>());
    PasscodePromptCallback promptCallback = [](const std::vector<uint8_t> &passcode) { (void)passcode; };
    (void)manager->PromptPasscode(tokenId, challenge, publicKey, algorithm, std::move(promptCallback));
}

static void FuzzMiscManagerImplConstructor(FuzzedDataProvider &fuzzData)
{
    (void)fuzzData;
    auto manager = std::make_shared<MiscManagerImpl>();
    (void)manager;
}

static void FuzzPendingUnlock(FuzzedDataProvider &fuzzData)
{
    auto manager = MiscManagerImpl::Create();
    if (!manager) {
        return;
    }
    // Interleave Push/Take with fuzz scheduleIds to exercise the bounded pending list, the max-5
    // eviction, dedupe-on-re-push, and idempotent take. Results are not asserted (state depends on
    // prior iterations).
    int32_t opCount = fuzzData.ConsumeIntegralInRange<int32_t>(0, INT32_10);
    for (int32_t i = 0; i < opCount && fuzzData.remaining_bytes() >= sizeof(uint64_t); ++i) {
        uint64_t scheduleId = fuzzData.ConsumeIntegral<uint64_t>();
        if (fuzzData.ConsumeBool()) {
            manager->PushPendingUnlock(scheduleId, scheduleId);
        } else {
            (void)manager->TakePendingUnlock(scheduleId);
        }
    }
}

static const MiscManagerImplFuzzFunction g_fuzzFuncs[] = {
    FuzzCreate,
    FuzzGetNextGlobalId,
    FuzzGetLocalUdid,
    FuzzClearDeviceSelectCallback,
    FuzzSetDeviceSelectCallback,
    FuzzGetDeviceSelectResult,
    FuzzSetPasscodePromptCallback,
    FuzzClearPasscodePromptCallback,
    FuzzPromptPasscode,
    FuzzMiscManagerImplConstructor,
    FuzzPendingUnlock,
};

constexpr uint8_t NUM_FUZZ_OPERATIONS = sizeof(g_fuzzFuncs) / sizeof(MiscManagerImplFuzzFunction);

void FuzzMiscManagerImpl(FuzzedDataProvider &fuzzData)
{
    for (size_t i = 0; i < NUM_FUZZ_OPERATIONS; ++i) {
        if (fuzzData.remaining_bytes() < MINIMUM_REMAINING_BYTES) {
            break;
        }
        g_fuzzFuncs[i](fuzzData);
        EnsureAllTaskExecuted();
    }

    constexpr uint32_t loopCount = BASE_LOOP_COUNT + NUM_FUZZ_OPERATIONS * LOOP_PER_OPERATION;
    for (uint32_t i = 0; i < loopCount; ++i) {
        if (!fuzzData.remaining_bytes()) {
            break;
        }

        uint8_t operation = fuzzData.ConsumeIntegralInRange<uint8_t>(0, NUM_FUZZ_OPERATIONS - 1);
        g_fuzzFuncs[operation](fuzzData);
        EnsureAllTaskExecuted();
    }

    EnsureAllTaskExecuted();
}

FUZZ_REGISTER(FuzzMiscManagerImpl)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
