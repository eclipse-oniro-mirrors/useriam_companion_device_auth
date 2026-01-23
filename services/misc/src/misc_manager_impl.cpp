/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "misc_manager_impl.h"

#include <limits>
#include <new>
#include <random>
#include <utility>

#include "errors.h"
#include "ipc_skeleton.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "callback_death_recipient.h"
#include "ipc_set_device_select_result_callback_stub.h"
#include "parameter.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "task_runner.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
std::vector<DeviceKey> ConvertIpcDeviceSelectResultToDeviceKeys(const IpcDeviceSelectResult &ipcResult)
{
    std::vector<DeviceKey> deviceKeys;
    deviceKeys.reserve(ipcResult.deviceKeys.size());

    for (const auto &ipcDeviceKey : ipcResult.deviceKeys) {
        DeviceKey deviceKey {};
        deviceKey.idType = static_cast<DeviceIdType>(ipcDeviceKey.deviceIdType);
        deviceKey.deviceId = ipcDeviceKey.deviceId;
        deviceKey.deviceUserId = ipcDeviceKey.deviceUserId;
        deviceKeys.push_back(deviceKey);
    }

    return deviceKeys;
}

class MiscDeviceSelectResultCallback : public IpcSetDeviceSelectResultCallbackStub {
public:
    explicit MiscDeviceSelectResultCallback(DeviceSelectResultHandler &&handler) : handler_(std::move(handler))
    {
    }
    ~MiscDeviceSelectResultCallback() override = default;

    ErrCode OnSetDeviceSelectResult(const IpcDeviceSelectResult &ipcDeviceSelectResult) override
    {
        if (!handler_) {
            IAM_LOGE("handler is invalid");
            return ERR_INVALID_VALUE;
        }
        std::vector<DeviceKey> deviceKeys = ConvertIpcDeviceSelectResultToDeviceKeys(ipcDeviceSelectResult);
        TaskRunnerManager::GetInstance().PostTaskOnResident(
            [handler = std::move(handler_), devices = std::move(deviceKeys)]() mutable {
                if (handler) {
                    handler(devices);
                }
            });
        return ERR_OK;
    }

    int32_t CallbackEnter(uint32_t code) override
    {
        (void)code;
        return ERR_OK;
    }

    int32_t CallbackExit(uint32_t code, int32_t result) override
    {
        (void)code;
        (void)result;
        return ERR_OK;
    }

private:
    DeviceSelectResultHandler handler_ {};
};
} // namespace

MiscManagerImpl::MiscManagerImpl()
{
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis(1, std::numeric_limits<uint64_t>::max());
    globalIdCounter_ = dis(gen);
}

std::shared_ptr<MiscManagerImpl> MiscManagerImpl::Create()
{
    auto manager = std::shared_ptr<MiscManagerImpl>(new (std::nothrow) MiscManagerImpl());
    ENSURE_OR_RETURN_VAL(manager != nullptr, nullptr);
    return manager;
}

uint64_t MiscManagerImpl::GetNextGlobalId()
{
    return globalIdCounter_++;
}

bool MiscManagerImpl::SetDeviceSelectCallback(uint32_t tokenId,
    const sptr<IIpcDeviceSelectCallback> &deviceSelectCallback)
{
    ENSURE_OR_RETURN_VAL(deviceSelectCallback != nullptr, false);

    auto obj = deviceSelectCallback->AsObject();
    ENSURE_OR_RETURN_VAL(obj != nullptr, false);

    auto weakSelf = weak_from_this();
    sptr<IRemoteObject::DeathRecipient> deathRecipient = CallbackDeathRecipient::Register(obj, [weakSelf, tokenId]() {
        IAM_LOGI("device select callback died, clearing callback");
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->ClearDeviceSelectCallback(tokenId);
    });
    ENSURE_OR_RETURN_VAL(deathRecipient != nullptr, false);

    auto it = callbacks_.find(tokenId);
    if (it != callbacks_.end()) {
        IAM_LOGI("replacing existing callback");
        callbacks_.erase(it);
    }

    callbacks_[tokenId] = { deviceSelectCallback, deathRecipient };
    IAM_LOGI("set device select callback");
    return true;
}

bool MiscManagerImpl::GetDeviceDeviceSelectResult(uint32_t tokenId, SelectPurpose selectPurpose,
    DeviceSelectResultHandler &&resultHandler)
{
    ENSURE_OR_RETURN_VAL(resultHandler != nullptr, false);

    sptr<IIpcDeviceSelectCallback> deviceSelectCallback;
    {
        auto it = callbacks_.find(tokenId);
        if (it != callbacks_.end()) {
            deviceSelectCallback = it->second.callback;
        }
    }

    if (deviceSelectCallback == nullptr) {
        IAM_LOGE("deviceSelectCallback not found, tokenId:%{public}u", tokenId);
        return false;
    }

    sptr<MiscDeviceSelectResultCallback> setResultCallback =
        new (std::nothrow) MiscDeviceSelectResultCallback(std::move(resultHandler));
    ENSURE_OR_RETURN_VAL(setResultCallback != nullptr, false);

    ErrCode ret = deviceSelectCallback->OnDeviceSelect(static_cast<int32_t>(selectPurpose), setResultCallback);
    if (ret != ERR_OK) {
        IAM_LOGE("OnDeviceSelect failed, ret:%{public}d", ret);
        return false;
    }

    IAM_LOGI("requested device select result, selectPurpose:%{public}d", static_cast<int32_t>(selectPurpose));
    return true;
}

void MiscManagerImpl::ClearDeviceSelectCallback(uint32_t tokenId)
{
    auto it = callbacks_.find(tokenId);
    if (it == callbacks_.end()) {
        return;
    }

    callbacks_.erase(it);
    IAM_LOGI("cleared device select callback");
}

std::optional<std::string> MiscManagerImpl::GetLocalUdid()
{
    constexpr uint32_t UDID_LENGTH = 65;
    char udidBuffer[UDID_LENGTH] = { 0 };
    int udidRet = AclGetDevUdid(udidBuffer, UDID_LENGTH);
    if (udidRet == 0 && udidBuffer[UDID_LENGTH - 1] == '\0') {
        return std::string(udidBuffer, strnlen(udidBuffer, UDID_LENGTH));
    }
    return std::nullopt;
}

bool MiscManagerImpl::CheckBusinessIds(const std::vector<BusinessId> &businessIds)
{
    IAM_LOGI("Start, businessIds size:%{public}zu", businessIds.size());

    for (const auto &businessId : businessIds) {
        if (businessId != BusinessId::DEFAULT) {
            IAM_LOGE("Invalid businessId:%{public}d", businessId);
            return false;
        }
    }

    IAM_LOGI("End, all businessIds are valid");
    return true;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
