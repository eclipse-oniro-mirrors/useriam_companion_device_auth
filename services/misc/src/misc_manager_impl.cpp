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
#include "ipc_passcode_submit_callback_stub.h"
#include "ipc_set_device_select_result_callback_stub.h"
#include "parameter.h"
#include "service_common.h"
#include "singleton_manager.h"
#include "task_runner.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_MISC_MANAGER_IMPL

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
        std::optional<std::vector<uint8_t>> selectContext = ipcDeviceSelectResult.hasSelectionContext
            ? std::optional<std::vector<uint8_t>>(ipcDeviceSelectResult.selectionContext)
            : std::nullopt;
        TaskRunnerManager::GetInstance().PostTaskOnResident(
            [handler = std::move(handler_), devices = std::move(deviceKeys),
                context = std::move(selectContext)]() mutable {
                IAM_LOGI("devices:%{public}s contextLen:%{public}zu", DeviceKey::GetVectorDesc(devices).c_str(),
                    context.has_value() ? context->size() : 0);
                if (handler) {
                    handler(devices, context);
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

class MiscPasscodePromptCallback : public IpcPasscodeSubmitCallbackStub {
public:
    explicit MiscPasscodePromptCallback(PasscodePromptCallback &&handler) : handler_(std::move(handler))
    {
    }
    ~MiscPasscodePromptCallback() override = default;

    ErrCode OnPasscodeSubmit(const std::vector<uint8_t> &passcode) override
    {
        IAM_LOGI("OnPasscodeSubmit invoked, encrypted data len:%{public}zu", passcode.size());
        if (!handler_) {
            IAM_LOGE("handler has already been consumed");
            return GENERAL_ERROR;
        }
        std::vector<uint8_t> passcodeVec(passcode.begin(), passcode.end());
        TaskRunnerManager::GetInstance().PostTaskOnResident(
            [handler = std::move(handler_), passcode = std::move(passcodeVec)]() mutable {
                if (handler) {
                    handler(passcode);
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
    PasscodePromptCallback handler_ {};
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
    // uint64_t overflow is acceptable: it will wrap around to 0
    return globalIdCounter_++;
}

bool MiscManagerImpl::SetDeviceSelectCallback(uint32_t tokenId,
    const sptr<IIpcDeviceSelectCallback> &deviceSelectCallback)
{
    ENSURE_OR_RETURN_VAL(deviceSelectCallback != nullptr, false);

    auto obj = deviceSelectCallback->AsObject();
    ENSURE_OR_RETURN_VAL(obj != nullptr, false);

    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        CallbackDeathRecipient::Register(obj, [weakSelf = weak_from_this(), tokenId]() {
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
    auto it = callbacks_.find(tokenId);
    if (it != callbacks_.end()) {
        deviceSelectCallback = it->second.callback;
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

    IAM_LOGI("requested device select result, selectPurpose:%{public}d", selectPurpose);
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

bool MiscManagerImpl::SetPasscodePromptCallback(uint32_t tokenId,
    const sptr<IIpcPasscodePromptCallback> &passcodePromptCallback)
{
    ENSURE_OR_RETURN_VAL(passcodePromptCallback != nullptr, false);

    auto obj = passcodePromptCallback->AsObject();
    ENSURE_OR_RETURN_VAL(obj != nullptr, false);

    sptr<IRemoteObject::DeathRecipient> deathRecipient =
        CallbackDeathRecipient::Register(obj, [weakSelf = weak_from_this(), tokenId]() {
            IAM_LOGI("passcode prompt callback died, clearing callback");
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->ClearPasscodePromptCallback(tokenId);
        });
    ENSURE_OR_RETURN_VAL(deathRecipient != nullptr, false);

    auto it = passcodePromptCallbacks_.find(tokenId);
    if (it != passcodePromptCallbacks_.end()) {
        IAM_LOGI("replacing existing passcode prompt callback");
    }

    passcodePromptCallbacks_[tokenId] = { passcodePromptCallback, deathRecipient };
    IAM_LOGI("set passcode prompt callback");
    return true;
}

void MiscManagerImpl::ClearPasscodePromptCallback(uint32_t tokenId)
{
    auto it = passcodePromptCallbacks_.find(tokenId);
    if (it == passcodePromptCallbacks_.end()) {
        return;
    }

    passcodePromptCallbacks_.erase(it);
    IAM_LOGI("cleared passcode prompt callback");
}

bool MiscManagerImpl::PromptPasscode(uint32_t tokenId, const std::vector<uint8_t> &challenge,
    const std::vector<uint8_t> &publicKey, AsymEncryptAlgorithm asymEncryptAlgorithm,
    PasscodePromptCallback &&promptCallback)
{
    ENSURE_OR_RETURN_VAL(promptCallback != nullptr, false);

    sptr<IIpcPasscodePromptCallback> passcodePromptCallback;
    auto it = passcodePromptCallbacks_.find(tokenId);
    if (it != passcodePromptCallbacks_.end()) {
        passcodePromptCallback = it->second.callback;
    }
    ENSURE_OR_RETURN_VAL(passcodePromptCallback != nullptr, false);

    sptr<MiscPasscodePromptCallback> ipcSubmitCallback =
        new (std::nothrow) MiscPasscodePromptCallback(std::move(promptCallback));
    ENSURE_OR_RETURN_VAL(ipcSubmitCallback != nullptr, false);

    IpcPasscodePromptOptions ipcOptions;
    ipcOptions.challenge = challenge;
    ipcOptions.publicKey = publicKey;
    ipcOptions.asymEncryptAlgorithm = static_cast<int8_t>(asymEncryptAlgorithm);

    ErrCode ret = passcodePromptCallback->OnPasscodePrompt(ipcSubmitCallback, ipcOptions);
    if (ret != ERR_OK) {
        IAM_LOGE("OnPasscodePrompt failed, ret:%{public}d", ret);
        return false;
    }

    IAM_LOGI("requested passcode prompt, challenge len:%{public}zu, publicKey len:%{public}zu, algorithm:%{public}d",
        challenge.size(), publicKey.size(), static_cast<uint8_t>(asymEncryptAlgorithm));
    return true;
}

std::optional<std::string> MiscManagerImpl::GetLocalUdid()
{
    if (cachedUdid_.has_value()) {
        return cachedUdid_;
    }
    constexpr uint32_t UDID_LENGTH = 65;
    char udidBuffer[UDID_LENGTH] = { 0 };
    int udidRet = GetDevUdid(udidBuffer, UDID_LENGTH);
    if (udidRet != 0) {
        IAM_LOGE("GetLocalUdid failed, udidRet:%{public}d", udidRet);
        return std::nullopt;
    }
    std::string udid(udidBuffer, strnlen(udidBuffer, UDID_LENGTH - 1));
    if (udid.empty()) {
        IAM_LOGE("GetLocalUdid failed, empty udid");
        return std::nullopt;
    }
    cachedUdid_ = std::move(udid);
    IAM_LOGI("GetLocalUdid success");
    return cachedUdid_;
}

void MiscManagerImpl::SetCompanionAuthBlocked(bool blocked)
{
    if (blocked == companionAuthBlocked_) {
        IAM_LOGI("companion auth blocked unchanged %{public}d, skip notify", blocked);
        return;
    }
    companionAuthBlocked_ = blocked;
    IAM_LOGI("set companion auth blocked %{public}d", blocked);
    NotifyCompanionAuthBlockedChange(blocked);
}

bool MiscManagerImpl::IsCompanionAuthBlocked() const
{
    return companionAuthBlocked_;
}

std::unique_ptr<Subscription> MiscManagerImpl::SubscribeCompanionAuthBlockedChange(
    CompanionAuthBlockedCallback callback)
{
    ENSURE_OR_RETURN_VAL(callback != nullptr, nullptr);
    SubscribeId subscribeId = GetNextGlobalId();
    blockedChangeSubscribers_[subscribeId] = std::move(callback);
    std::weak_ptr<MiscManagerImpl> weakSelf = weak_from_this();
    return std::make_unique<Subscription>([weakSelf, subscribeId]() {
        auto self = weakSelf.lock();
        if (self != nullptr) {
            self->blockedChangeSubscribers_.erase(subscribeId);
        }
    });
}

void MiscManagerImpl::NotifyCompanionAuthBlockedChange(bool blocked)
{
    std::vector<CompanionAuthBlockedCallback> snapshot;
    for (const auto &entry : blockedChangeSubscribers_) {
        snapshot.push_back(entry.second);
    }
    TaskRunnerManager::GetInstance().PostTaskOnResident([snapshot = std::move(snapshot), blocked]() {
        for (const auto &callback : snapshot) {
            if (callback != nullptr) {
                callback(blocked);
            }
        }
    });
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
