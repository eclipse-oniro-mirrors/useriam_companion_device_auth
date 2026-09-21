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

#include "host_binding_manager_impl.h"

#include <algorithm>
#include <cinttypes>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "adapter_manager.h"
#include "host_binding.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_HOST_BINDING_MANAGER_IMPL

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::shared_ptr<HostBindingManagerImpl> HostBindingManagerImpl::Create()
{
    auto manager = std::shared_ptr<HostBindingManagerImpl>(new (std::nothrow) HostBindingManagerImpl());
    ENSURE_OR_RETURN_VAL(manager != nullptr, nullptr);
    if (!manager->Initialize()) {
        IAM_LOGE("Initialize failed");
        return nullptr;
    }
    return manager;
}

bool HostBindingManagerImpl::Initialize()
{
    IAM_LOGI("begin");

    unlockedActiveUserIdSubscription_ =
        GetUserIdManager().SubscribeUnlockedActiveUserKey([weakSelf = weak_from_this()](const UserKey &userKey) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->OnActiveUserKeyChanged(userKey);
        });
    ENSURE_OR_RETURN_VAL(unlockedActiveUserIdSubscription_ != nullptr, false);

    subProfileChangedSubscription_ = GetUserIdManager().SubscribeSubProfileChanged(
        [weakSelf = weak_from_this()](const UserKey &userKey, SubProfileEventType eventType) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            if (eventType == SubProfileEventType::SWITCHED) {
                self->OnActiveUserKeyChanged(userKey);
                return;
            }
        });
    ENSURE_OR_RETURN_VAL(subProfileChangedSubscription_ != nullptr, false);

    IAM_LOGI("success");
    return true;
}

void HostBindingManagerImpl::OnActiveUserKeyChanged(const UserKey &activeUserKey)
{
    if (activeUserKey == activeUserKey_) {
        IAM_LOGI("active user key unchanged");
        return;
    }

    IAM_LOGI("active user key changed from userId %{public}d subProfileId %{public}d to userId %{public}d "
             "subProfileId %{public}d",
        activeUserKey_.userId, activeUserKey_.subProfileId, activeUserKey.userId, activeUserKey.subProfileId);
    bindings_.clear();
    activeUserKey_ = activeUserKey;

    if (activeUserKey_.userId == INVALID_USER_ID) {
        return;
    }

    ReloadBindingsForSubProfile(activeUserKey_);
}

void HostBindingManagerImpl::ReloadBindingsForSubProfile(const UserKey &activeUserKey)
{
    CompanionGetPersistedHostBindingStatusInput input { activeUserKey };
    CompanionGetPersistedHostBindingStatusOutput output {};
    ResultCode ret = GetSecurityAgent().CompanionGetPersistedHostBindingStatus(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("failed to get persisted host binding status, ret %{public}d", ret);
        return;
    }

    for (const auto &persistedStatus : output.hostBindingStatusList) {
        auto binding = HostBinding::Create(persistedStatus);
        if (binding == nullptr) {
            IAM_LOGE("failed to create binding id %{public}s",
                GET_MASKED_NUM_STRING(persistedStatus.bindingId).c_str());
            continue;
        }

        ret = AddBindingInternal(binding);
        if (ret != ResultCode::SUCCESS) {
            IAM_LOGE("failed to add binding id %{public}s, ret %{public}d",
                GET_MASKED_NUM_STRING(persistedStatus.bindingId).c_str(), ret);
        }
    }
    IAM_LOGI("reloaded %{public}zu bindings for user %{public}d, subProfileId=%{public}d", bindings_.size(),
        activeUserKey.userId, activeUserKey.subProfileId);
}

std::optional<HostBindingStatus> HostBindingManagerImpl::GetHostBindingStatus(BindingId bindingId)
{
    auto binding = FindBindingById(bindingId);
    if (binding == nullptr) {
        IAM_LOGI("binding id %{public}s not found", GET_MASKED_NUM_STRING(bindingId).c_str());
        return std::nullopt;
    }

    return binding->GetStatus();
}

std::optional<HostBindingStatus> HostBindingManagerImpl::GetHostBindingStatus(const UserKey &companionUserKey,
    const DeviceKey &hostDeviceKey)
{
    auto binding = FindBindingByDeviceUser(companionUserKey, hostDeviceKey);
    if (binding == nullptr) {
        IAM_LOGI("binding not found for device-user combination, companionUserId %{public}d, hostDeviceKey %{public}s",
            companionUserKey.userId, hostDeviceKey.GetDesc().c_str());
        return std::nullopt;
    }

    return binding->GetStatus();
}

std::vector<HostBindingStatus> HostBindingManagerImpl::GetAllHostBindingStatus()
{
    std::vector<HostBindingStatus> result;
    result.reserve(bindings_.size());

    for (const auto &binding : bindings_) {
        if (binding != nullptr) {
            result.push_back(binding->GetStatus());
        }
    }

    IAM_LOGI("returning %{public}zu host binding statuses", result.size());
    return result;
}

ResultCode HostBindingManagerImpl::BeginAddHostBinding(const BeginAddHostBindingInput &in,
    BeginAddHostBindingOutput &out)
{
    IAM_LOGI("begin add host binding, request id 0x%{public}08X", in.requestId);

    ENSURE_OR_RETURN_VAL(in.companionUserKey == activeUserKey_, ResultCode::GENERAL_ERROR);

    CompanionBeginAddHostBindingInput input { .requestId = in.requestId,
        .secureProtocolId = in.secureProtocolId,
        .addHostBindingRequest = in.addHostBindingRequest };

    CompanionBeginAddHostBindingOutput output {};
    ResultCode ret = BeginAddHostBindingWithSecurityAgent(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("security agent failed to begin add host binding, ret %{public}d", ret);
        return ret;
    }

    if (output.addHostBindingReply.empty() || output.hostBindingStatus.bindingId == 0) {
        IAM_LOGE("invalid add request output");
        return ResultCode::GENERAL_ERROR;
    }

    if (output.replacedBindingId.has_value()) {
        uint32_t replacedId = output.replacedBindingId.value();
        IAM_LOGI("replacing binding %{public}s", GET_MASKED_NUM_STRING(replacedId).c_str());
        ResultCode removeRet = RemoveBindingInternal(replacedId);
        if (removeRet != ResultCode::SUCCESS) {
            IAM_LOGE("failed to remove replaced binding %{public}s, ret %{public}d",
                GET_MASKED_NUM_STRING(replacedId).c_str(), removeRet);
        }
    }

    auto binding = HostBinding::Create(output.hostBindingStatus);
    if (binding == nullptr) {
        IAM_LOGE("failed to create HostBinding for %{public}s",
            GET_MASKED_NUM_STRING(output.hostBindingStatus.bindingId).c_str());
        return ResultCode::GENERAL_ERROR;
    }

    ret = AddBindingInternal(binding);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("failed to add binding %{public}s, ret %{public}d",
            GET_MASKED_NUM_STRING(binding->GetBindingId()).c_str(), ret);
        return ret;
    }

    out.addHostBindingReply.swap(output.addHostBindingReply);
    out.bindingId = output.hostBindingStatus.bindingId;

    IAM_LOGI("begin add host binding success, request id 0x%{public}08X, binding id %{public}s", in.requestId,
        GET_MASKED_NUM_STRING(out.bindingId).c_str());
    return ResultCode::SUCCESS;
}

CompanionEndAddHostBindingInput HostBindingManagerImpl::BuildCompanionEndAddHostBindingInput(
    const EndAddHostBindingInput &input)
{
    return CompanionEndAddHostBindingInput { .requestId = input.requestId,
        .resultCode = input.resultCode,
        .tokenData = input.tokenData };
}

void HostBindingManagerImpl::FillEndAddHostBindingOutput(const CompanionEndAddHostBindingOutput &ffiOutput,
    EndAddHostBindingOutput &output)
{
    output.atl = ffiOutput.atl;
    output.esl = ffiOutput.esl;
}

ResultCode HostBindingManagerImpl::EndAddHostBinding(const EndAddHostBindingInput &input,
    EndAddHostBindingOutput &output)
{
    IAM_LOGI("end add host binding, request id 0x%{public}08X, result %{public}d", input.requestId, input.resultCode);

    auto ffiInput = BuildCompanionEndAddHostBindingInput(input);
    CompanionEndAddHostBindingOutput ffiOutput {};
    // Rust end() only distributes tokens and never deletes the binding, so skip
    // RemoveBindingInternal here to keep C++ and Rust state consistent.
    // Binding cleanup is handled by RemoveHostBinding or BeginAddHostBinding replacement.
    ResultCode ret = GetSecurityAgent().CompanionEndAddHostBinding(ffiInput, ffiOutput);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("security agent failed to end add host binding, ret %{public}d", ret);
        return ret;
    }

    FillEndAddHostBindingOutput(ffiOutput, output);

    if (input.resultCode != ResultCode::SUCCESS) {
        return input.resultCode;
    }
    SetHostBindingTokenValid(input.bindingId, true);

    // Token data received and stored in the binding by SecurityAgent
    if (!input.tokenData.empty()) {
        IAM_LOGI("end add host binding received token data, binding id %{public}s, token size %{public}zu",
            GET_MASKED_NUM_STRING(input.bindingId).c_str(), input.tokenData.size());
    }

    IAM_LOGI("end add host binding success, binding id %{public}s", GET_MASKED_NUM_STRING(input.bindingId).c_str());
    return ResultCode::SUCCESS;
}

ResultCode HostBindingManagerImpl::RemoveHostBinding(const UserKey &companionUserKey, const DeviceKey &hostDeviceKey)
{
    auto persistedId = FindPersistedBindingId(companionUserKey, hostDeviceKey);
    if (!persistedId.has_value()) {
        IAM_LOGE("binding not found for user %{public}d", companionUserKey.userId);
        return ResultCode::GENERAL_ERROR;
    }

    CompanionRemoveHostBindingInput input { *persistedId };
    ResultCode ret = GetSecurityAgent().CompanionRemoveHostBinding(input);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("security agent failed to remove host binding %{public}s, ret %{public}d",
            GET_MASKED_NUM_STRING(*persistedId).c_str(), ret);
        return ret;
    }

    RemoveBindingInternal(*persistedId);
    IAM_LOGI("remove host binding success, id %{public}s", GET_MASKED_NUM_STRING(*persistedId).c_str());
    return ResultCode::SUCCESS;
}

ResultCode HostBindingManagerImpl::RemoveHostBindingById(BindingId bindingId)
{
    CompanionRemoveHostBindingInput input { bindingId };
    ResultCode ret = GetSecurityAgent().CompanionRemoveHostBinding(input);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("security agent failed to remove host binding %{public}s, ret %{public}d",
            GET_MASKED_NUM_STRING(bindingId).c_str(), ret);
        return ret;
    }

    RemoveBindingInternal(bindingId);
    IAM_LOGI("remove host binding by id success, id %{public}s", GET_MASKED_NUM_STRING(bindingId).c_str());
    return ResultCode::SUCCESS;
}

std::optional<BindingId> HostBindingManagerImpl::FindPersistedBindingId(const UserKey &companionUserKey,
    const DeviceKey &hostDeviceKey)
{
    CompanionGetPersistedHostBindingStatusInput input { companionUserKey };
    CompanionGetPersistedHostBindingStatusOutput output {};
    ResultCode ret = GetSecurityAgent().CompanionGetPersistedHostBindingStatus(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("failed to get persisted host binding status, ret %{public}d, user %{public}d", ret,
            companionUserKey.userId);
        return std::nullopt;
    }

    for (const auto &status : output.hostBindingStatusList) {
        if (status.hostDeviceKey == hostDeviceKey) {
            return status.bindingId;
        }
    }
    return std::nullopt;
}

std::shared_ptr<HostBinding> HostBindingManagerImpl::FindBindingById(BindingId bindingId)
{
    auto it =
        std::find_if(bindings_.begin(), bindings_.end(), [bindingId](const std::shared_ptr<HostBinding> &binding) {
            return binding != nullptr && binding->GetBindingId() == bindingId;
        });

    return (it != bindings_.end()) ? *it : nullptr;
}

std::shared_ptr<HostBinding> HostBindingManagerImpl::FindBindingByDeviceUser(const UserKey &userKey,
    const DeviceKey &deviceKey)
{
    auto it = std::find_if(bindings_.begin(), bindings_.end(),
        [userKey, &deviceKey](const std::shared_ptr<HostBinding> &binding) {
            ENSURE_OR_RETURN_VAL(binding != nullptr, false);
            const auto &key = binding->GetHostDeviceKey();
            return binding->GetCompanionUserId() == userKey.userId && key == deviceKey;
        });

    return (it != bindings_.end()) ? *it : nullptr;
}

ResultCode HostBindingManagerImpl::BeginAddHostBindingWithSecurityAgent(const CompanionBeginAddHostBindingInput &input,
    CompanionBeginAddHostBindingOutput &output)
{
    return GetSecurityAgent().CompanionBeginAddHostBinding(input, output);
}

ResultCode HostBindingManagerImpl::AddBindingInternal(const std::shared_ptr<HostBinding> &binding)
{
    ENSURE_OR_RETURN_VAL(binding != nullptr, ResultCode::GENERAL_ERROR);

    BindingId bindingId = binding->GetBindingId();
    UserKey userKey { binding->GetCompanionUserId(), binding->GetCompanionSubProfileId() };
    const DeviceKey &deviceKey = binding->GetHostDeviceKey();

    if (FindBindingById(bindingId) != nullptr) {
        IAM_LOGE("binding id %{public}s already exists", GET_MASKED_NUM_STRING(bindingId).c_str());
        return ResultCode::GENERAL_ERROR;
    }

    auto duplicatedBinding = FindBindingByDeviceUser(userKey, deviceKey);
    if (duplicatedBinding != nullptr) {
        IAM_LOGI("user %{public}d already bound, replace %{public}s -> %{public}s", userKey.userId,
            GET_MASKED_NUM_STRING(duplicatedBinding->GetBindingId()).c_str(), GET_MASKED_NUM_STRING(bindingId).c_str());
        RemoveBindingInternal(duplicatedBinding->GetBindingId());
    }

    bindings_.push_back(binding);

    IAM_LOGI("added binding id %{public}s, hostDeviceKey %{public}s, companion user %{public}d",
        GET_MASKED_NUM_STRING(bindingId).c_str(), deviceKey.GetDesc().c_str(), userKey.userId);
    return ResultCode::SUCCESS;
}

ResultCode HostBindingManagerImpl::RemoveBindingInternal(BindingId bindingId)
{
    auto it = std::find_if(bindings_.begin(), bindings_.end(),
        [bindingId](const std::shared_ptr<HostBinding> &binding) { return binding->GetBindingId() == bindingId; });
    if (it == bindings_.end()) {
        IAM_LOGI("binding id %{public}s not found", GET_MASKED_NUM_STRING(bindingId).c_str());
        return ResultCode::GENERAL_ERROR;
    }

    bindings_.erase(it);

    IAM_LOGI("removed binding id %{public}s", GET_MASKED_NUM_STRING(bindingId).c_str());
    return ResultCode::SUCCESS;
}

bool HostBindingManagerImpl::SetHostBindingTokenValid(BindingId bindingId, bool isTokenValid)
{
    auto binding = FindBindingById(bindingId);
    if (binding == nullptr) {
        IAM_LOGE("binding not found for binding id %{public}s", GET_MASKED_NUM_STRING(bindingId).c_str());
        return false;
    }

    binding->SetTokenValid(isTokenValid, "unknown");

    IAM_LOGI("set host binding token valid success, binding id %{public}s, isTokenValid %{public}d",
        GET_MASKED_NUM_STRING(bindingId).c_str(), isTokenValid);
    return true;
}

void HostBindingManagerImpl::StartObtainTokenRequests(const UserKey &activeUserKey, uint32_t lockStateAuthTypeValue,
    const std::vector<uint8_t> &fwkUnlockMsg)
{
    IAM_LOGI("start, userId=%{public}d, subProfileId=%{public}d", activeUserKey.userId, activeUserKey.subProfileId);

    if (activeUserKey_ != activeUserKey) {
        IAM_LOGI("userKey mismatch: requested userId %{public}d subProfileId %{public}d, "
                 "active userId %{public}d subProfileId %{public}d, skip",
            activeUserKey.userId, activeUserKey.subProfileId, activeUserKey_.userId, activeUserKey_.subProfileId);
        return;
    }

    for (const auto &binding : bindings_) {
        ENSURE_OR_CONTINUE(binding != nullptr);

        BindingId bindingId = binding->GetBindingId();
        const DeviceKey &hostDeviceKey = binding->GetHostDeviceKey();
        IAM_LOGI("binding %{public}s creating CompanionObtainTokenRequest for host device idType=%{public}d, "
                 "userId=%{public}d",
            GET_MASKED_NUM_STRING(bindingId).c_str(), static_cast<int32_t>(hostDeviceKey.idType),
            hostDeviceKey.deviceUserId);
        auto request =
            GetRequestFactory().CreateCompanionObtainTokenRequest(hostDeviceKey, lockStateAuthTypeValue, fwkUnlockMsg);
        ENSURE_OR_CONTINUE(request != nullptr);

        bool result = GetRequestManager().Start(request);
        if (!result) {
            IAM_LOGE("binding %{public}s failed to start CompanionObtainTokenRequest",
                GET_MASKED_NUM_STRING(bindingId).c_str());
            continue;
        }

        IAM_LOGI("binding %{public}s successfully started CompanionObtainTokenRequest",
            GET_MASKED_NUM_STRING(bindingId).c_str());
    }

    IAM_LOGI("end");
}

void HostBindingManagerImpl::RevokeTokens(UserId userId, const std::string &reason)
{
    IAM_LOGI("start, userId=%{public}d, reason=%{public}s", userId, reason.c_str());

    if (activeUserKey_.userId != userId) {
        IAM_LOGI("user id %{public}d mismatch with active user id %{public}d, skip", userId, activeUserKey_.userId);
        return;
    }

    IAM_LOGI("Found %{public}zu host bindings in total", bindings_.size());

    std::string actualReason = reason.empty() ? "property freeze" : reason;
    for (const auto &binding : bindings_) {
        ENSURE_OR_CONTINUE(binding != nullptr);
        binding->SetTokenValid(false, actualReason);
    }

    IAM_LOGI("end");
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
