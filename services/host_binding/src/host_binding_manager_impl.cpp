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

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::shared_ptr<HostBindingManagerImpl> HostBindingManagerImpl::Create()
{
    auto manager = std::shared_ptr<HostBindingManagerImpl>(new (std::nothrow) HostBindingManagerImpl());
    ENSURE_OR_RETURN_VAL(manager != nullptr, nullptr);
    manager->Initialize();
    return manager;
}

bool HostBindingManagerImpl::Initialize()
{
    IAM_LOGI("begin");

    if (activeUserIdSubscription_ != nullptr) {
        IAM_LOGI("already subscribed to active user id");
        return true;
    }

    auto weakSelf = weak_from_this();
    activeUserIdSubscription_ = GetUserIdManager().SubscribeActiveUserId([weakSelf](UserId userId) {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->OnActiveUserIdChanged(userId);
    });
    ENSURE_OR_RETURN_VAL(activeUserIdSubscription_ != nullptr, false);

    IAM_LOGI("success");
    return true;
}

void HostBindingManagerImpl::OnActiveUserIdChanged(UserId userId)
{
    if (userId == activeUserId_) {
        IAM_LOGI("active user id is the same as the companion user id");
        return;
    }

    IAM_LOGI("active user id changed from %{public}d to %{public}d", activeUserId_, userId);
    bindings_.clear();
    activeUserId_ = userId;

    if (activeUserId_ == INVALID_USER_ID) {
        return;
    }

    CompanionGetPersistedHostBindingStatusInput input { activeUserId_ };
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
    IAM_LOGI("reloaded %{public}zu bindings for user %{public}d", bindings_.size(), activeUserId_);
    return;
}

std::optional<HostBindingStatus> HostBindingManagerImpl::GetHostBindingStatus(BindingId bindingId)
{
    auto binding = FindBindingById(bindingId);
    if (binding == nullptr) {
        IAM_LOGE("binding id %{public}s not found", GET_MASKED_NUM_STRING(bindingId).c_str());
        return std::nullopt;
    }

    return binding->GetStatus();
}

std::optional<HostBindingStatus> HostBindingManagerImpl::GetHostBindingStatus(UserId companionUserId,
    const DeviceKey &hostDeviceKey)
{
    auto binding = FindBindingByDeviceUser(companionUserId, hostDeviceKey);
    if (binding == nullptr) {
        IAM_LOGE("binding not found for device-user combination");
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

    IAM_LOGE("returning %{public}zu host binding statuses", result.size());
    return result;
}

ResultCode HostBindingManagerImpl::BeginAddHostBinding(RequestId requestId, UserId companionUserId,
    SecureProtocolId secureProtocolId, const std::vector<uint8_t> &addHostBindingRequest,
    std::vector<uint8_t> &outAddHostBindingReply)
{
    IAM_LOGI("begin add host binding, request id 0x%{public}08X", requestId);

    ENSURE_OR_RETURN_VAL(companionUserId == activeUserId_, ResultCode::GENERAL_ERROR);
    if (activeUserId_ != companionUserId) {
        IAM_LOGE("companion user id mismatch, expected %{public}d, actual %{public}d", activeUserId_, companionUserId);
        return ResultCode::GENERAL_ERROR;
    }

    CompanionBeginAddHostBindingInput input { .requestId = requestId,
        .secureProtocolId = secureProtocolId,
        .addHostBindingRequest = addHostBindingRequest };

    CompanionBeginAddHostBindingOutput output {};
    ResultCode ret = GetSecurityAgent().CompanionBeginAddHostBinding(input, output);
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
            IAM_LOGW("failed to remove replaced binding %{public}s, ret %{public}d",
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

    outAddHostBindingReply.swap(output.addHostBindingReply);

    IAM_LOGI("begin add host binding success, request id 0x%{public}08X", requestId);
    return ResultCode::SUCCESS;
}

ResultCode HostBindingManagerImpl::EndAddHostBinding(RequestId requestId, ResultCode resultCode,
    const std::vector<uint8_t> &tokenData)
{
    IAM_LOGI("end add host binding, request id 0x%{public}08X, result %{public}d", requestId, resultCode);

    CompanionEndAddHostBindingInput input { .requestId = requestId, .resultCode = resultCode, .tokenData = tokenData };
    CompanionEndAddHostBindingOutput output {};
    ResultCode ret = GetSecurityAgent().CompanionEndAddHostBinding(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("security agent failed to end add host binding, ret %{public}d", ret);
        return ret;
    }

    if (resultCode != ResultCode::SUCCESS) {
        if (output.bindingId != 0) {
            IAM_LOGI("removing failed binding %{public}s", GET_MASKED_NUM_STRING(output.bindingId).c_str());
            RemoveBindingInternal(output.bindingId);
        }
        return ResultCode::SUCCESS;
    }

    // Token data received and stored in the binding by SecurityAgent
    if (!tokenData.empty()) {
        IAM_LOGI("end add host binding received token data, binding id %{public}s, token size %{public}zu",
            GET_MASKED_NUM_STRING(output.bindingId).c_str(), tokenData.size());
    }

    IAM_LOGI("end add host binding success, binding id %{public}s", GET_MASKED_NUM_STRING(output.bindingId).c_str());
    return ResultCode::SUCCESS;
}

ResultCode HostBindingManagerImpl::RemoveHostBinding(UserId companionUserId, const DeviceKey &hostDeviceKey)
{
    auto binding = FindBindingByDeviceUser(companionUserId, hostDeviceKey);
    if (binding == nullptr) {
        IAM_LOGE("binding not found for user %{public}d", companionUserId);
        return ResultCode::GENERAL_ERROR;
    }

    BindingId bindingId = binding->GetBindingId();
    CompanionRemoveHostBindingInput input { bindingId };
    ResultCode ret = GetSecurityAgent().CompanionRemoveHostBinding(input);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("security agent failed to remove host binding %{public}s, ret %{public}d",
            GET_MASKED_NUM_STRING(bindingId).c_str(), ret);
        return ret;
    }

    ResultCode removeRet = RemoveBindingInternal(bindingId);
    if (removeRet != ResultCode::SUCCESS) {
        IAM_LOGW("binding id %{public}s not cached locally", GET_MASKED_NUM_STRING(bindingId).c_str());
    }

    IAM_LOGI("remove host binding success, id %{public}s", GET_MASKED_NUM_STRING(bindingId).c_str());
    return ResultCode::SUCCESS;
}

std::shared_ptr<HostBinding> HostBindingManagerImpl::FindBindingById(BindingId bindingId)
{
    auto it = std::find_if(bindings_.begin(), bindings_.end(),
        [bindingId](const std::shared_ptr<HostBinding> &binding) { return binding->GetBindingId() == bindingId; });

    return (it != bindings_.end()) ? *it : nullptr;
}

std::shared_ptr<HostBinding> HostBindingManagerImpl::FindBindingByDeviceUser(UserId userId, const DeviceKey &deviceKey)
{
    auto it = std::find_if(bindings_.begin(), bindings_.end(),
        [userId, &deviceKey](const std::shared_ptr<HostBinding> &binding) {
            const auto &key = binding->GetHostDeviceKey();
            return binding->GetCompanionUserId() == userId && key == deviceKey;
        });

    return (it != bindings_.end()) ? *it : nullptr;
}

ResultCode HostBindingManagerImpl::AddBindingInternal(const std::shared_ptr<HostBinding> &binding)
{
    ENSURE_OR_RETURN_VAL(binding != nullptr, ResultCode::GENERAL_ERROR);

    BindingId bindingId = binding->GetBindingId();
    UserId userId = binding->GetCompanionUserId();
    const DeviceKey &deviceKey = binding->GetHostDeviceKey();

    if (FindBindingById(bindingId) != nullptr) {
        IAM_LOGE("binding id %{public}s already exists", GET_MASKED_NUM_STRING(bindingId).c_str());
        return ResultCode::GENERAL_ERROR;
    }

    auto duplicatedBinding = FindBindingByDeviceUser(userId, deviceKey);
    if (duplicatedBinding != nullptr) {
        IAM_LOGI("user %{public}d already bound, replace %{public}s -> %{public}s", userId,
            GET_MASKED_NUM_STRING(duplicatedBinding->GetBindingId()).c_str(), GET_MASKED_NUM_STRING(bindingId).c_str());
        RemoveBindingInternal(duplicatedBinding->GetBindingId());
    }

    bindings_.push_back(binding);

    IAM_LOGI("added binding id %{public}s, hostDeviceKey %{public}s, companion user %{public}d",
        GET_MASKED_NUM_STRING(bindingId).c_str(), deviceKey.GetDesc().c_str(), userId);
    return ResultCode::SUCCESS;
}

ResultCode HostBindingManagerImpl::RemoveBindingInternal(BindingId bindingId)
{
    auto it = std::find_if(bindings_.begin(), bindings_.end(),
        [bindingId](const std::shared_ptr<HostBinding> &binding) { return binding->GetBindingId() == bindingId; });
    if (it == bindings_.end()) {
        IAM_LOGW("binding id %{public}s not found", GET_MASKED_NUM_STRING(bindingId).c_str());
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

    binding->SetTokenValid(isTokenValid);

    IAM_LOGI("set host binding token valid success, binding id %{public}s, isTokenValid %{public}d",
        GET_MASKED_NUM_STRING(bindingId).c_str(), isTokenValid);
    return true;
}

void HostBindingManagerImpl::StartObtainTokenRequests(UserId userId, const std::vector<uint8_t> &fwkUnlockMsg)
{
    IAM_LOGI("start, userId=%{public}d", userId);

    if (activeUserId_ != userId) {
        IAM_LOGI("user id %{public}d mismatch with active user id %{public}d, skip", userId, activeUserId_);
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
        auto request = GetRequestFactory().CreateCompanionObtainTokenRequest(hostDeviceKey, fwkUnlockMsg);
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

void HostBindingManagerImpl::RevokeTokens(UserId userId)
{
    IAM_LOGI("start, userId=%{public}d", userId);

    if (activeUserId_ != userId) {
        IAM_LOGI("user id %{public}d mismatch with active user id %{public}d, skip", userId, activeUserId_);
        return;
    }

    IAM_LOGI("Found %{public}zu host bindings in total", bindings_.size());

    for (const auto &binding : bindings_) {
        ENSURE_OR_CONTINUE(binding != nullptr);
        binding->SetTokenValid(false);
    }

    IAM_LOGI("end");
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
