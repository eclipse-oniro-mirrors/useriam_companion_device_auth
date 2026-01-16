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

#include "companion_manager_impl.h"

#include <algorithm>
#include <cinttypes>
#include <utility>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "companion.h"
#include "host_remove_host_binding_request.h"
#include "request_factory.h"
#include "request_manager.h"
#include "security_agent.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::shared_ptr<CompanionManagerImpl> CompanionManagerImpl::Create()
{
    auto manager = std::shared_ptr<CompanionManagerImpl>(new (std::nothrow) CompanionManagerImpl());
    ENSURE_OR_RETURN_VAL(manager != nullptr, nullptr);
    manager->Initialize();
    return manager;
}

CompanionManagerImpl::CompanionManagerImpl()
{
}

CompanionManagerImpl::~CompanionManagerImpl()
{
}

void CompanionManagerImpl::Initialize()
{
    IAM_LOGI("initialize companion manager begin");

    if (activeUserIdSubscription_ != nullptr) {
        IAM_LOGI("already subscribed to active user id");
        return;
    }

    auto weakSelf = weak_from_this();
    activeUserIdSubscription_ = GetUserIdManager().SubscribeActiveUserId([weakSelf](UserId userId) {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->OnActiveUserIdChanged(userId);
    });
    ENSURE_OR_RETURN(activeUserIdSubscription_ != nullptr);

    IAM_LOGI("initialize companion manager success");
}

void CompanionManagerImpl::Reload(const std::vector<PersistedCompanionStatus> &persistedCompanionList)
{
    for (const auto &persistedStatus : persistedCompanionList) {
        auto companion = Companion::Create(persistedStatus, weak_from_this());
        if (companion == nullptr) {
            IAM_LOGE("failed to create companion template id %{public}s",
                GET_MASKED_NUM_CSTR(persistedStatus.templateId));
            continue;
        }

        ResultCode ret = AddCompanionInternal(companion);
        if (ret != ResultCode::SUCCESS) {
            IAM_LOGE("failed to add companion template id %{public}s, ret %{public}d",
                GET_MASKED_NUM_CSTR(persistedStatus.templateId), ret);
        }
    }
    IAM_LOGI("reloaded %{public}zu companions for user %{public}d", companions_.size(), hostUserId_);
}

std::optional<CompanionStatus> CompanionManagerImpl::GetCompanionStatus(TemplateId templateId)
{
    auto companion = FindCompanionByTemplateId(templateId);
    if (companion == nullptr) {
        IAM_LOGE("template id %{public}s not found", GET_MASKED_NUM_CSTR(templateId));
        return std::nullopt;
    }
    return companion->GetStatus();
}

std::optional<CompanionStatus> CompanionManagerImpl::GetCompanionStatus(UserId hostUserId,
    const DeviceKey &companionDeviceKey)
{
    auto companion = FindCompanionByDeviceUser(hostUserId, companionDeviceKey);
    if (companion == nullptr) {
        IAM_LOGE("companion not found for device-user combination");
        return std::nullopt;
    }
    return companion->GetStatus();
}

std::vector<CompanionStatus> CompanionManagerImpl::GetAllCompanionStatus()
{
    std::vector<CompanionStatus> statusList;
    statusList.reserve(companions_.size());
    for (const auto &companion : companions_) {
        if (companion != nullptr) {
            statusList.push_back(companion->GetStatus());
        }
    }
    return statusList;
}

std::unique_ptr<Subscription> CompanionManagerImpl::SubscribeCompanionDeviceStatusChange(
    OnCompanionDeviceStatusChange &&callback)
{
    SubscribeId subscriptionId = nextSubscriptionId_.fetch_add(1);
    auto weakSelf = weak_from_this();
    statusSubscribers_[subscriptionId] = std::move(callback);

    IAM_LOGI("Companion device status subscription added: %{public}" PRIu64, subscriptionId);

    return std::make_unique<Subscription>([weakSelf, subscriptionId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->UnsubscribeCompanionDeviceStatusChange(subscriptionId);
    });
}

void CompanionManagerImpl::UnsubscribeCompanionDeviceStatusChange(SubscribeId subscriptionId)
{
    statusSubscribers_.erase(subscriptionId);
    IAM_LOGI("Companion device status subscription removed: %{public}" PRIu64, subscriptionId);
}

ResultCode CompanionManagerImpl::BeginAddCompanion(const BeginAddCompanionParams &params,
    std::vector<uint8_t> &outAddHostBindingRequest)
{
    IAM_LOGI("begin add companion, request id %{public}u", params.requestId);

    if (hostUserId_ == INVALID_USER_ID) {
        IAM_LOGE("no active user");
        return ResultCode::GENERAL_ERROR;
    }

    if (hostUserId_ != params.hostDeviceKey.deviceUserId) {
        IAM_LOGE("host user id mismatch, expected %{public}d, actual %{public}d", hostUserId_,
            params.hostDeviceKey.deviceUserId);
        return ResultCode::GENERAL_ERROR;
    }

    HostBeginAddCompanionInput input { .requestId = params.requestId,
        .scheduleId = params.scheduleId,
        .hostDeviceKey = params.hostDeviceKey,
        .companionDeviceKey = params.companionDeviceKey,
        .fwkMsg = params.fwkMsg,
        .secureProtocolId = params.secureProtocolId,
        .initKeyNegotiationReply = params.initKeyNegotiationReply };

    HostBeginAddCompanionOutput output {};
    ResultCode ret = GetSecurityAgent().HostBeginAddCompanion(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("security agent failed to begin add companion, ret %{public}d", ret);
        return ret;
    }

    if (output.addHostBindingRequest.empty()) {
        IAM_LOGE("invalid begin add companion output");
        return ResultCode::GENERAL_ERROR;
    }

    outAddHostBindingRequest.swap(output.addHostBindingRequest);

    IAM_LOGI("begin add companion success, request id %{public}u", params.requestId);
    return ResultCode::SUCCESS;
}

ResultCode CompanionManagerImpl::EndAddCompanion(const EndAddCompanionInput &input, EndAddCompanionOutput &output)
{
    IAM_LOGI("end add companion, request id %{public}u", input.requestId);

    if (hostUserId_ == INVALID_USER_ID) {
        IAM_LOGE("no active user");
        return ResultCode::GENERAL_ERROR;
    }

    if (hostUserId_ != input.companionStatus.hostUserId) {
        IAM_LOGE("host user id mismatch, expected %{public}d, actual %{public}d", hostUserId_,
            input.companionStatus.hostUserId);
        return ResultCode::GENERAL_ERROR;
    }

    HostEndAddCompanionInput secInput { .requestId = input.requestId,
        .companionStatus = input.companionStatus,
        .secureProtocolId = input.secureProtocolId,
        .addHostBindingReply = input.addHostBindingReply };

    HostEndAddCompanionOutput secOutput {};
    ResultCode ret = GetSecurityAgent().HostEndAddCompanion(secInput, secOutput);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("security agent failed to end add companion, ret %{public}d", ret);
        return ret;
    }

    PersistedCompanionStatus updatedStatus = input.companionStatus;
    updatedStatus.templateId = secOutput.templateId;

    auto companion = Companion::Create(updatedStatus, weak_from_this());
    if (companion == nullptr) {
        IAM_LOGE("failed to create Companion for %{public}s", GET_MASKED_NUM_CSTR(secOutput.templateId));
        return ResultCode::GENERAL_ERROR;
    }

    ret = AddCompanionInternal(companion);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("failed to add companion %{public}s, ret %{public}d",
            GET_TRUNCATED_STRING(companion->GetTemplateId()).c_str(), ret);
        return ret;
    }

    output.fwkMsg.swap(secOutput.fwkMsg);
    output.tokenData.swap(secOutput.tokenData);
    output.atl = secOutput.atl;

    NotifyCompanionStatusChange();

    IAM_LOGI("end add companion success, request id %{public}u", input.requestId);
    return ResultCode::SUCCESS;
}

ResultCode CompanionManagerImpl::RemoveCompanion(TemplateId templateId)
{
    HostRemoveCompanionInput input { templateId };
    HostRemoveCompanionOutput output;
    ResultCode ret = GetSecurityAgent().HostRemoveCompanion(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("security agent failed to remove companion %{public}s, ret %{public}d",
            GET_MASKED_NUM_CSTR(templateId), ret);
        return ret;
    }

    ResultCode removeRet = RemoveCompanionInternal(templateId);
    if (removeRet != ResultCode::SUCCESS) {
        IAM_LOGW("companion template id %{public}s not cached locally", GET_MASKED_NUM_CSTR(templateId));
    }

    NotifyCompanionStatusChange();

    auto request = GetRequestFactory().CreateHostRemoveHostBindingRequest(output.userId, output.companionDeviceKey);
    if (request == nullptr) {
        IAM_LOGE("CreateHostRemoveHostBindingRequest failed for templateId %{public}s",
            GET_MASKED_NUM_CSTR(templateId));
        return ResultCode::SUCCESS;
    }

    bool result = GetRequestManager().Start(request);
    if (!result) {
        IAM_LOGE("request Start failed for templateId %{public}s", GET_MASKED_NUM_CSTR(templateId));
        return ResultCode::SUCCESS;
    }

    IAM_LOGI("remove companion success, template id %{public}s", GET_MASKED_NUM_CSTR(templateId));
    return ResultCode::SUCCESS;
}

ResultCode CompanionManagerImpl::UpdateCompanionStatus(TemplateId templateId, const std::string &deviceName,
    const std::string &deviceUserName)
{
    auto companion = FindCompanionByTemplateId(templateId);
    if (companion == nullptr) {
        IAM_LOGE("companion template id %{public}s not found", GET_MASKED_NUM_CSTR(templateId));
        return ResultCode::GENERAL_ERROR;
    }

    HostUpdateCompanionStatusInput input { .templateId = templateId,
        .companionDeviceName = deviceName,
        .companionDeviceUserName = deviceUserName };
    ResultCode ret = GetSecurityAgent().HostUpdateCompanionStatus(input);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("HostUpdateCompanionStatus failed ret %{public}d", ret);
        return ret;
    }

    companion->SetDeviceNames(deviceName, deviceUserName);

    IAM_LOGI("update companion status success, template id %{public}s", GET_MASKED_NUM_CSTR(templateId));
    return ResultCode::SUCCESS;
}

ResultCode CompanionManagerImpl::UpdateCompanionEnabledBusinessIds(TemplateId templateId,
    const std::vector<BusinessId> &enabledBusinessIds)
{
    auto companion = FindCompanionByTemplateId(templateId);
    if (companion == nullptr) {
        IAM_LOGE("companion template id %{public}s not found", GET_MASKED_NUM_CSTR(templateId));
        return ResultCode::NOT_ENROLLED;
    }

    HostUpdateCompanionEnabledBusinessIdsInput input { .templateId = templateId,
        .enabledBusinessIds = enabledBusinessIds };
    ResultCode ret = GetSecurityAgent().HostUpdateCompanionEnabledBusinessIds(input);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("HostUpdateCompanionEnabledBusinessIds failed ret %{public}d", ret);
        return ret;
    }

    companion->SetEnabledBusinessIds(enabledBusinessIds);

    IAM_LOGI("update companion enabled business ids success, template id %{public}s", GET_MASKED_NUM_CSTR(templateId));
    return ResultCode::SUCCESS;
}

bool CompanionManagerImpl::SetCompanionTokenAtl(TemplateId templateId, std::optional<Atl> atl)
{
    auto companion = FindCompanionByTemplateId(templateId);
    if (companion == nullptr) {
        IAM_LOGE("companion template id %{public}s not found", GET_MASKED_NUM_CSTR(templateId));
        return false;
    }

    companion->SetCompanionTokenAtl(atl);
    return true;
}

ResultCode CompanionManagerImpl::UpdateToken(TemplateId templateId, const std::vector<uint8_t> &fwkMsg,
    bool &needRedistribute)
{
    needRedistribute = false;

    auto companion = FindCompanionByTemplateId(templateId);
    if (companion == nullptr) {
        IAM_LOGE("companion template id %{public}s not found", GET_MASKED_NUM_CSTR(templateId));
        return ResultCode::GENERAL_ERROR;
    }

    HostUpdateTokenInput input = { .templateId = templateId, .fwkMsg = fwkMsg };
    HostUpdateTokenOutput output = {};
    ResultCode ret = GetSecurityAgent().HostUpdateToken(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("HostUpdateToken failed ret=%{public}d", ret);
        return ret;
    }

    needRedistribute = output.needRedistribute;
    if (needRedistribute) {
        companion->RefreshTokenTimer();
    }

    return ResultCode::SUCCESS;
}

ResultCode CompanionManagerImpl::HandleCompanionCheckFail(TemplateId templateId)
{
    auto companion = FindCompanionByTemplateId(templateId);
    if (companion == nullptr) {
        IAM_LOGE("companion template id %{public}s not found", GET_MASKED_NUM_CSTR(templateId));
        return ResultCode::GENERAL_ERROR;
    }

    companion->SetCompanionValid(false);

    IAM_LOGI("handle companion check fail success, template id %{public}s set to invalid",
        GET_MASKED_NUM_CSTR(templateId));
    return ResultCode::SUCCESS;
}

void CompanionManagerImpl::OnActiveUserIdChanged(UserId userId)
{
    if (userId == hostUserId_) {
        IAM_LOGI("active user id is the same as the host user id");
        return;
    }

    IAM_LOGI("active user id changed from %{public}d to %{public}d", hostUserId_, userId);
    companions_.clear();
    hostUserId_ = userId;
    if (hostUserId_ == INVALID_USER_ID) {
        return;
    }
    HostGetPersistedCompanionStatusInput input { hostUserId_ };
    HostGetPersistedCompanionStatusOutput output;
    ResultCode ret = GetSecurityAgent().HostGetPersistedCompanionStatus(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("failed to get persisted companion status, ret %{public}d", ret);
        return;
    }
    Reload(output.companionStatusList);
    NotifyCompanionStatusChange();
}

void CompanionManagerImpl::NotifyCompanionStatusChange()
{
    std::vector<CompanionStatus> statusList;
    statusList.reserve(companions_.size());
    for (const auto &companion : companions_) {
        if (companion != nullptr) {
            statusList.push_back(companion->GetStatus());
        }
    }

    std::vector<OnCompanionDeviceStatusChange> callbacks;
    callbacks.reserve(statusSubscribers_.size());
    for (const auto &entry : statusSubscribers_) {
        callbacks.emplace_back(entry.second);
    }

    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [callbacks = std::move(callbacks), statusList = std::move(statusList)]() {
            for (const auto &callback : callbacks) {
                callback(statusList);
            }
        });
}

std::shared_ptr<Companion> CompanionManagerImpl::FindCompanionByTemplateId(TemplateId templateId)
{
    auto it =
        std::find_if(companions_.begin(), companions_.end(), [templateId](const std::shared_ptr<Companion> &companion) {
            return companion != nullptr && companion->GetTemplateId() == templateId;
        });

    return (it != companions_.end()) ? *it : nullptr;
}

std::shared_ptr<Companion> CompanionManagerImpl::FindCompanionByDeviceUser(UserId hostUserId,
    const DeviceKey &deviceKey)
{
    auto it = std::find_if(companions_.begin(), companions_.end(),
        [hostUserId, &deviceKey](const std::shared_ptr<Companion> &companion) {
            return companion != nullptr && companion->GetHostUserId() == hostUserId &&
                companion->GetCompanionDeviceKey() == deviceKey;
        });

    return (it != companions_.end()) ? *it : nullptr;
}

ResultCode CompanionManagerImpl::AddCompanionInternal(const std::shared_ptr<Companion> &companion)
{
    ENSURE_OR_RETURN_VAL(companion != nullptr, ResultCode::GENERAL_ERROR);

    TemplateId templateId = companion->GetTemplateId();
    UserId userId = companion->GetHostUserId();
    const DeviceKey &deviceKey = companion->GetCompanionDeviceKey();

    if (FindCompanionByTemplateId(templateId) != nullptr) {
        IAM_LOGE("companion template id %{public}s already exists", GET_MASKED_NUM_CSTR(templateId));
        return ResultCode::GENERAL_ERROR;
    }

    if (FindCompanionByDeviceUser(userId, deviceKey) != nullptr) {
        IAM_LOGE("user %{public}d, device %{public}s already exists", userId, deviceKey.GetDesc().c_str());
        return ResultCode::GENERAL_ERROR;
    }

    companions_.push_back(companion);

    IAM_LOGI("added companion template id %{public}s, companionDeviceKey %{public}s, host user %{public}d",
        GET_MASKED_NUM_CSTR(templateId), deviceKey.GetDesc().c_str(), userId);
    return ResultCode::SUCCESS;
}

ResultCode CompanionManagerImpl::RemoveCompanionInternal(TemplateId templateId)
{
    // clang-format off
    companions_.erase(std::remove_if(companions_.begin(), companions_.end(),
        [templateId](const std::shared_ptr<Companion> &companion) {
            return companion != nullptr && companion->GetTemplateId() == templateId;
        }),
        companions_.end());
    // clang-format on
    return ResultCode::SUCCESS;
}

void CompanionManagerImpl::StartIssueTokenRequests(const std::vector<uint64_t> &templateIds,
    const std::vector<uint8_t> &fwkUnlockMsg)
{
    IAM_LOGI("start, templateIds size=%{public}zu", templateIds.size());
    for (const auto &templateId : templateIds) {
        IAM_LOGI("templateId %{public}s", GET_MASKED_NUM_CSTR(templateId));
    }

    for (const auto &companion : companions_) {
        if (companion == nullptr) {
            continue;
        }

        IAM_LOGI("companion %{public}s", companion->GetDescription().c_str());

        TemplateId templateId = companion->GetTemplateId();
        auto it = std::find(templateIds.begin(), templateIds.end(), templateId);
        if (it == templateIds.end()) {
            IAM_LOGI("companion %{public}s not in template list, skip", companion->GetDescription().c_str());
            continue;
        }

        CompanionStatus companionStatus = companion->GetStatus();
        if (!companionStatus.isValid) {
            IAM_LOGW("companion %{public}s is invalid, skip", companion->GetDescription().c_str());
            continue;
        }

        IAM_LOGI("companion %{public}s creating HostIssueTokenRequest, userId=%{public}d",
            companion->GetDescription().c_str(), companionStatus.hostUserId);

        auto request = GetRequestFactory().CreateHostIssueTokenRequest(companionStatus.hostUserId,
            companionStatus.templateId, fwkUnlockMsg);
        if (request == nullptr) {
            IAM_LOGE("companion %{public}s failed to create HostIssueTokenRequest",
                companion->GetDescription().c_str());
            continue;
        }

        bool result = GetRequestManager().Start(request);
        if (!result) {
            IAM_LOGE("companion %{public}s failed to start HostIssueTokenRequest", companion->GetDescription().c_str());
            continue;
        }

        IAM_LOGI("companion %{public}s successfully started HostIssueTokenRequest",
            companion->GetDescription().c_str());
    }

    IAM_LOGI("end");
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
