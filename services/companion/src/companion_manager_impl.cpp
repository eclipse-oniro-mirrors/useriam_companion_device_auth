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
#include "iam_safe_arithmetic.h"

#include "adapter_manager.h"
#include "companion.h"
#include "host_remove_host_binding_request.h"
#include "relative_timer.h"
#include "request_factory.h"
#include "request_manager.h"
#include "scope_guard.h"
#include "security_agent.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"
#include "time_keeper.h"

#define LOG_TAG "CDA_SA"

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

bool CompanionManagerImpl::Initialize()
{
    IAM_LOGI("initialize companion manager begin");

    activeUserIdSubscription_ = GetUserIdManager().SubscribeActiveUserId([weakSelf = weak_from_this()](UserId userId) {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->OnActiveUserIdChanged(userId);
    });
    ENSURE_OR_RETURN_VAL(activeUserIdSubscription_ != nullptr, false);

    IAM_LOGI("initialize companion manager success");
    return true;
}

void CompanionManagerImpl::Reload(const std::vector<PersistedCompanionStatus> &persistedCompanionList,
    const std::vector<TemplateId> &activeUserTemplateIds)
{
    auto nowMs = GetTimeKeeper().GetSystemTimeMs();
    ENSURE_OR_RETURN(nowMs.has_value());
    for (const auto &persistedStatus : persistedCompanionList) {
        ReloadSingleCompanion(persistedStatus, activeUserTemplateIds, nowMs.value());
    }
    IAM_LOGI("reloaded %{public}zu companions for user %{public}d", companions_.size(), hostUserId_);
}

void CompanionManagerImpl::ReloadSingleCompanion(const PersistedCompanionStatus &persistedStatus,
    const std::vector<TemplateId> &activeUserTemplateIds, uint64_t nowMs)
{
    TemplateId templateId = persistedStatus.templateId;
    bool addedToIdm = std::find(activeUserTemplateIds.begin(), activeUserTemplateIds.end(), templateId) !=
        activeUserTemplateIds.end();
    if (addedToIdm) {
        auto companion = Companion::Create(persistedStatus, true, weak_from_this());
        ENSURE_OR_RETURN(companion != nullptr);

        ResultCode addCompanionRet = AddCompanionInternal(companion);
        ENSURE_OR_RETURN(addCompanionRet == ResultCode::SUCCESS);
        IAM_LOGI("Reloaded companion %{public}s (in IDM)", GET_MASKED_NUM_CSTR(templateId));
    } else {
        auto companion = Companion::Create(persistedStatus, true, weak_from_this());
        ENSURE_OR_RETURN(companion != nullptr);

        ResultCode addCompanionRet = AddCompanionInternal(companion);
        ENSURE_OR_RETURN(addCompanionRet == ResultCode::SUCCESS);

        IAM_LOGI("Reloaded companion %{public}s (not in IDM, timer started)", GET_MASKED_NUM_CSTR(templateId));
    }
}

std::optional<CompanionStatus> CompanionManagerImpl::GetCompanionStatus(TemplateId templateId)
{
    auto companion = FindCompanionByTemplateId(templateId);
    if (companion == nullptr) {
        IAM_LOGE("template id %{public}s not found", GET_MASKED_NUM_CSTR(templateId));
        return std::nullopt;
    }

    if (!companion->IsAddedToIdm()) {
        IAM_LOGI("template id %{public}s is not added to IDM", GET_MASKED_NUM_CSTR(templateId));
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

    if (!companion->IsAddedToIdm()) {
        IAM_LOGI("template id %{public}s is not added to IDM", GET_MASKED_NUM_CSTR(companion->GetTemplateId()));
        return std::nullopt;
    }

    return companion->GetStatus();
}

std::vector<CompanionStatus> CompanionManagerImpl::GetAllCompanionStatus()
{
    std::vector<CompanionStatus> statusList;
    statusList.reserve(companions_.size());
    for (const auto &companion : companions_) {
        ENSURE_OR_CONTINUE(companion != nullptr);
        if (!companion->IsAddedToIdm()) {
            IAM_LOGI("template id  %{public}s is not added to IDM", GET_MASKED_NUM_CSTR(companion->GetTemplateId()));
            continue;
        }
        statusList.push_back(companion->GetStatus());
    }
    return statusList;
}

std::unique_ptr<Subscription> CompanionManagerImpl::SubscribeCompanionDeviceStatusChange(
    OnCompanionDeviceStatusChange &&callback)
{
    SubscribeId subscriptionId = GetMiscManager().GetNextGlobalId();
    statusSubscribers_[subscriptionId] = std::move(callback);

    IAM_LOGD("Companion device status subscription added: 0x%{public}016" PRIX64 "", subscriptionId);

    return std::make_unique<Subscription>([weakSelf = weak_from_this(), subscriptionId]() {
        auto self = weakSelf.lock();
        ENSURE_OR_RETURN(self != nullptr);
        self->UnsubscribeCompanionDeviceStatusChange(subscriptionId);
    });
}

void CompanionManagerImpl::UnsubscribeCompanionDeviceStatusChange(SubscribeId subscriptionId)
{
    statusSubscribers_.erase(subscriptionId);
    IAM_LOGD("Companion device status subscription removed: 0x%{public}016" PRIX64 "", subscriptionId);
}

ResultCode CompanionManagerImpl::BeginAddCompanion(const BeginAddCompanionParams &params,
    std::vector<uint8_t> &outAddHostBindingRequest)
{
    IAM_LOGI("begin add companion, request id 0x%{public}08X", params.requestId);

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

    IAM_LOGI("begin add companion success, request id 0x%{public}08X", params.requestId);
    return ResultCode::SUCCESS;
}

ResultCode CompanionManagerImpl::EndAddCompanion(const EndAddCompanionInput &input, EndAddCompanionOutput &output)
{
    IAM_LOGI("end add companion, request id 0x%{public}08X", input.requestId);

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
    updatedStatus.addedTime = secOutput.addedTime;

    auto companion = Companion::Create(updatedStatus, true, weak_from_this());
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

    output.templateId = secOutput.templateId;
    output.fwkMsg.swap(secOutput.fwkMsg);
    output.tokenData.swap(secOutput.tokenData);
    output.atl = secOutput.atl;

    NotifyCompanionStatusChange();

    IAM_LOGI("end add companion success, request id 0x%{public}08X", input.requestId);
    return ResultCode::SUCCESS;
}

ResultCode CompanionManagerImpl::RemoveCompanion(TemplateId templateId)
{
    HostRemoveCompanionInput input { templateId };
    HostRemoveCompanionOutput output {};
    ResultCode ret = GetSecurityAgent().HostRemoveCompanion(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("security agent failed to remove companion %{public}s, ret %{public}d",
            GET_MASKED_NUM_CSTR(templateId), ret);
        return ret;
    }

    auto companion = FindCompanionByTemplateId(templateId);
    ENSURE_OR_RETURN_VAL(companion != nullptr, ResultCode::GENERAL_ERROR);
    companion->SetAddedToIdm(false);
    NotifyCompanionStatusChange();
    ScopeGuard guard([this, templateId]() { HandleRemoveHostBindingComplete(templateId); });
    auto request =
        GetRequestFactory().CreateHostRemoveHostBindingRequest(output.userId, templateId, output.companionDeviceKey);
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
    guard.Cancel();

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

    if (!output.needRedistribute) {
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
    templateChangeSubscription_.reset();

    if (hostUserId_ == INVALID_USER_ID) {
        return;
    }

    templateChangeSubscription_ = AdapterManager::GetInstance().GetIdmAdapter().SubscribeUserTemplateChange(hostUserId_,
        [weakSelf = weak_from_this()](UserId changedUserId, const std::vector<TemplateId> &templateIds) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->OnTemplateListChanged(changedUserId, templateIds);
        });
    ENSURE_OR_RETURN(templateChangeSubscription_ != nullptr);

    auto activeUserTemplateIds = AdapterManager::GetInstance().GetIdmAdapter().GetUserTemplates(hostUserId_);
    IAM_LOGI("Got %{public}zu templates for user %{public}d", activeUserTemplateIds.size(), hostUserId_);

    HostGetPersistedCompanionStatusInput input { hostUserId_ };
    HostGetPersistedCompanionStatusOutput output {};
    ResultCode ret = GetSecurityAgent().HostGetPersistedCompanionStatus(input, output);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("failed to get persisted companion status, ret %{public}d", ret);
        return;
    }
    Reload(output.companionStatusList, activeUserTemplateIds);
    NotifyCompanionStatusChange();
}

void CompanionManagerImpl::OnTemplateListChanged(UserId userId, const std::vector<TemplateId> &templateIds)
{
    if (userId != hostUserId_) {
        IAM_LOGI("template list changed for non-host user %{public}d (current host: %{public}d), ignoring", userId,
            hostUserId_);
        return;
    }

    IAM_LOGI("template list changed for user %{public}d, %{public}zu templates", userId, templateIds.size());

    for (const auto &templateId : templateIds) {
        auto companion = FindCompanionByTemplateId(templateId);
        if (companion != nullptr && !companion->IsAddedToIdm()) {
            IAM_LOGI("template %{public}s added to IDM, marking companion", GET_MASKED_NUM_CSTR(templateId));
            companion->SetAddedToIdm(true);
        }
    }
}

void CompanionManagerImpl::NotifyCompanionStatusChange()
{
    std::vector<CompanionStatus> statusList;
    statusList.reserve(companions_.size());
    for (const auto &companion : companions_) {
        ENSURE_OR_CONTINUE(companion != nullptr);

        if (!companion->IsAddedToIdm()) {
            IAM_LOGE("template id %{public}s is not added to IDM", GET_MASKED_NUM_CSTR(companion->GetTemplateId()));
            continue;
        }
        statusList.push_back(companion->GetStatus());
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
        ENSURE_OR_CONTINUE(companion != nullptr);
        IAM_LOGI("companion %{public}s", companion->GetDescription());

        TemplateId templateId = companion->GetTemplateId();
        auto it = std::find(templateIds.begin(), templateIds.end(), templateId);
        if (it == templateIds.end()) {
            IAM_LOGI("companion %{public}s not in template list, skip", companion->GetDescription());
            continue;
        }

        CompanionStatus companionStatus = companion->GetStatus();
        if (!companionStatus.isValid) {
            IAM_LOGW("companion %{public}s is invalid, skip", companion->GetDescription());
            continue;
        }

        IAM_LOGI("companion %{public}s creating HostIssueTokenRequest, userId=%{public}d", companion->GetDescription(),
            companionStatus.hostUserId);

        auto request = GetRequestFactory().CreateHostIssueTokenRequest(companionStatus.hostUserId,
            companionStatus.templateId, fwkUnlockMsg);
        if (request == nullptr) {
            IAM_LOGE("companion %{public}s failed to create HostIssueTokenRequest", companion->GetDescription());
            continue;
        }

        bool result = GetRequestManager().Start(request);
        if (!result) {
            IAM_LOGE("companion %{public}s failed to start HostIssueTokenRequest", companion->GetDescription());
            continue;
        }

        IAM_LOGI("companion %{public}s successfully started HostIssueTokenRequest", companion->GetDescription());
    }

    IAM_LOGI("end");
}

void CompanionManagerImpl::HandleRemoveHostBindingComplete(TemplateId templateId)
{
    IAM_LOGI("start, template id %{public}s", GET_MASKED_NUM_CSTR(templateId));
    ResultCode removeRet = RemoveCompanionInternal(templateId);
    if (removeRet != ResultCode::SUCCESS) {
        IAM_LOGE("failed to remove companion template id %{public}s", GET_MASKED_NUM_CSTR(templateId));
        return;
    }

    NotifyCompanionStatusChange();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
