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

#include "host_mix_auth_request.h"

#include <cinttypes>

#include "iam_check.h"
#include "iam_logger.h"

#include "adapter_manager.h"
#include "common_defines.h"
#include "companion_manager.h"
#include "misc_manager.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_HOST_MIX_AUTH_REQUEST

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
HostMixAuthRequest::HostMixAuthRequest(const HostMixAuthParams &params, FwkResultCallback &&requestCallback)
    : BaseRequest(RequestType::HOST_MIX_AUTH_REQUEST, params.scheduleId, DEFAULT_REQUEST_TIMEOUT_MS, "-"),
      fwkMsg_(params.fwkMsg),
      hostUserId_(params.hostUserId),
      templateIdList_(params.templateIdList),
      tokenId_(params.tokenId),
      businessId_(params.businessId),
      authIntent_(params.authIntent),
      authScene_(params.authScene),
      title_(params.title),
      requestCallback_(std::move(requestCallback))
{
    desc_.SetTemplateIdList(templateIdList_);
    desc_.SetScheduleId(params.scheduleId);
    eventCollector_.SetHostUserId(params.hostUserId);
    eventCollector_.SetScheduleId(params.scheduleId);
    eventCollector_.SetTriggerReason("authIntent " + std::to_string(params.authIntent));
    eventCollector_.SetTemplateIdList(params.templateIdList);
}

bool HostMixAuthRequest::AnyTemplateValid() const
{
    for (auto templateId : templateIdList_) {
        auto companionStatus = GetCompanionManager().GetCompanionStatus(templateId);
        if (!companionStatus.has_value()) {
            IAM_LOGE("%{public}s templateId:%{public}s not found", GetDescription(), GET_MASKED_NUM_CSTR(templateId));
            continue;
        }
        if (!companionStatus->isValid) {
            IAM_LOGE("%{public}s templateId:%{public}s is invalid", GetDescription(), GET_MASKED_NUM_CSTR(templateId));
            continue;
        }
        return true;
    }
    return false;
}

void HostMixAuthRequest::HandleDeviceSelectResult(const std::vector<DeviceKey> &selectedDevices,
    const std::optional<std::vector<uint8_t>> &selectContext)
{
    IAM_LOGI("%{public}s HandleDeviceSelectResult size:%{public}zu", GetDescription(), selectedDevices.size());

    if (selectedDevices.empty()) {
        IAM_LOGI("%{public}s selected devices is empty, use all templates", GetDescription());
        StartAuthWithTemplateList(templateIdList_);
        return;
    }

    auto filteredList = GetFilteredTemplateList(selectedDevices);
    if (filteredList.empty()) {
        IAM_LOGE("%{public}s filtered list is empty", GetDescription());
        CompleteWithError(ResultCode::NO_VALID_CREDENTIAL);
        return;
    }

    desc_.SetTemplateIdList(filteredList);
    eventCollector_.SetTemplateIdList(filteredList);
    selectContext_ = selectContext;
    StartAuthWithTemplateList(filteredList);
}

std::vector<TemplateId> HostMixAuthRequest::GetFilteredTemplateList(const std::vector<DeviceKey> &selectedDevices)
{
    std::vector<TemplateId> result;

    for (const auto &deviceKey : selectedDevices) {
        auto companionStatus = GetCompanionManager().GetCompanionStatus(hostUserId_, deviceKey);
        if (!companionStatus.has_value()) {
            IAM_LOGE("%{public}s companion status not found for device", GetDescription());
            continue;
        }

        TemplateId templateId = companionStatus->templateId;
        if (std::find(templateIdList_.begin(), templateIdList_.end(), templateId) == templateIdList_.end()) {
            continue;
        }

        bool businessIdOk = true;
        if (businessId_.has_value()) {
            const auto &enabledBusinessIds = companionStatus->enabledBusinessIds;
            businessIdOk = std::find(enabledBusinessIds.begin(), enabledBusinessIds.end(), businessId_.value()) !=
                enabledBusinessIds.end();
        }
        if (!businessIdOk) {
            IAM_LOGE("%{public}s templateId:%{public}s business id not enabled", GetDescription(),
                GET_MASKED_NUM_CSTR(templateId));
            continue;
        }
        result.push_back(templateId);
    }

    return result;
}

void HostMixAuthRequest::StartAuthWithTemplateList(const std::vector<TemplateId> &templateList)
{
    std::vector<RequestId> subRequestIds;
    for (auto templateId : templateList) {
        auto companionStatus = GetCompanionManager().GetCompanionStatus(templateId);
        if (!companionStatus.has_value()) {
            IAM_LOGE("%{public}s GetCompanionStatus fail, templateId:%{public}s", GetDescription(),
                GET_MASKED_NUM_CSTR(templateId));
            continue;
        }
        const DeviceKey &companionDeviceKey = companionStatus->companionDeviceStatus.deviceKey;
        AuthRequestParams authParams = { .scheduleId = GetScheduleId(),
            .fwkMsg = fwkMsg_,
            .hostUserId = hostUserId_,
            .templateId = templateId,
            .authIntent = authIntent_ };
        auto hostSingleMixAuthRequest =
            GetRequestFactory().CreateHostSingleMixAuthRequest(authParams, companionDeviceKey,
                [weakSelf = weak_from_this(), templateId](ResultCode result, const std::vector<uint8_t> &extraInfo) {
                    auto self = weakSelf.lock();
                    ENSURE_OR_RETURN(self != nullptr);
                    self->HandleAuthResult(templateId, result, extraInfo);
                });
        if (hostSingleMixAuthRequest == nullptr) {
            IAM_LOGE("%{public}s factory returned nullptr for templateId:%{public}s", GetDescription(),
                GET_MASKED_NUM_CSTR(templateId));
            continue;
        }
        if (!GetRequestManager().Start(hostSingleMixAuthRequest)) {
            IAM_LOGE("%{public}s start request fail templateId:%{public}s", GetDescription(),
                GET_MASKED_NUM_CSTR(templateId));
            continue;
        }
        subRequestIds.push_back(hostSingleMixAuthRequest->GetRequestId());
        IAM_LOGI("%{public}s start request success for companion device:%{public}s", GetDescription(),
            companionStatus->GetDesc().c_str());
        requestMap_.emplace(templateId, hostSingleMixAuthRequest->GetRequestId());
    }
    desc_.SetSubRequestIdList(subRequestIds);
    if (requestMap_.empty()) {
        IAM_LOGE("%{public}s no request exist", GetDescription());
        CompleteWithError(ResultCode::GENERAL_ERROR);
        return;
    }
}

void HostMixAuthRequest::Start()
{
    StartTimeout(weak_from_this());

    if (!AnyTemplateValid()) {
        IAM_LOGE("%{public}s no valid templateId found", GetDescription());
        CompleteWithError(ResultCode::NO_VALID_CREDENTIAL);
        return;
    }

    if (!tokenId_.has_value()) {
        IAM_LOGI("%{public}s no tokenId, skip device selection, use all templates", GetDescription());
        StartAuthWithTemplateList(templateIdList_);
        return;
    }

    bool selectorSet = GetMiscManager().GetDeviceDeviceSelectResult(tokenId_.value(), SelectPurpose::SELECT_AUTH_DEVICE,
        [weakSelf = weak_from_this()](const std::vector<DeviceKey> &selectedDevices,
            const std::optional<std::vector<uint8_t>> &selectContext) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleDeviceSelectResult(selectedDevices, selectContext);
        });
    if (!selectorSet) {
        IAM_LOGE("%{public}s no device selector set", GetDescription());
        CompleteWithError(ResultCode::GENERAL_ERROR);
        return;
    }

    IAM_LOGI("%{public}s waiting for device select result", GetDescription());
}

bool HostMixAuthRequest::Cancel(ResultCode resultCode)
{
    if (cancelled_) {
        IAM_LOGI("%{public}s already cancelled, skip", GetDescription());
        return true;
    }
    cancelled_ = true;
    auto requestMap = std::move(requestMap_);
    requestMap_.clear();
    for (auto &entry : requestMap) {
        if (entry.second != 0) {
            GetRequestManager().Cancel(entry.second);
        }
    }
    CompleteWithError(resultCode);
    return true;
}

void HostMixAuthRequest::HandleAuthResult(TemplateId templateId, ResultCode result,
    const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("%{public}s templateId:%{public}s result:%{public}d", GetDescription(), GET_MASKED_NUM_CSTR(templateId),
        result);
    eventCollector_.AddTemplateAuthResult(templateId, result);

    auto it = requestMap_.find(templateId);
    if (it == requestMap_.end()) {
        IAM_LOGE("%{public}s request already released", GetDescription());
        return;
    }
    requestMap_.erase(it);
    if (result != ResultCode::SUCCESS) {
        if (requestMap_.empty()) {
            CompleteWithError(ResultCode::FAIL);
            return;
        }
        IAM_LOGE("%{public}s wait for other request result, current size:%{public}zu", GetDescription(),
            requestMap_.size());
        return;
    }
    auto requestMap = std::move(requestMap_);
    requestMap_.clear();
    for (auto &entry : requestMap) {
        if (entry.second != 0) {
            GetRequestManager().Cancel(entry.second);
        }
    }
    eventCollector_.SetSuccessTemplateId(templateId);
    CompleteWithSuccess(templateId, extraInfo);
}

uint32_t HostMixAuthRequest::GetMaxConcurrency() const
{
    return 1; // Spec: max 1 concurrent HostMixAuthRequest
}

bool HostMixAuthRequest::ShouldCancelOnNewRequest([[maybe_unused]] RequestType newRequestType,
    [[maybe_unused]] const std::optional<DeviceKey> &newPeerDevice,
    [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: HostMixAuthRequest does not preempt on new requests
    return false;
}

void HostMixAuthRequest::InvokeCallback(ResultCode result, const std::vector<uint8_t> &extraInfo)
{
    if (requestCallback_ == nullptr) {
        IAM_LOGI("%{public}s callback already sent", GetDescription());
        return;
    }
    TaskRunnerManager::GetInstance().PostTaskOnResident(
        [cb = std::move(requestCallback_), result, extra = extraInfo]() mutable {
            if (cb) {
                cb(result, extra);
            }
        });
    requestCallback_ = nullptr;
}

void HostMixAuthRequest::CompleteWithError(ResultCode result)
{
    IAM_LOGI("%{public}s complete with error: %{public}d", GetDescription(), result);
    InvokeCallback(result, {});
    eventCollector_.Report(result);
    Destroy();
}

void HostMixAuthRequest::CompleteWithSuccess(TemplateId templateId, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("%{public}s complete with success", GetDescription());
    Attributes attributes;
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_AUTH_INTENT, authIntent_);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_HOST_USER_ID, hostUserId_);
    attributes.SetUint64Value(Attributes::ATTR_CDA_SA_TEMPLATE_ID, templateId);
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_AUTH_SCENE, static_cast<int32_t>(authScene_));
    if (!title_.empty()) {
        attributes.SetStringValue(Attributes::ATTR_CDA_SA_WIDGET_TITLE, title_);
    }
    if (selectContext_) {
        attributes.SetUint8ArrayValue(Attributes::ATTR_CDA_SA_SELECT_CONTEXT, *selectContext_);
    }
    GetEventBus().Publish(EventType::AUTH_SUCCESS, attributes.Serialize());

    InvokeCallback(ResultCode::SUCCESS, extraInfo);
    eventCollector_.Report(ResultCode::SUCCESS);
    Destroy();
}

void HostMixAuthRequest::Destroy()
{
    IAM_LOGI("%{public}s destroy", GetDescription());
    BaseRequest::Destroy();
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
