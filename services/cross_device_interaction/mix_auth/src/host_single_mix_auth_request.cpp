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

#include "host_single_mix_auth_request.h"

#include <cinttypes>

#include "iam_check.h"
#include "iam_log_tracer.h"
#include "iam_logger.h"

#include "adapter_manager.h"
#include "host_delegate_auth_request.h"
#include "host_token_auth_request.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_HOST_SINGLE_MIX_AUTH_REQUEST

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
HostSingleMixAuthRequest::HostSingleMixAuthRequest(const AuthRequestParams &params, const DeviceKey &companionDeviceKey,
    FwkResultCallback &&requestCallback)
    : BaseRequest(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, params.scheduleId, DEFAULT_REQUEST_TIMEOUT_MS, "-"),
      fwkMsg_(params.fwkMsg),
      hostUserId_(params.hostUserId),
      templateId_(params.templateId),
      authIntent_(params.authIntent),
      requestCallback_(std::move(requestCallback)),
      peerDeviceKey_(companionDeviceKey)
{
    desc_.SetTemplateId(templateId_);
    eventCollector_.SetHostUserId(params.hostUserId);
    eventCollector_.SetScheduleId(params.scheduleId);
    eventCollector_.SetTriggerReason("authIntent " + std::to_string(params.authIntent));
    eventCollector_.SetTemplateIdList({ params.templateId });
}

void HostSingleMixAuthRequest::Start()
{
    LogTraceGuard guard;
    IAM_LOGI("%{public}s start", GetDescription());
    StartTimeout(weak_from_this());

    if (!GetCompanionManager().IsCapabilitySupported(templateId_, Capability::TOKEN_AUTH)) {
        IAM_LOGE("%{public}s TOKEN_AUTH capability not supported by companion device", GetDescription());
        HandleTokenAuthResult(ResultCode::GENERAL_ERROR, std::vector<uint8_t> {});
        return;
    }

    AuthRequestParams tokenAuthParams = { .scheduleId = GetScheduleId(),
        .fwkMsg = fwkMsg_,
        .hostUserId = hostUserId_,
        .templateId = templateId_,
        .authIntent = authIntent_ };
    auto tokenAuthRequest = GetRequestFactory().CreateHostTokenAuthRequest(tokenAuthParams,
        [weakSelf = weak_from_this()](ResultCode result, const std::vector<uint8_t> &extraInfo) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleTokenAuthResult(result, extraInfo);
        });
    if (tokenAuthRequest == nullptr) {
        IAM_LOGE("%{public}s CreateHostTokenAuthRequest fail", GetDescription());
        CompleteWithError(ResultCode::GENERAL_ERROR);
        return;
    }
    tokenAuthRequestId_ = tokenAuthRequest->GetRequestId();
    subRequestIds_.push_back(*tokenAuthRequestId_);
    desc_.SetSubRequestIdList(subRequestIds_);
    if (!GetRequestManager().Start(tokenAuthRequest)) {
        IAM_LOGE("%{public}s tokenAuthRequest Start failed for templateId %{public}s", GetDescription(),
            GET_MASKED_NUM_CSTR(templateId_));
        CompleteWithError(ResultCode::GENERAL_ERROR);
        return;
    }
    IAM_LOGI("%{public}s Start token auth", GetDescription());
}

bool HostSingleMixAuthRequest::Cancel(ResultCode resultCode)
{
    LogTraceGuard guard;
    IAM_LOGI("%{public}s start", GetDescription());
    if (cancelled_) {
        IAM_LOGI("%{public}s already cancelled, skip", GetDescription());
        return true;
    }
    cancelled_ = true;
    if (tokenAuthRequestId_.has_value()) {
        GetRequestManager().Cancel(*tokenAuthRequestId_);
    }
    if (delegateAuthRequestId_.has_value()) {
        GetRequestManager().Cancel(*delegateAuthRequestId_);
    }
    CompleteWithError(resultCode);
    return true;
}

std::optional<DeviceKey> HostSingleMixAuthRequest::GetPeerDeviceKey() const
{
    return peerDeviceKey_;
}

void HostSingleMixAuthRequest::HandleTokenAuthResult(ResultCode result, const std::vector<uint8_t> &extraInfo)
{
    LogTraceGuard guard;
    IAM_LOGI("%{public}s result:%{public}d", GetDescription(), result);
    if (cancelled_) {
        IAM_LOGI("%{public}s already cancelled, skip", GetDescription());
        return;
    }
    tokenAuthRequestId_.reset();
    if (result == ResultCode::SUCCESS) {
        CompleteWithSuccess(extraInfo);
        return;
    }
    if (!GetCompanionManager().IsCapabilitySupported(templateId_, Capability::DELEGATE_AUTH)) {
        IAM_LOGE("%{public}s DELEGATE_AUTH capability not supported by companion device", GetDescription());
        CompleteWithError(ResultCode::GENERAL_ERROR);
        return;
    }
    AuthRequestParams delegateAuthParams = { .scheduleId = GetScheduleId(),
        .fwkMsg = fwkMsg_,
        .hostUserId = hostUserId_,
        .templateId = templateId_,
        .authIntent = authIntent_ };
    auto delegateAuthRequest = GetRequestFactory().CreateHostDelegateAuthRequest(delegateAuthParams,
        [weakSelf = weak_from_this()](ResultCode result, const std::vector<uint8_t> &extraInfo) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleDelegateAuthResult(result, extraInfo);
        });
    if (delegateAuthRequest == nullptr) {
        IAM_LOGE("%{public}s CreateHostDelegateAuthRequest fail", GetDescription());
        CompleteWithError(ResultCode::GENERAL_ERROR);
        return;
    }
    delegateAuthRequestId_ = delegateAuthRequest->GetRequestId();
    subRequestIds_.push_back(*delegateAuthRequestId_);
    desc_.SetSubRequestIdList(subRequestIds_);
    if (!GetRequestManager().Start(delegateAuthRequest)) {
        IAM_LOGE("%{public}s delegateAuthRequest Start failed for templateId %{public}s", GetDescription(),
            GET_MASKED_NUM_CSTR(templateId_));
        CompleteWithError(ResultCode::GENERAL_ERROR);
        return;
    }
}

void HostSingleMixAuthRequest::HandleDelegateAuthResult(ResultCode result, const std::vector<uint8_t> &extraInfo)
{
    LogTraceGuard guard;
    IAM_LOGI("%{public}s result:%{public}d", GetDescription(), result);
    if (cancelled_) {
        IAM_LOGI("%{public}s already cancelled, skip", GetDescription());
        return;
    }
    delegateAuthRequestId_.reset();
    if (result != ResultCode::SUCCESS) {
        CompleteWithError(ResultCode::GENERAL_ERROR);
        return;
    }
    CompleteWithSuccess(extraInfo);
}

uint32_t HostSingleMixAuthRequest::GetMaxConcurrency() const
{
    return 10; // Spec: max 10 concurrent HostSingleMixAuthRequest
}

bool HostSingleMixAuthRequest::ShouldCancelOnNewRequest(RequestType newRequestType,
    const std::optional<DeviceKey> &newPeerDevice, [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: new HostSingleMixAuthRequest to same device preempts existing one
    if (newRequestType == RequestType::HOST_SINGLE_MIX_AUTH_REQUEST) {
        if (newPeerDevice.has_value() && peerDeviceKey_ == newPeerDevice.value()) {
            IAM_LOGI("%{public}s: preempted by new HostSingleMixAuth to same device", GetDescription());
            return true;
        }
    }

    return false;
}

void HostSingleMixAuthRequest::InvokeCallback(ResultCode result, const std::vector<uint8_t> &extraInfo)
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

void HostSingleMixAuthRequest::CompleteWithError(ResultCode result)
{
    IAM_LOGI("%{public}s complete with error: %{public}d", GetDescription(), result);
    InvokeCallback(result, {});
    eventCollector_.Report(result);
    Destroy();
}

void HostSingleMixAuthRequest::CompleteWithSuccess(const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("%{public}s complete with success", GetDescription());
    InvokeCallback(ResultCode::SUCCESS, extraInfo);
    eventCollector_.Report(ResultCode::SUCCESS);
    Destroy();
}

void HostSingleMixAuthRequest::Destroy()
{
    BaseRequest::Destroy();
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
