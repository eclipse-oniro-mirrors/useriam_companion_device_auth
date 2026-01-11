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

#include "iam_check.h"
#include "iam_logger.h"

#include "host_delegate_auth_request.h"
#include "host_token_auth_request.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
HostSingleMixAuthRequest::HostSingleMixAuthRequest(ScheduleId scheduleId, std::vector<uint8_t> fwkMsg,
    UserId hostUserId, TemplateId templateId, FwkResultCallback &&requestCallback)
    : BaseRequest(RequestType::HOST_SINGLE_MIX_AUTH_REQUEST, scheduleId),
      fwkMsg_(fwkMsg),
      hostUserId_(hostUserId),
      templateId_(templateId),
      requestCallback_(std::move(requestCallback))
{
}

void HostSingleMixAuthRequest::Start()
{
    tokenAuthRequest_ = GetRequestFactory().CreateHostTokenAuthRequest(GetScheduleId(), fwkMsg_, hostUserId_,
        templateId_, [weakSelf = weak_from_this()](ResultCode result, const std::vector<uint8_t> &extraInfo) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleTokenAuthResult(result, extraInfo);
        });
    if (tokenAuthRequest_ == nullptr) {
        IAM_LOGE("%{public}s CreateHostTokenAuthRequest fail", GetDescription());
        CompleteWithError(ResultCode::GENERAL_ERROR);
        return;
    }
    if (!GetRequestManager().Start(tokenAuthRequest_)) {
        IAM_LOGE("tokenAuthRequest_ Start failed for templateId %{public}s", GET_TRUNCATED_STRING(templateId_).c_str());
        CompleteWithError(ResultCode::GENERAL_ERROR);
        return;
    }
}

bool HostSingleMixAuthRequest::Cancel(ResultCode resultCode)
{
    if (cancelled_) {
        IAM_LOGI("%{public}s already cancelled, skip", GetDescription());
        return true;
    }
    cancelled_ = true;
    if (tokenAuthRequest_ != nullptr) {
        tokenAuthRequest_->Cancel(resultCode);
    }
    if (delegateAuthRequest_ != nullptr) {
        delegateAuthRequest_->Cancel(resultCode);
    }
    CompleteWithError(resultCode);
    return true;
}

void HostSingleMixAuthRequest::HandleTokenAuthResult(ResultCode result, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("%{public}s result:%{public}d", GetDescription(), result);
    if (tokenAuthRequest_ == nullptr) {
        IAM_LOGE("%{public}s tokenAuthRequest_ already released", GetDescription());
        return;
    }
    tokenAuthRequest_.reset();
    if (result == ResultCode::SUCCESS) {
        CompleteWithSuccess(extraInfo);
        return;
    }
    IAM_LOGE("%{public}s token auth failed, start delegate auth", GetDescription());
    delegateAuthRequest_ = GetRequestFactory().CreateHostDelegateAuthRequest(GetScheduleId(), fwkMsg_, hostUserId_,
        templateId_, [weakSelf = weak_from_this()](ResultCode result, const std::vector<uint8_t> &extraInfo) {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            self->HandleDelegateAuthResult(result, extraInfo);
        });
    if (delegateAuthRequest_ == nullptr) {
        IAM_LOGE("%{public}s CreateHostDelegateAuthRequest fail", GetDescription());
        CompleteWithError(ResultCode::GENERAL_ERROR);
        return;
    }
    if (!GetRequestManager().Start(delegateAuthRequest_)) {
        IAM_LOGE("delegateAuthRequest_ Start failed for templateId %{public}s",
            GET_TRUNCATED_STRING(templateId_).c_str());
        CompleteWithError(ResultCode::GENERAL_ERROR);
        return;
    }
}

void HostSingleMixAuthRequest::HandleDelegateAuthResult(ResultCode result, const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("%{public}s result:%{public}d", GetDescription(), result);
    if (delegateAuthRequest_ == nullptr) {
        IAM_LOGE("%{public}s delegateAuthRequest_ already released", GetDescription());
        return;
    }
    delegateAuthRequest_.reset();
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
    [[maybe_unused]] const std::optional<DeviceKey> &newPeerDevice,
    [[maybe_unused]] uint32_t subsequentSameTypeCount) const
{
    // Spec: new HostMixAuthRequest preempts HostSingleMixAuthRequest
    if (newRequestType == RequestType::HOST_MIX_AUTH_REQUEST) {
        IAM_LOGI("%{public}s: preempted by new HostMixAuth", GetDescription());
        return true;
    }

    // Spec: new HostSingleMixAuthRequest with same templateId preempts existing one
    // Note: In practice, this would need access to the new request's templateId for comparison
    // For now, returning false to allow the manager to make the decision
    if (newRequestType == RequestType::HOST_SINGLE_MIX_AUTH_REQUEST) {
        IAM_LOGI("%{public}s: checking HostSingleMixAuth preemption", GetDescription());
        // Comparison logic for templateId should be handled at request manager level
        return false;
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
}

void HostSingleMixAuthRequest::CompleteWithError(ResultCode result)
{
    IAM_LOGI("%{public}s complete with error: %{public}d", GetDescription(), result);
    InvokeCallback(result, {});
    Destroy();
}

void HostSingleMixAuthRequest::CompleteWithSuccess(const std::vector<uint8_t> &extraInfo)
{
    IAM_LOGI("%{public}s complete with success", GetDescription());
    InvokeCallback(ResultCode::SUCCESS, extraInfo);
    Destroy();
}

void HostSingleMixAuthRequest::Destroy()
{
    IAM_LOGI("%{public}s destroy", GetDescription());
    StopTimeout();

    auto requestId = GetRequestId();
    TaskRunnerManager::GetInstance().PostTaskOnResident([requestId]() {
        GetRequestManager().Remove(requestId);
        IAM_LOGI("request %{public}u removed", requestId);
    });
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
