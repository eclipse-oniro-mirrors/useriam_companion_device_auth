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

#include "base_request.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "misc_manager.h"
#include "relative_timer.h"
#include "request_manager.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_BASE_REQUEST

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

namespace {
static const char *GetRequestTypeAbbr(RequestType requestType)
{
    switch (requestType) {
        case RequestType::NONE:
            return "-";
        case RequestType::HOST_SYNC_DEVICE_STATUS_REQUEST:
            return "RHSync";
        case RequestType::HOST_ADD_COMPANION_REQUEST:
            return "RHAddC";
        case RequestType::COMPANION_ADD_COMPANION_REQUEST:
            return "RCAddC";
        case RequestType::HOST_REMOVE_HOST_BINDING_REQUEST:
            return "RHRmB";
        case RequestType::HOST_ISSUE_TOKEN_REQUEST:
            return "RHIsT";
        case RequestType::COMPANION_ISSUE_TOKEN_REQUEST:
            return "RCIsT";
        case RequestType::COMPANION_OBTAIN_TOKEN_REQUEST:
            return "RCObT";
        case RequestType::HOST_OBTAIN_TOKEN_REQUEST:
            return "RHObT";
        case RequestType::COMPANION_REVOKE_TOKEN_REQUEST:
            return "RCRvT";
        case RequestType::HOST_TOKEN_AUTH_REQUEST:
            return "RHTkA";
        case RequestType::HOST_DELEGATE_AUTH_REQUEST:
            return "RHDlA";
        case RequestType::COMPANION_DELEGATE_AUTH_REQUEST:
            return "RCDlA";
        case RequestType::HOST_SINGLE_MIX_AUTH_REQUEST:
            return "RHMixS";
        case RequestType::HOST_MIX_AUTH_REQUEST:
            return "RHMixA";
        default:
            return "?";
    }
}
} // namespace

BaseRequest::BaseRequest(RequestType requestType, ScheduleId scheduleId, uint32_t timeoutMs,
    const std::string &connectionName)
    : eventCollector_(GetRequestTypeAbbr(requestType)),
      requestType_(requestType),
      scheduleId_(scheduleId),
      timeoutMs_(timeoutMs)
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    requestId_ = static_cast<RequestId>(GetMiscManager().GetNextGlobalId());
    desc_ = InteractionDesc(REQUEST_PREFIX, GetRequestTypeAbbr(requestType_));
    desc_.SetRequestId(requestId_);
    if (!connectionName.empty() && connectionName != "-") {
        desc_.SetConnectionName(connectionName);
    }
    IAM_LOGI("created request %{public}s", GetDescription());
}

BaseRequest::~BaseRequest()
{
    CHECK_RUNNING_ON_RESIDENT_THREAD();
    StopTimeout();
}

RequestType BaseRequest::GetRequestType() const
{
    return requestType_;
}

const char *BaseRequest::GetDescription() const
{
    return desc_.GetCStr();
}

RequestId BaseRequest::GetRequestId() const
{
    return requestId_;
}

ScheduleId BaseRequest::GetScheduleId() const
{
    return scheduleId_;
}

std::optional<DeviceKey> BaseRequest::GetPeerDeviceKey() const
{
    return std::nullopt;
}

std::optional<TemplateId> BaseRequest::GetTemplateId() const
{
    return templateId_;
}

uint32_t BaseRequest::CountSameType(const std::vector<std::shared_ptr<IRequest>> &prevRequests) const
{
    uint32_t sameTypeCount = 0;
    for (const auto &req : prevRequests) {
        if (req != nullptr && req->GetRequestType() == GetRequestType()) {
            sameTypeCount++;
        }
    }
    return sameTypeCount;
}

bool BaseRequest::CanStart(const std::vector<std::shared_ptr<IRequest>> &prevRequests) const
{
    return CountSameType(prevRequests) < GetMaxConcurrency();
}

void BaseRequest::StartTimeout(std::weak_ptr<BaseRequest> weakSelf)
{
    if (timeoutMs_ == 0) {
        return;
    }

    timeoutSubscription_ = RelativeTimer::GetInstance().Register(
        [weakSelf]() {
            auto self = weakSelf.lock();
            ENSURE_OR_RETURN(self != nullptr);
            IAM_LOGE("%{public}s timeout", self->GetDescription());
            self->Cancel(ResultCode::TIMEOUT);
        },
        timeoutMs_);
    ENSURE_OR_RETURN_DESC(GetDescription(), timeoutSubscription_ != nullptr);
}

void BaseRequest::StopTimeout()
{
    if (timeoutSubscription_ != nullptr) {
        timeoutSubscription_.reset();
    }
}

void BaseRequest::Destroy()
{
    IAM_LOGI("%{public}s destroy", GetDescription());
    StopTimeout();

    TaskRunnerManager::GetInstance().PostTaskOnResident([requestId = requestId_]() {
        GetRequestManager().Remove(requestId);
        IAM_LOGI("request 0x%{public}08X removed", requestId);
    });
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
