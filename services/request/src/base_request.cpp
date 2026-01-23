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

#include <cinttypes>

#include "iam_check.h"
#include "iam_logger.h"

#include "misc_manager.h"
#include "relative_timer.h"
#include "request_manager.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"

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
            return "HSync";
        case RequestType::HOST_ADD_COMPANION_REQUEST:
            return "HAddC";
        case RequestType::COMPANION_ADD_COMPANION_REQUEST:
            return "CAddC";
        case RequestType::HOST_REMOVE_HOST_BINDING_REQUEST:
            return "HRmB";
        case RequestType::HOST_ISSUE_TOKEN_REQUEST:
            return "HIsT";
        case RequestType::COMPANION_ISSUE_TOKEN_REQUEST:
            return "CIsT";
        case RequestType::COMPANION_OBTAIN_TOKEN_REQUEST:
            return "CObT";
        case RequestType::HOST_OBTAIN_TOKEN_REQUEST:
            return "HObT";
        case RequestType::COMPANION_REVOKE_TOKEN_REQUEST:
            return "CRvT";
        case RequestType::HOST_TOKEN_AUTH_REQUEST:
            return "HTkA";
        case RequestType::HOST_DELEGATE_AUTH_REQUEST:
            return "HDlA";
        case RequestType::COMPANION_DELEGATE_AUTH_REQUEST:
            return "CDlA";
        case RequestType::HOST_SINGLE_MIX_AUTH_REQUEST:
            return "HMixS";
        case RequestType::HOST_MIX_AUTH_REQUEST:
            return "HMixA";
        default:
            return "?";
    }
}
} // namespace

std::string BaseRequest::GenerateDescription(RequestType requestType, RequestId requestId)
{
    return std::string("CdaRequest(") + GetRequestTypeAbbr(requestType) + "," + std::to_string(requestId) + ")";
}

std::string BaseRequest::GenerateDescription(RequestType requestType, RequestId requestId,
    const std::string &connectionName)
{
    if (connectionName.empty() || connectionName == "-") {
        return GenerateDescription(requestType, requestId);
    }
    return std::string("CdaRequest(") + GetRequestTypeAbbr(requestType) + "," + std::to_string(requestId) + "," +
        connectionName + ")";
}

BaseRequest::BaseRequest(RequestType requestType, ScheduleId scheduleId, uint32_t timeoutMs,
    const std::string &connectionName)
    : requestType_(requestType),
      scheduleId_(scheduleId),
      timeoutMs_(timeoutMs)
{
    requestId_ = static_cast<RequestId>(GetMiscManager().GetNextGlobalId());
    description_ = GenerateDescription(requestType_, requestId_, connectionName);
    StartTimeout();
}

BaseRequest::~BaseRequest()
{
    StopTimeout();
}

RequestType BaseRequest::GetRequestType() const
{
    return requestType_;
}

const char *BaseRequest::GetDescription() const
{
    return description_.c_str();
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

void BaseRequest::StartTimeout()
{
    if (timeoutMs_ == 0) {
        return;
    }

    timeoutSubscription_ = RelativeTimer::GetInstance().Register(
        [this]() {
            IAM_LOGE("%{public}s timeout", GetDescription());
            Cancel(ResultCode::TIMEOUT);
        },
        timeoutMs_);
    ENSURE_OR_RETURN(timeoutSubscription_ != nullptr);
}

void BaseRequest::StopTimeout()
{
    if (timeoutSubscription_ != nullptr) {
        timeoutSubscription_.reset();
    }
}

void BaseRequest::UpdateDescription(const std::string &newDescription)
{
    description_ = newDescription;
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
