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

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
BaseRequest::BaseRequest(RequestType requestType, ScheduleId scheduleId, uint32_t timeoutMs)
    : requestType_(requestType),
      scheduleId_(scheduleId),
      timeoutMs_(timeoutMs)
{
    requestId_ = static_cast<RequestId>(GetMiscManager().GetNextGlobalId());
    description_ =
        "Request(" + std::to_string(static_cast<int32_t>(requestType)) + ":" + std::to_string(requestId_) + ")";
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

void BaseRequest::Destroy()
{
    IAM_LOGI("%{public}s destroy", GetDescription());
    StopTimeout();

    auto requestId = requestId_;
    TaskRunnerManager::GetInstance().PostTaskOnResident([requestId]() {
        GetRequestManager().Remove(requestId);
        IAM_LOGI("request %{public}" PRIu64 " removed", requestId);
    });
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
