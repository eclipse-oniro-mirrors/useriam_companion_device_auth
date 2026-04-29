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

#include "request_manager_impl.h"

#include <algorithm>
#include <cinttypes>
#include <vector>

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_safe_arithmetic.h"

#include "singleton_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_REQUEST_MANAGER_IMPL

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
RequestManagerImpl::RequestManagerImpl()
{
}

std::shared_ptr<RequestManagerImpl> RequestManagerImpl::Create()
{
    auto manager = std::shared_ptr<RequestManagerImpl>(new (std::nothrow) RequestManagerImpl());
    ENSURE_OR_RETURN_VAL(manager != nullptr, nullptr);
    return manager;
}

bool RequestManagerImpl::Start(const std::shared_ptr<IRequest> &request)
{
    ENSURE_OR_RETURN_VAL(request != nullptr, false);

    constexpr size_t maxTotalRequests = 200;
    auto totalRequests = SafeAdd(waitingRequests_.size(), runningRequests_.size());
    ENSURE_OR_RETURN_VAL(totalRequests.has_value(), false);
    if (totalRequests.value() >= maxTotalRequests) {
        IAM_LOGE("total requests limit reached (%{public}zu), reject requestId:0x%{public}08X", totalRequests.value(),
            request->GetRequestId());
        return false;
    }

    RequestId requestId = request->GetRequestId();
    if (Get(requestId) != nullptr) {
        IAM_LOGE("request already exists, requestId:0x%{public}08X", requestId);
        return false;
    }

    std::vector<std::shared_ptr<IRequest>> requestToCancel;

    auto processRequests = [&request, &requestToCancel](const auto &container) {
        for (auto it = container.rbegin(); it != container.rend(); ++it) {
            const auto &existingRequest = *it;
            ENSURE_OR_CONTINUE(existingRequest != nullptr);
            if (existingRequest->ShouldCancelOnNewRequest(request->GetRequestType(), request->GetPeerDeviceKey(), 0)) {
                requestToCancel.push_back(existingRequest);
                continue;
            }
        }
    };

    processRequests(waitingRequests_);
    processRequests(runningRequests_);

    TaskRunnerManager::GetInstance().PostTaskOnResident([requestToCancel]() {
        for (auto &request : requestToCancel) {
            ENSURE_OR_CONTINUE(request != nullptr);
            request->Cancel(ResultCode::CANCELED);
        }
    });

    std::vector<std::shared_ptr<IRequest>> prevRequests;
    prevRequests.insert(prevRequests.end(), runningRequests_.begin(), runningRequests_.end());
    prevRequests.insert(prevRequests.end(), waitingRequests_.begin(), waitingRequests_.end());

    if (!request->CanStart(prevRequests)) {
        IAM_LOGI("request cannot start, enqueued requestId:0x%{public}08X", requestId);
        waitingRequests_.push_back(request);
        return true;
    }

    runningRequests_.push_back(request);
    TaskRunnerManager::GetInstance().PostTaskOnResident([request]() {
        ENSURE_OR_RETURN(request != nullptr);
        request->Start();
    });
    return true;
}

bool RequestManagerImpl::Cancel(RequestId requestId)
{
    auto request = Get(requestId);
    if (request != nullptr) {
        return request->Cancel(ResultCode::CANCELED);
    }
    IAM_LOGE("request not found, requestId:0x%{public}08X", requestId);
    return false;
}

bool RequestManagerImpl::CancelRequestByScheduleId(ScheduleId scheduleId)
{
    ENSURE_OR_RETURN_VAL(scheduleId != 0, false);

    for (const auto &request : runningRequests_) {
        ENSURE_OR_CONTINUE(request != nullptr);
        if (request->GetScheduleId() == scheduleId) {
            return request->Cancel(ResultCode::CANCELED);
        }
    }

    for (const auto &request : waitingRequests_) {
        ENSURE_OR_CONTINUE(request != nullptr);
        if (request->GetScheduleId() == scheduleId) {
            return request->Cancel(ResultCode::CANCELED);
        }
    }

    IAM_LOGE("request not found, scheduleId:0x%{public}016" PRIX64, scheduleId);
    return false;
}

void RequestManagerImpl::CancelAll()
{
    for (const auto &request : runningRequests_) {
        ENSURE_OR_CONTINUE(request != nullptr);
        RequestId requestId = request->GetRequestId();
        if (!request->Cancel(ResultCode::CANCELED)) {
            IAM_LOGE("cancel request 0x%{public}08X failed", requestId);
        }
    }

    for (const auto &request : waitingRequests_) {
        ENSURE_OR_CONTINUE(request != nullptr);
        RequestId requestId = request->GetRequestId();
        if (!request->Cancel(ResultCode::CANCELED)) {
            IAM_LOGE("cancel request 0x%{public}08X failed", requestId);
        }
    }
}

void RequestManagerImpl::Remove(RequestId requestId)
{
    auto runningIt = std::find_if(runningRequests_.begin(), runningRequests_.end(),
        [requestId](const auto &request) { return request != nullptr && request->GetRequestId() == requestId; });
    bool wasRunning = (runningIt != runningRequests_.end());
    if (wasRunning) {
        runningRequests_.erase(runningIt);
    }

    auto waitingIt = std::find_if(waitingRequests_.begin(), waitingRequests_.end(),
        [requestId](const auto &request) { return request != nullptr && request->GetRequestId() == requestId; });
    if (waitingIt != waitingRequests_.end()) {
        waitingRequests_.erase(waitingIt);
    }

    if (!wasRunning) {
        return;
    }

    std::vector<std::shared_ptr<IRequest>> prevRequests(runningRequests_.begin(), runningRequests_.end());
    std::vector<std::shared_ptr<IRequest>> toStart;

    for (auto it = waitingRequests_.begin(); it != waitingRequests_.end();) {
        const auto &waitingRequest = *it;
        if (waitingRequest == nullptr) {
            it = waitingRequests_.erase(it);
            continue;
        }
        bool canStart = waitingRequest->CanStart(prevRequests);
        prevRequests.push_back(waitingRequest);
        if (canStart) {
            toStart.push_back(waitingRequest);
            runningRequests_.push_back(waitingRequest);
            it = waitingRequests_.erase(it);
        } else {
            ++it;
        }
    }

    for (const auto &req : toStart) {
        TaskRunnerManager::GetInstance().PostTaskOnResident([req]() {
            ENSURE_OR_RETURN(req != nullptr);
            req->Start();
        });
    }
}

std::shared_ptr<IRequest> RequestManagerImpl::Get(RequestId requestId) const
{
    for (const auto &request : runningRequests_) {
        ENSURE_OR_CONTINUE(request != nullptr);
        if (request->GetRequestId() == requestId) {
            return request;
        }
    }

    for (const auto &request : waitingRequests_) {
        ENSURE_OR_CONTINUE(request != nullptr);
        if (request->GetRequestId() == requestId) {
            return request;
        }
    }

    return nullptr;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
