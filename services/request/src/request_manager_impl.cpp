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

#include "singleton_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "CDA_SA"

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

    RequestId requestId = request->GetRequestId();
    if (Get(requestId) != nullptr) {
        IAM_LOGE("request already exists, requestId:0x%{public}08X", requestId);
        return false;
    }

    uint32_t subsequentSameTypeCount = 1;
    std::vector<std::shared_ptr<IRequest>> requestToCancel;

    auto processRequests = [&subsequentSameTypeCount, &request, &requestToCancel](const auto &container) {
        for (auto it = container.rbegin(); it != container.rend(); ++it) {
            const auto &existingRequest = *it;
            ENSURE_OR_CONTINUE(existingRequest != nullptr);
            if (existingRequest->ShouldCancelOnNewRequest(request->GetRequestType(), request->GetPeerDeviceKey(), 0)) {
                requestToCancel.push_back(existingRequest);
                continue;
            }
            if (existingRequest->GetRequestType() == request->GetRequestType()) {
                subsequentSameTypeCount++;
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

    if (subsequentSameTypeCount > request->GetMaxConcurrency()) {
        IAM_LOGE("request max concurrency reached, requestId:0x%{public}08X", requestId);
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
    RequestType removedRunningType = RequestType::NONE;

    auto runningIt = std::find_if(runningRequests_.begin(), runningRequests_.end(),
        [requestId](const auto &request) { return request != nullptr && request->GetRequestId() == requestId; });
    if (runningIt != runningRequests_.end()) {
        removedRunningType = (*runningIt)->GetRequestType();
        runningRequests_.erase(runningIt);
    }

    auto waitingIt = std::find_if(waitingRequests_.begin(), waitingRequests_.end(),
        [requestId](const auto &request) { return request != nullptr && request->GetRequestId() == requestId; });
    if (waitingIt != waitingRequests_.end()) {
        waitingRequests_.erase(waitingIt);
    }

    if (removedRunningType == RequestType::NONE) {
        return;
    }

    uint32_t currentRunningCount = 0;
    for (const auto &request : runningRequests_) {
        ENSURE_OR_CONTINUE(request != nullptr);
        if (request->GetRequestType() == removedRunningType) {
            currentRunningCount++;
        }
    }

    auto itToStart = waitingRequests_.end();
    for (auto it = waitingRequests_.begin(); it != waitingRequests_.end(); ++it) {
        const auto &waitingRequest = *it;
        ENSURE_OR_CONTINUE(waitingRequest != nullptr);

        if (waitingRequest->GetRequestType() != removedRunningType) {
            continue;
        }

        if (currentRunningCount <= waitingRequest->GetMaxConcurrency()) {
            itToStart = it;
            break;
        }
    }

    std::shared_ptr<IRequest> requestToStart;
    if (itToStart != waitingRequests_.end()) {
        requestToStart = *itToStart;
        waitingRequests_.erase(itToStart);
        runningRequests_.push_back(requestToStart);
    }

    TaskRunnerManager::GetInstance().PostTaskOnResident([requestToStart]() {
        ENSURE_OR_RETURN(requestToStart != nullptr);
        requestToStart->Start();
    });
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
