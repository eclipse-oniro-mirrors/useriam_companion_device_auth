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

#ifndef COMPANION_DEVICE_AUTH_REQUEST_MANAGER_IMPL_H
#define COMPANION_DEVICE_AUTH_REQUEST_MANAGER_IMPL_H

#include <cstdint>
#include <deque>
#include <memory>

#include "irequest.h"
#include "request_manager.h"
#include "task_runner_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class RequestManagerImpl : public IRequestManager {
public:
    static std::shared_ptr<RequestManagerImpl> Create();

    ~RequestManagerImpl() override = default;

    bool Start(const std::shared_ptr<IRequest> &request) override;
    bool Cancel(RequestId requestId) override;
    bool CancelRequestByScheduleId(ScheduleId scheduleId) override;
    void CancelAll() override;
    void Remove(RequestId requestId) override;
    std::shared_ptr<IRequest> Get(RequestId requestId) const override;

private:
    RequestManagerImpl();

    std::deque<std::shared_ptr<IRequest>> runningRequests_;
    std::deque<std::shared_ptr<IRequest>> waitingRequests_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_REQUEST_MANAGER_IMPL_H
