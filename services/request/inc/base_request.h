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

#ifndef COMPANION_DEVICE_AUTH_BASE_REQUEST_H
#define COMPANION_DEVICE_AUTH_BASE_REQUEST_H

#include <cstdint>
#include <memory>
#include <string>

#include "irequest.h"
#include "misc_manager.h"
#include "relative_timer.h"
#include "service_common.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class BaseRequest : public IRequest {
public:
    BaseRequest(RequestType requestType, ScheduleId scheduleId, uint32_t timeoutMs, const std::string &connectionName);

    virtual ~BaseRequest();

    static std::string GenerateDescription(RequestType requestType, RequestId requestId);
    static std::string GenerateDescription(RequestType requestType, RequestId requestId,
        const std::string &connectionName);

    RequestType GetRequestType() const final override;
    const char *GetDescription() const final override;
    RequestId GetRequestId() const final override;
    ScheduleId GetScheduleId() const final override;
    std::optional<DeviceKey> GetPeerDeviceKey() const override;

protected:
    void StartTimeout();
    void StopTimeout();
    void UpdateDescription(const std::string &newDescription);
    void Destroy();
    virtual void CompleteWithError(ResultCode result) = 0;

    const RequestType requestType_;
    RequestId requestId_ = 0;
    const ScheduleId scheduleId_ = 0;
    std::string description_ = "";
    const uint32_t timeoutMs_ = 0;
    std::unique_ptr<Subscription> timeoutSubscription_;
    bool cancelled_ = false;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_BASE_REQUEST_H
