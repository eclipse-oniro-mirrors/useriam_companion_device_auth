/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_REQUEST_H
#define COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_REQUEST_H

#include <memory>
#include <optional>

#include "irequest.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class MockIRequest : public IRequest {
public:
    MockIRequest(RequestType requestType = RequestType::HOST_ADD_COMPANION_REQUEST, RequestId requestId = 1,
        ScheduleId scheduleId = 0)
        : requestType_(requestType),
          requestId_(requestId),
          scheduleId_(scheduleId),
          description_("MockRequest"),
          maxConcurrency_(1),
          shouldCancel_(false),
          peerDeviceKey_(std::nullopt),
          cancelReturnValue_(true)
    {
    }

    virtual ~MockIRequest() = default;

    void Start() override
    {
    }

    bool Cancel(ResultCode resultCode) override
    {
        (void)resultCode;
        return cancelReturnValue_;
    }

    RequestType GetRequestType() const override
    {
        return requestType_;
    }

    const char *GetDescription() const override
    {
        return description_;
    }

    RequestId GetRequestId() const override
    {
        return requestId_;
    }

    ScheduleId GetScheduleId() const override
    {
        return scheduleId_;
    }

    std::optional<DeviceKey> GetPeerDeviceKey() const override
    {
        return peerDeviceKey_;
    }

    uint32_t GetMaxConcurrency() const override
    {
        return maxConcurrency_;
    }

    bool ShouldCancelOnNewRequest(RequestType newRequestType, const std::optional<DeviceKey> &newPeerDevice,
        uint32_t subsequentSameTypeCount) const override
    {
        (void)newRequestType;
        (void)newPeerDevice;
        (void)subsequentSameTypeCount;
        return shouldCancel_;
    }

    // Setter methods for test configuration
    void SetRequestType(RequestType requestType)
    {
        requestType_ = requestType;
    }

    void SetRequestId(RequestId requestId)
    {
        requestId_ = requestId;
    }

    void SetScheduleId(ScheduleId scheduleId)
    {
        scheduleId_ = scheduleId;
    }

    void SetDescription(const char *description)
    {
        description_ = description;
    }

    void SetMaxConcurrency(uint32_t maxConcurrency)
    {
        maxConcurrency_ = maxConcurrency;
    }

    void SetShouldCancel(bool shouldCancel)
    {
        shouldCancel_ = shouldCancel;
    }

    void SetPeerDeviceKey(const std::optional<DeviceKey> &deviceKey)
    {
        peerDeviceKey_ = deviceKey;
    }

    void SetCancelReturnValue(bool returnValue)
    {
        cancelReturnValue_ = returnValue;
    }

private:
    RequestType requestType_;
    RequestId requestId_;
    ScheduleId scheduleId_;
    const char *description_;
    uint32_t maxConcurrency_;
    bool shouldCancel_;
    std::optional<DeviceKey> peerDeviceKey_;
    bool cancelReturnValue_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TEST_UNITTEST_SERVICES_MOCK_REQUEST_H
