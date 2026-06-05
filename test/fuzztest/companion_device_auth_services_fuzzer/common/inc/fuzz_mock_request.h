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

#ifndef COMPANION_DEVICE_AUTH_FUZZ_MOCK_REQUEST_H
#define COMPANION_DEVICE_AUTH_FUZZ_MOCK_REQUEST_H

#include <memory>
#include <optional>
#include <vector>

#include "irequest.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class FuzzMockRequest : public IRequest {
public:
    FuzzMockRequest(RequestType requestType, std::optional<DeviceKey> peerDeviceKey)
        : requestType_(requestType),
          peerDeviceKey_(peerDeviceKey)
    {
    }

    virtual ~FuzzMockRequest() = default;

    void Start() override
    {
    }

    bool Cancel(ResultCode resultCode) override
    {
        (void)resultCode;
        return true;
    }

    RequestType GetRequestType() const override
    {
        return requestType_;
    }

    const char *GetDescription() const override
    {
        return "FuzzMockRequest";
    }

    RequestId GetRequestId() const override
    {
        return 0;
    }

    ScheduleId GetScheduleId() const override
    {
        return 0;
    }

    std::optional<DeviceKey> GetPeerDeviceKey() const override
    {
        return peerDeviceKey_;
    }

    std::optional<TemplateId> GetTemplateId() const override
    {
        return std::nullopt;
    }

    uint32_t GetMaxConcurrency() const override
    {
        return 1;
    }

    bool CanStart(const std::vector<std::shared_ptr<IRequest>> &prevRequests) const override
    {
        (void)prevRequests;
        return true;
    }

    bool ShouldCancelOnNewRequest(const IRequest &newRequest, uint32_t subsequentSameTypeCount) const override
    {
        (void)newRequest;
        (void)subsequentSameTypeCount;
        return true;
    }

private:
    RequestType requestType_;
    std::optional<DeviceKey> peerDeviceKey_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_FUZZ_MOCK_REQUEST_H
