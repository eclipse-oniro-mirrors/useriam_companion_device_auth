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

#ifndef COMPANION_DEVICE_AUTH_IREQUEST_H
#define COMPANION_DEVICE_AUTH_IREQUEST_H

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "cda_attributes.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
enum class RequestType : int32_t {
    NONE = 0,

    HOST_SYNC_DEVICE_STATUS_REQUEST = 10,

    HOST_ADD_COMPANION_REQUEST = 20,
    COMPANION_ADD_COMPANION_REQUEST = 21,

    HOST_REMOVE_HOST_BINDING_REQUEST = 30,

    HOST_ISSUE_TOKEN_REQUEST = 40,
    COMPANION_ISSUE_TOKEN_REQUEST = 41,

    COMPANION_OBTAIN_TOKEN_REQUEST = 50,
    HOST_OBTAIN_TOKEN_REQUEST = 51,

    COMPANION_REVOKE_TOKEN_REQUEST = 60,

    HOST_TOKEN_AUTH_REQUEST = 70,

    HOST_DELEGATE_AUTH_REQUEST = 80,
    COMPANION_DELEGATE_AUTH_REQUEST = 81,

    HOST_SINGLE_MIX_AUTH_REQUEST = 90,
    HOST_MIX_AUTH_REQUEST = 91,
};

class IRequest {
public:
    virtual ~IRequest() = default;

    virtual void Start() = 0;
    virtual bool Cancel(ResultCode resultCode) = 0;
    virtual RequestType GetRequestType() const = 0;
    virtual const char *GetDescription() const = 0;
    virtual RequestId GetRequestId() const = 0;
    virtual ScheduleId GetScheduleId() const = 0;

    // Get peer device key if applicable (returns nullopt if not applicable)
    virtual std::optional<DeviceKey> GetPeerDeviceKey() const = 0;
    virtual uint32_t GetMaxConcurrency() const = 0;

    virtual bool ShouldCancelOnNewRequest(RequestType newRequestType, const std::optional<DeviceKey> &newPeerDevice,
        uint32_t subsequentSameTypeCount) const = 0;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_IREQUEST_H
