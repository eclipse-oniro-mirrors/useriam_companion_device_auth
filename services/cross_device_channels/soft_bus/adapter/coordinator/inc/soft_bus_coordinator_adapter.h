/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef COMPANION_DEVICE_AUTH_SOFT_BUS_COORDINATOR_ADAPTER_H
#define COMPANION_DEVICE_AUTH_SOFT_BUS_COORDINATOR_ADAPTER_H

#include <functional>
#include <memory>
#include <string>

#include "nocopyable.h"

#include "service_common.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using DisconnectRequestedCallback = std::function<void(const std::string &networkId)>;
using ConnectDecisionCallback = std::function<void(bool canConnect)>;

class ISoftBusCoordinatorAdapter : public NoCopyable {
public:
    virtual ~ISoftBusCoordinatorAdapter() = default;

    virtual bool Initialize() = 0;

    virtual void RequestResource(const std::string &connectionName, const std::string &networkId,
        ConnectionMode connectionMode, ConnectDecisionCallback &&callback) = 0;
    virtual void ReleaseResource(const std::string &connectionName) = 0;
    virtual std::unique_ptr<Subscription> RegisterDisconnectRequestedCallback(
        DisconnectRequestedCallback &&callback) = 0;
    virtual void AddConnection(const std::string &connectionName, const std::string &networkId) = 0;
    virtual void RemoveConnection(const std::string &connectionName) = 0;

protected:
    ISoftBusCoordinatorAdapter() = default;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SOFT_BUS_COORDINATOR_ADAPTER_H
