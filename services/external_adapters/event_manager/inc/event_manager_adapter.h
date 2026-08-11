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

#ifndef COMPANION_DEVICE_AUTH_EVENT_MANAGER_ADAPTER_H
#define COMPANION_DEVICE_AUTH_EVENT_MANAGER_ADAPTER_H

#include <string>

#include "interaction_event_collector.h"
#include "nocopyable.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class IEventManagerAdapter : public NoCopyable {
public:
    virtual ~IEventManagerAdapter() = default;
    virtual void ReportSystemFault(std::string faultType, std::string faultId, std::string faultInfo) = 0;
    virtual void ReportInteractionEvent(const InteractionEventCollector &eventCollector) = 0;

protected:
    IEventManagerAdapter() = default;
};

void ReportSystemFault(std::string faultType, std::string faultId, std::string faultInfo);
void ReportInteractionEvent(const InteractionEventCollector &eventCollector);

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_EVENT_MANAGER_ADAPTER_H
