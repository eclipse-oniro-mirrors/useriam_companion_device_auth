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

#include <cstdint>
#include <string>

#include "nocopyable.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

enum class FaultType : uint32_t {
    NONE = 0,
};

class IEventManagerAdapter : public NoCopyable {
public:
    virtual ~IEventManagerAdapter() = default;
    virtual void ReportSystemFault(const char *fileName, uint32_t lineNum, FaultType faultType,
        std::string &faultInfo) = 0;

protected:
    IEventManagerAdapter() = default;
};

#define REPORT_SYSTEM_FAULT(faultType, faultInfo) \
    GetEventManagerAdapter().ReportSystemFault(__FILE__, __LINE__, faultType, faultInfo)

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_EVENT_MANAGER_ADAPTER_H
