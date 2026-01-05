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

#ifndef COMPANION_DEVICE_AUTH_REQUEST_MANAGER_H
#define COMPANION_DEVICE_AUTH_REQUEST_MANAGER_H

#include <cstdint>
#include <memory>
#include <vector>

#include "nocopyable.h"

#include "irequest.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class IRequestManager : public NoCopyable {
public:
    virtual ~IRequestManager() = default;

    virtual bool Start(const std::shared_ptr<IRequest> &request) = 0;
    virtual bool Cancel(RequestId requestId) = 0;
    virtual bool CancelRequestByScheduleId(ScheduleId scheduleId) = 0;
    virtual void CancelAll() = 0;
    virtual void Remove(RequestId requestId) = 0;
    virtual std::shared_ptr<IRequest> Get(RequestId requestId) const = 0;

#ifndef ENABLE_TEST
protected:
#endif
    IRequestManager() = default;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_REQUEST_MANAGER_H
