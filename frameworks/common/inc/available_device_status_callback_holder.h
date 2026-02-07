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

#ifndef AVAILABLE_DEVICE_STATUS_CALLBACK_HOLDER_H
#define AVAILABLE_DEVICE_STATUS_CALLBACK_HOLDER_H

#include "iavailable_device_status_callback.h"

#include "available_device_status_callback_wrapper.h"
#include "callback_holder.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
template <typename T>
class AvailableDeviceStatusCallbackHolder : public IAvailableDeviceStatusCallback,
                                            public CallbackHolder<AvailableDeviceStatusCallbackWrapper<T>> {
public:
    AvailableDeviceStatusCallbackHolder() = default;
    ~AvailableDeviceStatusCallbackHolder() = default;

    void OnAvailableDeviceStatusChange(const std::vector<ClientDeviceStatus> deviceStatusList) override
    {
        std::vector<std::shared_ptr<AvailableDeviceStatusCallbackWrapper<T>>> callbacks = this->GetCallbacks();
        for (const auto &callback : callbacks) {
            if (callback != nullptr) {
                callback->OnAvailableDeviceStatusChange(deviceStatusList);
            }
        }
    }
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // AVAILABLE_DEVICE_STATUS_CALLBACK_HOLDER_H