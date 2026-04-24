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

#include "available_device_status_callback_wrapper.h"
#include "callback_holder.h"
#include "iavailable_device_status_callback.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
template <typename T>
class AvailableDeviceStatusCallbackHolder : public IAvailableDeviceStatusCallback,
                                            public CallbackHolder<AvailableDeviceStatusCallbackWrapper<T>> {
public:
    AvailableDeviceStatusCallbackHolder() = default;
    ~AvailableDeviceStatusCallbackHolder() = default;

    void OnCallbackAdded(const std::shared_ptr<AvailableDeviceStatusCallbackWrapper<T>> &callback) override
    {
        std::lock_guard<std::recursive_mutex> lock(this->mutex_);
        if (callback != nullptr && hasCached_) {
            callback->OnAvailableDeviceStatusChange(cachedStatus_);
        }
    }

    void OnAvailableDeviceStatusChange(const std::vector<ClientDeviceStatus> deviceStatusList) override
    {
        std::vector<std::shared_ptr<AvailableDeviceStatusCallbackWrapper<T>>> callbacks;
        {
            std::lock_guard<std::recursive_mutex> lock(this->mutex_);
            cachedStatus_ = deviceStatusList;
            hasCached_ = true;
            callbacks = this->GetCallbacksUnchecked();
        }
        for (const auto &callback : callbacks) {
            if (callback != nullptr) {
                callback->OnAvailableDeviceStatusChange(deviceStatusList);
            }
        }
    }

private:
    std::vector<ClientDeviceStatus> cachedStatus_;
    bool hasCached_ = false;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // AVAILABLE_DEVICE_STATUS_CALLBACK_HOLDER_H