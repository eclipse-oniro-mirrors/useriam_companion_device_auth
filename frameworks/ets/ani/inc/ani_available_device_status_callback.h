/**
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

#ifndef ANI_AVAILABLE_DEVICE_STATUS_CALLBACK_H
#define ANI_AVAILABLE_DEVICE_STATUS_CALLBACK_H

#include <mutex>
#include <vector>

#include "nocopyable.h"

#include "companion_device_auth_common_defines.h"
#include "iavailable_device_status_callback.h"
#include "ohos.userIAM.companionDeviceAuth.proj.hpp"

namespace companionDeviceAuth = ohos::userIAM::companionDeviceAuth;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
using AvailableDeviceStatusCallback =
    ::taihe::callback<void(::taihe::array_view<::ohos::userIAM::companionDeviceAuth::DeviceStatus> deviceStatusList)>;
using AvailableDeviceStatusCallbackPtr = std::shared_ptr<taihe::optional<AvailableDeviceStatusCallback>>;
class AniAvailableDeviceStatusCallback : public IAvailableDeviceStatusCallback,
                                         public std::enable_shared_from_this<AniAvailableDeviceStatusCallback>,
                                         public NoCopyable {
public:
    explicit AniAvailableDeviceStatusCallback();
    ~AniAvailableDeviceStatusCallback() override;
    void OnAvailableDeviceStatusChange(const std::vector<ClientDeviceStatus> deviceStatusList) override;
    int32_t SetCallback(taihe::optional<AvailableDeviceStatusCallback> callback);
    void ClearCallback();
    bool HasCallback();
    void RemoveSingleCallback(taihe::optional<AvailableDeviceStatusCallback> callback);

private:
    void DoCallback(const std::vector<ClientDeviceStatus> deviceStatusList, AvailableDeviceStatusCallbackPtr callback);
    bool HasSameCallback(taihe::optional<AvailableDeviceStatusCallback> callback);

    std::recursive_mutex mutex_;
    std::vector<AvailableDeviceStatusCallbackPtr> callbacks_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // ANI_AVAILABLE_DEVICE_STATUS_CALLBACK_H