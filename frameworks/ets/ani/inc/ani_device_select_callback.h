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

#ifndef ANI_DEVICE_SELECT_CALLBACK_H
#define ANI_DEVICE_SELECT_CALLBACK_H

#include <mutex>

#include "nocopyable.h"

#include "companion_device_auth_common_defines.h"
#include "idevice_select_callback.h"
#include "ohos.userIAM.companionDeviceAuth.proj.hpp"

namespace companionDeviceAuth = ohos::userIAM::companionDeviceAuth;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
using DeviceSelectCallback =
    ::taihe::callback<::ohos::userIAM::companionDeviceAuth::DeviceSelectResult(int32_t selectPurpose)>;
using DeviceSelectCallbackPtr = std::shared_ptr<taihe::optional<DeviceSelectCallback>>;
class AniDeviceSelectCallback : public std::enable_shared_from_this<AniDeviceSelectCallback>,
                                public IDeviceSelectCallback,
                                public NoCopyable {
public:
    explicit AniDeviceSelectCallback();
    ~AniDeviceSelectCallback() override;
    void OnDeviceSelect(int32_t selectPurpose, const std::shared_ptr<SetDeviceSelectResultCallback> &callback) override;
    void SetCallback(taihe::optional<DeviceSelectCallback> callback);

private:
    DeviceSelectCallbackPtr GetCallback();

    std::recursive_mutex mutex_;
    DeviceSelectCallbackPtr callback_ { nullptr };
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // ANI_DEVICE_SELECT_CALLBACK_H