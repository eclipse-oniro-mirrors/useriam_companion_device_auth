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

#include "iam_logger.h"

#include "available_device_status_callback_wrapper.h"
#include "companion_device_auth_ani_helper.h"

#define LOG_TAG "CDA_ANI"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
using AniAvailableDeviceStatusCallbackWrapper = AvailableDeviceStatusCallbackWrapper<
    ::taihe::callback<void(::taihe::array_view<::ohos::userIAM::companionDeviceAuth::DeviceStatus> deviceStatusList)>>;

template <>
void AniAvailableDeviceStatusCallbackWrapper::OnAvailableDeviceStatusChange(
    const std::vector<ClientDeviceStatus> deviceStatusList)
{
    IAM_LOGI("start");
    std::vector<companionDeviceAuth::DeviceStatus> temp;
    for (size_t i = 0; i < deviceStatusList.size(); ++i) {
        companionDeviceAuth::DeviceStatus deviceStatus =
            CompanionDeviceAuthAniHelper::ConvertDeviceStatus(deviceStatusList[i]);
        temp.push_back(deviceStatus);
    }
    this->GetCallback()(
        taihe::array<companionDeviceAuth::DeviceStatus>(taihe::copy_data_t {}, temp.data(), temp.size()));

    IAM_LOGI("success");
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS