/*
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

#include "ani_device_select_callback.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "common_defines.h"
#include "companion_device_auth_ani_helper.h"

#define LOG_TAG "CDA_ANI"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
AniDeviceSelectCallback::AniDeviceSelectCallback()
{
}

AniDeviceSelectCallback::~AniDeviceSelectCallback()
{
}

void AniDeviceSelectCallback::OnDeviceSelect(int32_t selectPurpose,
    const std::shared_ptr<SetDeviceSelectResultCallback> &callback)
{
    IAM_LOGI("start");
    ClientDeviceSelectResult result;
    auto deviceSelectCallback = GetCallback();
    if (deviceSelectCallback == nullptr) {
        IAM_LOGE("deviceSelectCallback is null");
        return;
    }
    companionDeviceAuth::DeviceSelectResult deviceSelectResult = (**deviceSelectCallback)(selectPurpose);
    taihe::array<companionDeviceAuth::DeviceKey> deviceKeys = deviceSelectResult.deviceKeys;
    result.deviceKeys = {};
    for (auto &deviceKey : deviceKeys) {
        ClientDeviceKey clientDeviceKey = CompanionDeviceAuthAniHelper::ConvertAniDeviceKey(deviceKey);
        result.deviceKeys.push_back(clientDeviceKey);
    }

    if (deviceSelectResult.selectionContext.has_value()) {
        result.selectionContext =
            CompanionDeviceAuthAniHelper::ConvertArrayToUint8Vector(deviceSelectResult.selectionContext.value());
    }

    callback->OnSetDeviceSelectResult(result);
}

void AniDeviceSelectCallback::SetCallback(taihe::optional<DeviceSelectCallback> callback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    callback_ = std::make_shared<taihe::optional<DeviceSelectCallback>>(callback);
    ENSURE_OR_RETURN(callback_ != nullptr);
}

DeviceSelectCallbackPtr AniDeviceSelectCallback::GetCallback()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    return callback_;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS