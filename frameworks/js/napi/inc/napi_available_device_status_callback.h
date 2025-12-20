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

#ifndef NAPI_AVAILABLE_DEVICE_STATUS_CALLBACK_H
#define NAPI_AVAILABLE_DEVICE_STATUS_CALLBACK_H

#include <mutex>

#include "nocopyable.h"

#include "common_defines.h"
#include "companion_device_auth_napi_common.h"
#include "companion_device_auth_napi_helper.h"
#include "iavailable_device_status_callback.h"
#include "napi/native_api.h"
#include "napi/native_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class NapiAvailableDeviceStatusCallback : public IAvailableDeviceStatusCallback,
                                          public std::enable_shared_from_this<NapiAvailableDeviceStatusCallback>,
                                          public NoCopyable {
public:
    NapiAvailableDeviceStatusCallback(napi_env env);
    ~NapiAvailableDeviceStatusCallback() override;

    void OnAvailableDeviceStatusChange(const std::vector<ClientDeviceStatus> deviceStatusList) override;
    bool IsCallbackExists(const std::shared_ptr<JsRefHolder> &callback);
    napi_status DoCallback(const std::vector<ClientDeviceStatus> deviceStatusList);
    ResultCode SetCallback(const std::shared_ptr<JsRefHolder> &callback);
    ResultCode ClearCallback();
    ResultCode RemoveSingleCallback(const std::shared_ptr<JsRefHolder> &callback);
    bool HasCallback();

private:
    napi_env env_ { nullptr };
    std::recursive_mutex mutex_;
    std::vector<std::shared_ptr<JsRefHolder>> callbacks_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // NAPI_AVAILABLE_DEVICE_STATUS_CALLBACK_H