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

#ifndef STATUS_MONITOR_H
#define STATUS_MONITOR_H

#include <mutex>

#include "nocopyable.h"

#include "ability.h"

#include "common_defines.h"
#include "companion_device_auth_client.h"
#include "companion_device_auth_napi_helper.h"
#include "napi/native_api.h"
#include "napi_available_device_status_callback.h"
#include "napi_continuous_auth_status_callback.h"
#include "napi_template_status_callback.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class StatusMonitor : public NoCopyable {
public:
    explicit StatusMonitor(napi_env env);
    ~StatusMonitor() override = default;

    int32_t GetTemplateStatus(std::vector<ClientTemplateStatus> &clientTemplateStatusList);
    int32_t OnTemplateChange(napi_env env, napi_callback_info info);
    int32_t OffTemplateChange(napi_env env, napi_callback_info info);
    int32_t OnContinuousAuthChange(napi_env env, napi_callback_info info);
    int32_t OffContinuousAuthChange(napi_env env, napi_callback_info info);
    int32_t OnAvailableDeviceChange(napi_env env, napi_callback_info info);
    int32_t OffAvailableDeviceChange(napi_env env, napi_callback_info info);
    int32_t SetLocalUserId(napi_env env, napi_callback_info info);

private:
    int32_t SetAvailableDeviceStatusCallback(napi_env env, napi_value value);
    int32_t SetTemplateStatusCallback(napi_env env, napi_value value);
    int32_t SetContinuousAuthStatusCallback(napi_env env, napi_value paramValue, napi_value callbackValue);
    int32_t ClearAvailableDeviceStatusCallback();
    int32_t ClearTemplateStatusCallback();
    int32_t ClearContinuousAuthStatusCallback();
    int32_t RemoveSingleTemplateStatusChangedCallback(napi_env env, napi_value value);
    int32_t RemoveSingleAvailableDeviceStatusCallback(napi_env env, napi_value value);
    int32_t RemoveSingleContinuousAuthStatusCallback(napi_env env, napi_value value);
    int32_t SetContinuousAuthStatusCallbackWithTemplateId(napi_env env, uint64_t templateId,
        const std::shared_ptr<JsRefHolder> &callbackRef);
    int32_t SetContinuousAuthStatusCallbackWithoutTemplateId(napi_env env,
        const std::shared_ptr<JsRefHolder> &callbackRef);
    int32_t UpdateContinuousAuthStatusCallback(const std::shared_ptr<JsRefHolder> &callbackRef,
        const std::optional<uint64_t> templateId = std::nullopt);

    int32_t localUserId_;
    std::recursive_mutex mutex_;
    std::shared_ptr<NapiTemplateStatusCallback> templateStatusCallback_;
    std::vector<std::shared_ptr<NapiContinuousAuthStatusCallback>> continuousAuthStatusCallbacks_;
    std::shared_ptr<NapiAvailableDeviceStatusCallback> availableDeviceStatusCallback_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // STATUS_MONITOR_H