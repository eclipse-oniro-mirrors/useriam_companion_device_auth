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

#ifndef STATUS_MONITOR_H
#define STATUS_MONITOR_H

#include <mutex>

#include "nocopyable.h"

#include "ohos.userIAM.companionDeviceAuth.proj.hpp"

#include "ani_available_device_status_callback.h"
#include "ani_continuous_auth_status_callback.h"
#include "ani_template_status_callback.h"
#include "common_defines.h"
#include "companion_device_auth_client.h"
#include "companion_device_auth_common_defines.h"
#include "taihe/runtime.hpp"

namespace companionDeviceAuth = ohos::userIAM::companionDeviceAuth;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class StatusMonitor : public NoCopyable {
public:
    explicit StatusMonitor(int32_t localUserId);
    ~StatusMonitor() = default;

    int32_t GetTemplateStatus(std::vector<ClientTemplateStatus> &clientTemplateStatusList);
    int32_t OnTemplateChange(::taihe::callback_view<void(
            ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::TemplateStatus> templateStatusList)>
            callback);
    int32_t OffTemplateChange(::taihe::optional_view<::taihe::callback<void(
            ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::TemplateStatus> templateStatusList)>>
            callback);
    int32_t OnContinuousAuthChange(companionDeviceAuth::ContinuousAuthParam const &param,
        ::taihe::callback_view<void(bool isAuthPassed,
            ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>
            callback);
    int32_t OffContinuousAuthChange(::taihe::optional_view<::taihe::callback<void(bool isAuthPassed,
            ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>>
            callback);
    int32_t OnAvailableDeviceChange(::taihe::callback_view<void(
            ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::DeviceStatus> deviceStatusList)>
            callback);
    int32_t OffAvailableDeviceChange(::taihe::optional_view<::taihe::callback<void(
            ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::DeviceStatus> deviceStatusList)>>
            callback);
    int32_t UpdateContinuousAuthStatusCallback(companionDeviceAuth::ContinuousAuthParam const &param,
        ::taihe::callback_view<void(bool isAuthPassed,
            ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>
            callback);

private:
    std::recursive_mutex mutex_;
    int32_t localUserId_;
    std::shared_ptr<AniAvailableDeviceStatusCallback> availableDeviceStatusCallback_ { nullptr };
    std::shared_ptr<AniTemplateStatusCallback> templateStatusCallback_ { nullptr };
    std::vector<std::shared_ptr<AniContinuousAuthStatusCallback>> continuousAuthStatusCallbacks_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // STATUS_MONITOR_H