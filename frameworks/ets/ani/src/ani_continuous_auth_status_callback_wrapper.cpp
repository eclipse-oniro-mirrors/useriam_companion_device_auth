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

#include "companion_device_auth_ani_helper.h"
#include "continuous_auth_status_callback_wrapper.h"

#define LOG_TAG "CDA_ANI"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
using AniContinuousAuthStatusCallbackWrapper = ContinuousAuthStatusCallbackWrapper<::taihe::callback<void(
    bool isAuthPassed, ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>>;

template <>
void AniContinuousAuthStatusCallbackWrapper::OnContinuousAuthStatusChange(const bool isAuthPassed,
    const std::optional<int32_t> authTrustLevel)
{
    ::taihe::optional<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> optAuthTrustLevel = std::nullopt;
    if (authTrustLevel) {
        IAM_LOGI("authTrustLevel:%{public}d", *authTrustLevel);
        if (!CompanionDeviceAuthAniHelper::IsAuthTrustLevelValid(*authTrustLevel)) {
            IAM_LOGE("invalid atl");
            return;
        }
        optAuthTrustLevel = ::taihe::optional<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel>(std::in_place,
            CompanionDeviceAuthAniHelper::ConvertAuthTrustLevel(*authTrustLevel));
    }
    this->GetCallback()(isAuthPassed, optAuthTrustLevel);

    IAM_LOGI("success");
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS