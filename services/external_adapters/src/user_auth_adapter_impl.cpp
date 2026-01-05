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

#include "user_auth_adapter_impl.h"

#include <memory>
#include <optional>
#include <vector>

#include "iam_logger.h"
#include "iam_para2str.h"

#include "user_auth_client.h"
#include "user_auth_client_callback.h"

#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002510
#undef LOG_TAG
#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using UserAuth::UserAuthClient;

namespace {
constexpr uint32_t DEFAULT_AUTH_TYPE = 2; // Face authentication
constexpr const char *WIDGET_TITLE = "Companion Device Auth";
} // namespace

uint64_t UserAuthAdapterImpl::BeginDelegateAuth(uint32_t userId, const std::vector<uint8_t> &challenge,
    uint32_t authTrustLevel, const std::shared_ptr<UserAuth::AuthenticationCallback> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("Callback is null");
        return 0;
    }

    if (challenge.empty()) {
        IAM_LOGE("Challenge is empty");
        return 0;
    }

    // Build WidgetAuthParam with default settings
    UserAuth::WidgetAuthParam authParam;
    authParam.userId = userId;
    authParam.challenge = challenge;
    authParam.authTrustLevel = static_cast<UserAuth::AuthTrustLevel>(authTrustLevel);
    authParam.authTypes = std::vector<UserAuth::AuthType> { static_cast<UserAuth::AuthType>(DEFAULT_AUTH_TYPE) };

    // Build WidgetParam with default settings
    UserAuth::WidgetParam widgetParam;
    widgetParam.title = WIDGET_TITLE;

    return BeginWidgetAuth(authParam, widgetParam, callback);
}

uint64_t UserAuthAdapterImpl::BeginWidgetAuth(const UserAuth::WidgetAuthParam &authParam,
    const UserAuth::WidgetParam &widgetParam, const std::shared_ptr<UserAuth::AuthenticationCallback> &callback)
{
    if (callback == nullptr) {
        IAM_LOGE("Callback is null");
        return 0;
    }

    // Call UserAuthClient directly with provided parameters
    uint64_t contextId = UserAuthClient::GetInstance().BeginWidgetAuth(authParam, widgetParam, callback);
    if (contextId == 0) {
        IAM_LOGE("BeginWidgetAuth failed");
        return 0;
    }

    IAM_LOGI("Widget auth started: contextId=%{public}s", GET_MASKED_NUM_CSTR(contextId));
    return contextId;
}

int32_t UserAuthAdapterImpl::CancelAuthentication(uint64_t contextId)
{
    if (contextId == 0) {
        IAM_LOGE("Invalid context ID");
        return -1;
    }

    int32_t ret = UserAuthClient::GetInstance().CancelAuthentication(contextId);
    if (ret != 0) {
        IAM_LOGE("CancelAuthentication failed: %{public}d", ret);
        return ret;
    }

    IAM_LOGI("CancelAuthentication success: contextId=%{public}s", GET_MASKED_NUM_CSTR(contextId));
    return 0;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
