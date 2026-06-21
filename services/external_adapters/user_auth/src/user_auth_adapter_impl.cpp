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
#include <vector>

#include "ipc_skeleton.h"

#include "iam_check.h"
#include "iam_logger.h"
#include "iam_para2str.h"

#include "service_common.h"
#include "task_runner_manager.h"
#include "token_setproc.h"
#include "user_auth_client.h"
#include "user_auth_client_callback.h"
#include "xcollie_helper.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_USER_AUTH_ADAPTER_IMPL

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

using UserAuth::UserAuthClient;

namespace {
class AuthCallbackBridge : public UserAuth::AuthenticationCallback {
public:
    explicit AuthCallbackBridge(AuthResultCallback callback) : callback_(std::move(callback))
    {
    }
    virtual ~AuthCallbackBridge() = default;

    void OnResult(int32_t result, const UserAuth::Attributes &extraInfo) override
    {
        if (!callback_) {
            IAM_LOGE("Callback is null");
            return;
        }
        std::vector<uint8_t> token;
        if (result != UserAuth::ResultCode::SUCCESS) {
            PostCallbackToResident(result, token);
            return;
        }
        if (!extraInfo.GetUint8ArrayValue(UserAuth::Attributes::AttributeKey::ATTR_SIGNATURE, token)) {
            IAM_LOGE("Get token fail");
            PostCallbackToResident(UserAuth::ResultCode::GENERAL_ERROR, token);
            return;
        }
        PostCallbackToResident(result, token);
    }

    void PostCallbackToResident(int32_t result, const std::vector<uint8_t> &token)
    {
        TaskRunnerManager::GetInstance().PostTaskOnResident([cb = callback_, result, tokenCopy = token]() {
            if (cb) {
                cb(result, tokenCopy);
            }
        });
    }

    void OnAcquireInfo(int32_t module, uint32_t acquireInfo, const UserAuth::Attributes &extraInfo) override
    {
        (void)module;
        (void)acquireInfo;
        (void)extraInfo;
    }

private:
    AuthResultCallback callback_;
};
} // namespace

uint64_t UserAuthAdapterImpl::BeginDelegateAuth(const BeginDelegateAuthParam &param)
{
    if (!param.callback) {
        IAM_LOGE("Callback is null");
        return 0;
    }

    if (param.authTypes.empty()) {
        IAM_LOGE("AuthTypes is empty");
        return 0;
    }

    if (param.challenge.empty()) {
        IAM_LOGE("Challenge is empty");
        return 0;
    }

    UserAuth::WidgetAuthParam authParam;
    authParam.userId = param.userId;
    authParam.challenge = param.challenge;
    authParam.authTrustLevel = static_cast<UserAuth::AuthTrustLevel>(param.authTrustLevel);
    for (auto type : param.authTypes) {
        authParam.authTypes.push_back(static_cast<UserAuth::AuthType>(type));
    }
    authParam.remoteTokenId = param.remoteTokenId;

    UserAuth::WidgetParam widgetParam = {};
    widgetParam.title = "Delegate Authentication";
    widgetParam.navigationButtonText = param.navigationButtonText;
    widgetParam.windowMode = UserAuth::WindowModeType::UNKNOWN_WINDOW_MODE;

    // Create bridge callback
    auto authCallback = std::make_shared<AuthCallbackBridge>(std::move(param.callback));
    ENSURE_OR_RETURN_VAL(authCallback != nullptr, 0);
    XCollieHelper xcollie("UserAuthAdapterImpl-BeginDelegateAuth", API_CALL_TIMEOUT);

    SetFirstCallerTokenID(IPCSkeleton::GetCallingTokenID());
    uint64_t contextId = UserAuthClient::GetInstance().BeginWidgetAuth(authParam, widgetParam, authCallback);
    SetFirstCallerTokenID(0);

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

    XCollieHelper xcollie("UserAuthAdapterImpl-CancelAuthentication", API_CALL_TIMEOUT);

    SetFirstCallerTokenID(IPCSkeleton::GetCallingTokenID());
    int32_t ret = UserAuthClient::GetInstance().CancelAuthentication(contextId);
    SetFirstCallerTokenID(0);

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
