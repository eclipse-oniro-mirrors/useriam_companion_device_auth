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

#include "napi/native_node_api.h"

#include "iam_logger.h"
#include "scope_guard.h"

#include "continuous_auth_status_callback_wrapper.h"
#include "companion_device_auth_napi_helper.h"

#define LOG_TAG "CDA_NAPI"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
void DoCallback(const JsRefHolder &jsRefHolder, const bool isAuthPassed, const std::optional<int32_t> authTrustLevel)
{
    IAM_LOGI("start");
    napi_handle_scope scope = nullptr;
    napi_status status = napi_open_handle_scope(jsRefHolder.GetEnv(), &scope);
    if (status != napi_ok) {
        IAM_LOGE("napi_open_handle_scope fail");
        return;
    }
    if (scope == nullptr) {
        IAM_LOGE("scope is null");
        return;
    }
    ScopeGuard scopeGuard([env = jsRefHolder.GetEnv(), scope]() { napi_close_handle_scope(env, scope); });

    napi_value argv[ARGS_TWO];
    size_t argc = ARGS_ONE;

    status = napi_get_boolean(jsRefHolder.GetEnv(), isAuthPassed, &argv[0]);
    if (status != napi_ok) {
        IAM_LOGE("napi_get_boolean fail, ret:%{public}d", status);
        return;
    }

    if (authTrustLevel.has_value()) {
        status = napi_create_int32(jsRefHolder.GetEnv(), authTrustLevel.value(), &argv[1]);
        if (status != napi_ok) {
            IAM_LOGE("napi_create_int32 fail, ret:%{public}d", status);
            return;
        }
        argc = ARGS_TWO;
    }

    status = CompanionDeviceAuthNapiHelper::CallVoidNapiFunc(jsRefHolder.GetEnv(), jsRefHolder.GetRef(), argc, argv);
    if (status != napi_ok) {
        IAM_LOGE("CallVoidNapiFunc fail");
        return;
    }
    IAM_LOGI("success");
}
} // namespace

template <>
void ContinuousAuthStatusCallbackWrapper<JsRefHolder>::OnContinuousAuthStatusChange(
    const bool isAuthPassed, const std::optional<int32_t> authTrustLevel)
{
    uv_loop_s *loop = nullptr;
    napi_status napiStatus = napi_get_uv_event_loop(this->GetCallback().GetEnv(), &loop);
    if (napiStatus != napi_ok || loop == nullptr) {
        IAM_LOGE("napi_get_uv_event_loop fail");
        return;
    }
    auto task = [jsRefHolder = this->GetCallback(), isAuthPassed, authTrustLevel]() {
        DoCallback(jsRefHolder, isAuthPassed, authTrustLevel);
    };
    if (napi_send_event(this->GetCallback().GetEnv(), task, napi_eprio_immediate,
        "ContinuousAuthStatusCallbackWrapper<JsRefHolder>::OnContinuousAuthStatusChange") !=
        napi_status::napi_ok) {
        IAM_LOGE("napi_send_event: Failed to SendEvent");
    }
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS