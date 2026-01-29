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

#include "napi_continuous_auth_status_callback.h"

#include "napi/native_node_api.h"
#include <uv.h>

#include "iam_check.h"
#include "iam_logger.h"
#include "scope_guard.h"

#include "companion_device_auth_napi_helper.h"

#define LOG_TAG "CDA_NAPI"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
struct ContinuousAuthStatusCallbackHolder {
    std::shared_ptr<NapiContinuousAuthStatusCallback> callback { nullptr };
    bool isAuthPassed { false };
    std::optional<int32_t> authTrustLevel { std::nullopt };
    napi_env env { nullptr };
};
} // namespace

NapiContinuousAuthStatusCallback::NapiContinuousAuthStatusCallback(napi_env env) : env_(env)
{
    if (env_ == nullptr) {
        IAM_LOGE("NapiContinuousAuthStatusCallback get null env");
    }
}

NapiContinuousAuthStatusCallback::~NapiContinuousAuthStatusCallback()
{
}

bool NapiContinuousAuthStatusCallback::HasSameCallback(const std::shared_ptr<JsRefHolder> &callback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    auto it = std::find_if(callbacks_.begin(), callbacks_.end(),
        [&callback](const std::shared_ptr<JsRefHolder> &item) { return item->Equals(callback); });

    return it != callbacks_.end();
}

void NapiContinuousAuthStatusCallback::SetCallback(const std::shared_ptr<JsRefHolder> &callback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (HasSameCallback(callback)) {
        IAM_LOGI("same callback already exist");
        return;
    }

    callbacks_.push_back(callback);
    return;
}

void NapiContinuousAuthStatusCallback::ClearCallback()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    callbacks_.clear();
    return;
}

bool NapiContinuousAuthStatusCallback::HasCallback()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (callbacks_.empty()) {
        IAM_LOGI("do not have callback");
        return false;
    }
    return true;
}

napi_status NapiContinuousAuthStatusCallback::DoCallback(const bool isAuthPassed,
    const std::optional<int32_t> authTrustLevel)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (!HasCallback()) {
        IAM_LOGI("do not have callback");
        return napi_ok;
    }

    napi_value argv[ARGS_TWO];
    size_t argc = ARGS_ONE;

    napi_status status = napi_get_boolean(env_, isAuthPassed, &argv[0]);
    if (status != napi_ok) {
        IAM_LOGE("napi_get_boolean fail, ret:%{public}d", status);
        return status;
    }

    if (authTrustLevel.has_value()) {
        status = napi_create_int32(env_, authTrustLevel.value(), &argv[1]);
        if (status != napi_ok) {
            IAM_LOGE("napi_create_int32 fail, ret:%{public}d", status);
            return status;
        }
        argc = ARGS_TWO;
    }

    for (size_t i = 0; i < callbacks_.size(); ++i) {
        ENSURE_OR_CONTINUE(callbacks_[i] != nullptr);
        status = CompanionDeviceAuthNapiHelper::CallVoidNapiFunc(env_, callbacks_[i]->Get(), argc, argv);
        if (status != napi_ok) {
            IAM_LOGE("CallVoidNapiFunc fail at index: %{public}zu", i);
        }
    }
    IAM_LOGI("end");
    return napi_ok;
}

void NapiContinuousAuthStatusCallback::OnContinuousAuthStatusChange(const bool isAuthPassed,
    const std::optional<int32_t> authTrustLevel)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    uv_loop_s *loop = nullptr;
    napi_status napiStatus = napi_get_uv_event_loop(env_, &loop);
    if (napiStatus != napi_ok || loop == nullptr) {
        IAM_LOGE("napi_get_uv_event_loop fail");
        return;
    }
    std::shared_ptr<ContinuousAuthStatusCallbackHolder> continuousAuthStatusCallbackHolder =
        std::make_shared<ContinuousAuthStatusCallbackHolder>();
    ENSURE_OR_RETURN(continuousAuthStatusCallbackHolder != nullptr);
    continuousAuthStatusCallbackHolder->callback = shared_from_this();
    continuousAuthStatusCallbackHolder->isAuthPassed = isAuthPassed;
    continuousAuthStatusCallbackHolder->authTrustLevel = authTrustLevel;
    continuousAuthStatusCallbackHolder->env = env_;
    auto task = [continuousAuthStatusCallbackHolder]() {
        if (continuousAuthStatusCallbackHolder == nullptr || continuousAuthStatusCallbackHolder->callback == nullptr) {
            IAM_LOGE("continuousAuthStatusCallbackHolder is invalid");
            return;
        }
        napi_handle_scope scope = nullptr;
        napi_status status = napi_open_handle_scope(continuousAuthStatusCallbackHolder->env, &scope);
        ENSURE_OR_RETURN(status == napi_ok);
        ENSURE_OR_RETURN(scope != nullptr);
        ScopeGuard scopeGuard([&]() { napi_close_handle_scope(continuousAuthStatusCallbackHolder->env, scope); });
        ENSURE_OR_RETURN(continuousAuthStatusCallbackHolder->callback != nullptr);
        napi_status ret = continuousAuthStatusCallbackHolder->callback->DoCallback(
            continuousAuthStatusCallbackHolder->isAuthPassed, continuousAuthStatusCallbackHolder->authTrustLevel);
        if (ret != napi_ok) {
            IAM_LOGE("DoCallback fail ret = %{public}d", ret);
            return;
        }
    };
    // clang-format off
    if (napi_send_event(env_, task, napi_eprio_immediate,
        "CompanionDeviceAuthNapi::NapiContinuousAuthStatusCallback::OnContinuousAuthStatusChange") !=
        napi_status::napi_ok) {
        IAM_LOGE("napi_send_event: Failed to SendEvent");
    }
    // clang-format on
    IAM_LOGI("end");
}

int32_t NapiContinuousAuthStatusCallback::RemoveSingleCallback(const std::shared_ptr<JsRefHolder> &callback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (callback == nullptr) {
        IAM_LOGE("callback is null");
        return GENERAL_ERROR;
    }

    auto it = std::find_if(callbacks_.begin(), callbacks_.end(),
        [&callback](const std::shared_ptr<JsRefHolder> &item) { return item->Equals(callback); });
    if (it == callbacks_.end()) {
        IAM_LOGE("fail to find callback");
        return GENERAL_ERROR;
    }
    callbacks_.erase(it);
    IAM_LOGI("success");
    return SUCCESS;
}

int32_t NapiContinuousAuthStatusCallback::GetUserId()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    return userId_;
}

void NapiContinuousAuthStatusCallback::SetUserId(int32_t userId)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    userId_ = userId;
}

std::optional<uint64_t> NapiContinuousAuthStatusCallback::GetTemplateId()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    return templateId_;
}

void NapiContinuousAuthStatusCallback::SetTemplateId(uint64_t templateId)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    templateId_ = templateId;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
