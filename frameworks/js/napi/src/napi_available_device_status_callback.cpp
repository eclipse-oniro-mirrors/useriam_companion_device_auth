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

#include "napi_available_device_status_callback.h"

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
struct AvailableDeviceStatusCallbackHolder {
    std::shared_ptr<NapiAvailableDeviceStatusCallback> callback { nullptr };
    std::vector<ClientDeviceStatus> deviceStatusList {};
    napi_env env { nullptr };
};
} // namespace
NapiAvailableDeviceStatusCallback::NapiAvailableDeviceStatusCallback(napi_env env) : env_(env)
{
    if (env_ == nullptr) {
        IAM_LOGE("NapiAvailableDeviceStatusCallback get null env");
    }
}

NapiAvailableDeviceStatusCallback::~NapiAvailableDeviceStatusCallback()
{
}

bool NapiAvailableDeviceStatusCallback::HasSameCallback(const std::shared_ptr<JsRefHolder> &callback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    auto it = std::find_if(callbacks_.begin(), callbacks_.end(),
        [&callback](const std::shared_ptr<JsRefHolder> &item) { return item->Equals(callback); });

    return it != callbacks_.end();
}

void NapiAvailableDeviceStatusCallback::SetCallback(const std::shared_ptr<JsRefHolder> &callback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (HasSameCallback(callback)) {
        IAM_LOGI("same callback already exist");
        return;
    }
    callbacks_.push_back(callback);
}

void NapiAvailableDeviceStatusCallback::ClearCallback()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    callbacks_.clear();
}

bool NapiAvailableDeviceStatusCallback::HasCallback()
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (callbacks_.empty()) {
        IAM_LOGI("do not have callback");
        return false;
    }
    return true;
}

napi_status NapiAvailableDeviceStatusCallback::DoCallback(const std::vector<ClientDeviceStatus> deviceStatusList)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (!HasCallback()) {
        IAM_LOGI("do not have callback");
        return napi_ok;
    }

    napi_value deviceStatusListValue =
        CompanionDeviceAuthNapiHelper::ConvertDeviceStatusListToNapiValue(env_, deviceStatusList);
    if (deviceStatusListValue == nullptr) {
        IAM_LOGE("ConvertDeviceStatusListToNapiValue fail");
        return napi_generic_failure;
    }

    for (size_t i = 0; i < callbacks_.size(); ++i) {
        ENSURE_OR_CONTINUE(callbacks_[i] != nullptr);
        napi_status status = CompanionDeviceAuthNapiHelper::CallVoidNapiFunc(env_, callbacks_[i]->Get(), ARGS_ONE,
            &deviceStatusListValue);
        if (status != napi_ok) {
            IAM_LOGE("CallVoidNapiFunc fail at index:%{public}zu", i);
        }
    }

    IAM_LOGI("end");
    return napi_ok;
}

int32_t NapiAvailableDeviceStatusCallback::RemoveSingleCallback(const std::shared_ptr<JsRefHolder> &callback)
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

void NapiAvailableDeviceStatusCallback::OnAvailableDeviceStatusChange(
    const std::vector<ClientDeviceStatus> deviceStatusList)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    uv_loop_s *loop = nullptr;
    napi_status napiStatus = napi_get_uv_event_loop(env_, &loop);
    if (napiStatus != napi_ok || loop == nullptr) {
        IAM_LOGE("napi_get_uv_event_loop fail");
        return;
    }
    std::shared_ptr<AvailableDeviceStatusCallbackHolder> availableDeviceStatusCallbackHolder =
        std::make_shared<AvailableDeviceStatusCallbackHolder>();
    ENSURE_OR_RETURN(availableDeviceStatusCallbackHolder != nullptr);
    availableDeviceStatusCallbackHolder->callback = shared_from_this();
    availableDeviceStatusCallbackHolder->deviceStatusList = deviceStatusList;
    availableDeviceStatusCallbackHolder->env = env_;
    auto task = [availableDeviceStatusCallbackHolder]() {
        if (availableDeviceStatusCallbackHolder == nullptr ||
            availableDeviceStatusCallbackHolder->callback == nullptr) {
            IAM_LOGE("availableDeviceStatusCallbackHolder is invalid");
            return;
        }
        napi_handle_scope scope = nullptr;
        napi_status status = napi_open_handle_scope(availableDeviceStatusCallbackHolder->env, &scope);
        ENSURE_OR_RETURN(status == napi_ok);
        ENSURE_OR_RETURN(scope != nullptr);
        ScopeGuard scopeGuard([&]() { napi_close_handle_scope(availableDeviceStatusCallbackHolder->env, scope); });
        ENSURE_OR_RETURN(availableDeviceStatusCallbackHolder->callback != nullptr);
        napi_status ret = availableDeviceStatusCallbackHolder->callback->DoCallback(
            availableDeviceStatusCallbackHolder->deviceStatusList);
        if (ret != napi_ok) {
            IAM_LOGE("DoCallback fail ret = %{public}d", ret);
            return;
        }
    };
    // clang-format off
    if (napi_send_event(env_, task, napi_eprio_immediate,
        "CompanionDeviceAuthNapi::NapiAvailableDeviceStatusCallback::OnAvailableDeviceStatusChange") !=
        napi_status::napi_ok) {
        IAM_LOGE("napi_send_event: Failed to SendEvent");
    }
    // clang-format on
}

int32_t NapiAvailableDeviceStatusCallback::GetUserId()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    return userId_;
}

void NapiAvailableDeviceStatusCallback::SetUserId(int32_t userId)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    userId_ = userId;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
