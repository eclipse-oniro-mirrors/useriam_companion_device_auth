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

#include "napi_template_status_callback.h"

#include "napi/native_node_api.h"
#include <uv.h>

#include "iam_logger.h"
#include "iam_ptr.h"

#include "companion_device_auth_napi_helper.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH_NAPI"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
struct TemplateStatusCallbackHolder {
    std::shared_ptr<NapiTemplateStatusCallback> callback { nullptr };
    std::vector<ClientTemplateStatus> templateStatusList {};
    napi_env env { nullptr };
};
} // namespace

NapiTemplateStatusCallback::NapiTemplateStatusCallback(napi_env env) : env_(env)
{
    if (env_ == nullptr) {
        IAM_LOGE("NapiTemplateStatusCallback get null env");
    }
}

NapiTemplateStatusCallback::~NapiTemplateStatusCallback()
{
}

bool NapiTemplateStatusCallback::IsCallbackExists(const std::shared_ptr<JsRefHolder> &callback)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);

    auto it = std::find_if(callbacks_.begin(), callbacks_.end(),
        [&callback](const std::shared_ptr<JsRefHolder> &item) { return item->Equals(callback); });

    return it != callbacks_.end();
}

ResultCode NapiTemplateStatusCallback::SetCallback(const std::shared_ptr<JsRefHolder> &callback)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (IsCallbackExists(callback)) {
        IAM_LOGI("same callback already exist");
        return SUCCESS;
    }

    callbacks_.push_back(callback);
    return SUCCESS;
}

ResultCode NapiTemplateStatusCallback::ClearCallback()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    callbacks_.clear();
    return SUCCESS;
}

bool NapiTemplateStatusCallback::HasCallback()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (callbacks_.empty()) {
        return false;
    }
    return true;
}

napi_status NapiTemplateStatusCallback::DoCallback(const std::vector<ClientTemplateStatus> templateStatusList)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (!HasCallback()) {
        return napi_ok;
    }

    napi_value templateStatusListValue =
        CompanionDeviceAuthNapiHelper::ConvertTemplateStatusListToNapiValue(env_, templateStatusList);
    if (templateStatusListValue == nullptr) {
        return napi_generic_failure;
    }

    for (size_t i = 0; i < callbacks_.size(); ++i) {
        napi_status status = CompanionDeviceAuthNapiHelper::CallVoidNapiFunc(env_, callbacks_[i]->Get(), ARGS_ONE,
            &templateStatusListValue);
        if (status != napi_ok) {
            IAM_LOGE("CallVoidNapiFunc fail at index: %{puiblic}zu", i);
        }
    }

    return napi_ok;
}

ResultCode NapiTemplateStatusCallback::RemoveSingleCallback(const std::shared_ptr<JsRefHolder> &callback)
{
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
    return SUCCESS;
}

void NapiTemplateStatusCallback::OnTemplateStatusChange(const std::vector<ClientTemplateStatus> templateStatusList)
{
    IAM_LOGI("start");
    uv_loop_s *loop = nullptr;
    napi_status napiStatus = napi_get_uv_event_loop(env_, &loop);
    if (napiStatus != napi_ok || loop == nullptr) {
        IAM_LOGE("napi_get_uv_event_loop fail");
        return;
    }
    std::shared_ptr<TemplateStatusCallbackHolder> templateStatusCallbackHolder =
        MakeShared<TemplateStatusCallbackHolder>();
    if (templateStatusCallbackHolder == nullptr) {
        IAM_LOGE("templateStatusCallbackHolder is null");
        return;
    }
    templateStatusCallbackHolder->callback = shared_from_this();
    templateStatusCallbackHolder->templateStatusList = templateStatusList;
    templateStatusCallbackHolder->env = env_;
    auto task = [templateStatusCallbackHolder]() {
        IAM_LOGD("start");
        if (templateStatusCallbackHolder == nullptr || templateStatusCallbackHolder->callback == nullptr) {
            IAM_LOGE("templateStatusCallbackHolder is invalid");
            return;
        }
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(templateStatusCallbackHolder->env, &scope);
        if (scope == nullptr) {
            IAM_LOGE("scope is invalid");
            return;
        }
        napi_status ret =
            templateStatusCallbackHolder->callback->DoCallback(templateStatusCallbackHolder->templateStatusList);
        if (ret != napi_ok) {
            IAM_LOGE("DoCallback fail ret = %{public}d", ret);
            napi_close_handle_scope(templateStatusCallbackHolder->env, scope);
            return;
        }
        napi_close_handle_scope(templateStatusCallbackHolder->env, scope);
    };
    // clang-format off
    if (napi_send_event(env_, task, napi_eprio_immediate,
        "CompanionDeviceAuthNapi::NapiTemplateStatusCallback::OnTemplateStatusChange") != napi_status::napi_ok) {
        IAM_LOGE("napi_send_event: Failed to SendEvent");
    }
    // clang-format on
}

int32_t NapiTemplateStatusCallback::GetUserId()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    return userId_;
}

void NapiTemplateStatusCallback::SetUserId(int32_t userId)
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    userId_ = userId;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
