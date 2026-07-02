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

#include "napi_passcode_prompt_callback.h"

#include "napi/native_node_api.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "companion_device_auth_napi_helper.h"

#define LOG_TAG "CDA_NAPI"
#define LOG_FILE_ID LOG_FILE_NAPI_PASSCODE_PROMPT_CALLBACK

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
namespace {
struct SubmitCallbackData {
    std::shared_ptr<PasscodeSubmitCallback> submit;
};

napi_value SubmitFunc(napi_env env, napi_callback_info info)
{
    size_t argc = ARGS_ONE;
    napi_value argv[ARGS_ONE] = { nullptr };
    void *data = nullptr;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, nullptr, &data);
    if (status != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail");
        return nullptr;
    }
    if (argc != ARGS_ONE) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        return nullptr;
    }
    auto *cbData = static_cast<SubmitCallbackData *>(data);
    if (cbData == nullptr || cbData->submit == nullptr) {
        IAM_LOGE("submit callback data is null");
        return nullptr;
    }
    std::vector<uint8_t> passcode;
    if (argv[PARAM0] == nullptr) {
        IAM_LOGE("passcode argument is null, skipping submit");
        return nullptr;
    }
    status = CompanionDeviceAuthNapiHelper::GetUint8ArrayValue(env, argv[PARAM0], passcode);
    if (status != napi_ok) {
        IAM_LOGE("GetUint8ArrayValue for passcode fail, status:%{public}d", static_cast<int>(status));
        return nullptr;
    }
    IAM_LOGI("submit passcode, len:%{public}zu", passcode.size());
    cbData->submit->OnPasscodeSubmit(passcode);
    return nullptr;
}

void FinalizeSubmitCallbackData(napi_env env, void *data, void *hint)
{
    (void)env;
    (void)hint;
    if (data == nullptr) {
        IAM_LOGE("data is nullptr");
        return;
    }
    auto *cbData = static_cast<SubmitCallbackData *>(data);
    delete cbData;
}

struct PasscodePromptHolder {
    std::shared_ptr<NapiPasscodePromptCallback> callback { nullptr };
    std::shared_ptr<PasscodeSubmitCallback> submitCallback;
    ClientPasscodePromptParams options;
    std::shared_ptr<JsRefHolder> jsCallback;
    napi_env env { nullptr };
};

napi_value CreateSubmitFunction(napi_env env, const std::shared_ptr<PasscodeSubmitCallback> &submit)
{
    auto *cbData = new (std::nothrow) SubmitCallbackData();
    if (cbData == nullptr) {
        IAM_LOGE("fail to allocate SubmitCallbackData");
        return nullptr;
    }
    cbData->submit = submit;

    napi_value submitFunc = nullptr;
    napi_status status = napi_create_function(env, "submitFunc", NAPI_AUTO_LENGTH, SubmitFunc, cbData, &submitFunc);
    if (status != napi_ok) {
        IAM_LOGE("napi_create_function fail, ret:%{public}d", status);
        delete cbData;
        return nullptr;
    }

    status = napi_add_finalizer(env, submitFunc, cbData, FinalizeSubmitCallbackData, nullptr, nullptr);
    if (status != napi_ok) {
        IAM_LOGE("napi_add_finalizer fail, ret:%{public}d", status);
        delete cbData;
        return nullptr;
    }
    return submitFunc;
}

void DoPasscodePrompt(std::shared_ptr<PasscodePromptHolder> holder)
{
    IAM_LOGI("start");
    if (holder == nullptr || holder->submitCallback == nullptr || holder->jsCallback == nullptr) {
        IAM_LOGE("holder or submitCallback or jsCallback is invalid");
        return;
    }
    napi_handle_scope scope = nullptr;
    napi_open_handle_scope(holder->env, &scope);
    if (scope == nullptr) {
        IAM_LOGE("scope is invalid");
        return;
    }

    napi_value submitFunc = CreateSubmitFunction(holder->env, holder->submitCallback);
    if (submitFunc == nullptr) {
        napi_close_handle_scope(holder->env, scope);
        return;
    }

    napi_value optionsObj = nullptr;
    napi_status status = napi_create_object(holder->env, &optionsObj);
    if (status != napi_ok) {
        IAM_LOGE("napi_create_object fail");
        napi_close_handle_scope(holder->env, scope);
        return;
    }
    CompanionDeviceAuthNapiHelper::SetUint8ArrayProperty(holder->env, optionsObj, "challenge",
        holder->options.challenge);

    napi_value args[ARGS_TWO] = { submitFunc, optionsObj };
    status = CompanionDeviceAuthNapiHelper::CallVoidNapiFunc(holder->env, holder->jsCallback->GetRef(), ARGS_TWO, args);
    if (status != napi_ok) {
        IAM_LOGE("CallVoidNapiFunc fail, ret:%{public}d", status);
    }
    napi_close_handle_scope(holder->env, scope);
    IAM_LOGI("end");
}
} // namespace

NapiPasscodePromptCallback::NapiPasscodePromptCallback(napi_env env) : env_(env)
{
    if (env_ == nullptr) {
        IAM_LOGE("NapiPasscodePromptCallback get null env");
    }
}

NapiPasscodePromptCallback::~NapiPasscodePromptCallback()
{
}

void NapiPasscodePromptCallback::SetCallback(const std::shared_ptr<JsRefHolder> &callback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    callback_ = callback;
}

void NapiPasscodePromptCallback::OnPasscodePrompt(const std::shared_ptr<PasscodeSubmitCallback> &submit,
    const ClientPasscodePromptParams &options)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (callback_ == nullptr) {
        IAM_LOGE("callback_ is null");
        return;
    }
    if (submit == nullptr) {
        IAM_LOGE("submit is null");
        return;
    }
    auto holder = std::make_shared<PasscodePromptHolder>();
    ENSURE_OR_RETURN(holder != nullptr);
    holder->callback = shared_from_this();
    holder->submitCallback = submit;
    holder->options = options;
    holder->jsCallback = callback_;
    holder->env = env_;
    auto task = [holder]() { DoPasscodePrompt(holder); };
    // clang-format off
    if (napi_send_event(env_, task, napi_eprio_immediate,
        "CompanionDeviceAuthNapi::NapiPasscodePromptCallback::OnPasscodePrompt") != napi_status::napi_ok) {
        IAM_LOGE("napi_send_event: Failed to SendEvent");
    }
    // clang-format on
    IAM_LOGI("end");
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
