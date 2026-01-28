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

#include "status_monitor.h"

#include "iam_check.h"
#include "iam_logger.h"

#define LOG_TAG "CDA_NAPI"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
StatusMonitor::StatusMonitor(napi_env env)
    : templateStatusCallback_(std::make_shared<NapiTemplateStatusCallback>(env)),
      availableDeviceStatusCallback_(std::make_shared<NapiAvailableDeviceStatusCallback>(env))
{
}

int32_t StatusMonitor::SetLocalUserId(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    napi_value argv[ARGS_ONE];
    size_t argc = ARGS_ONE;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (status != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail, ret:%{public}d", status);
        return GENERAL_ERROR;
    }
    if (argc != ARGS_ONE) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        return GENERAL_ERROR;
    }

    int32_t userId {};
    status = CompanionDeviceAuthNapiHelper::GetInt32Value(env, argv[PARAM0], userId);
    if (status != napi_ok) {
        IAM_LOGE("GetInt32Value fail, ret:%{public}d", status);
        return GENERAL_ERROR;
    }

    bool isUserIdValid = false;
    int32_t ret = CompanionDeviceAuthClient::GetInstance().CheckLocalUserIdValid(userId, isUserIdValid);
    if (ret != SUCCESS) {
        IAM_LOGE("CheckLocalUserIdValid fail, ret:%{public}d", ret);
        return GENERAL_ERROR;
    }

    if (!isUserIdValid) {
        IAM_LOGE("input local user id is invalid");
        return USER_ID_NOT_FOUND;
    }

    localUserId_ = userId;
    templateStatusCallback_->SetUserId(userId);
    availableDeviceStatusCallback_->SetUserId(userId);
    IAM_LOGI("success");
    return SUCCESS;
}

int32_t StatusMonitor::GetTemplateStatus(std::vector<ClientTemplateStatus> &clientTemplateStatusList)
{
    IAM_LOGI("start");
    int32_t ret = CompanionDeviceAuthClient::GetInstance().GetTemplateStatus(localUserId_, clientTemplateStatusList);
    if (ret != SUCCESS) {
        IAM_LOGE("GetTemplateStatus fail, ret:%{public}d", ret);
        return ret;
    }
    IAM_LOGI("success");
    return SUCCESS;
}

int32_t StatusMonitor::OnTemplateChange(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (templateStatusCallback_ == nullptr) {
        IAM_LOGE("templateStatusCallback_ is nullptr");
        return GENERAL_ERROR;
    }

    napi_value argv[ARGS_ONE];
    size_t argc = ARGS_ONE;
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail, ret:%{public}d", ret);
        return GENERAL_ERROR;
    }
    if (argc != ARGS_ONE) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        return GENERAL_ERROR;
    }
    return SetTemplateStatusCallback(env, argv[PARAM0]);
}

int32_t StatusMonitor::OffTemplateChange(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (templateStatusCallback_ == nullptr) {
        IAM_LOGE("templateStatusCallback_ is nullptr");
        return GENERAL_ERROR;
    }

    napi_value argv[ARGS_ONE];
    size_t argc = ARGS_ONE;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (status != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail, ret:%{public}d", status);
        return GENERAL_ERROR;
    }

    if (argc == 0) {
        int32_t ret = CompanionDeviceAuthClient::GetInstance().UnsubscribeTemplateStatusChange(templateStatusCallback_);
        if (ret != SUCCESS) {
            IAM_LOGE("UnsubscribeTemplateStatusChange fail, ret:%{public}d", ret);
            return ret;
        }
        templateStatusCallback_->ClearCallback();
        IAM_LOGI("ClearCallback success");
        return SUCCESS;
    }

    if (argc != ARGS_ONE) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        return GENERAL_ERROR;
    }
    return RemoveSingleTemplateStatusChangedCallback(env, argv[PARAM0]);
}

int32_t StatusMonitor::OnAvailableDeviceChange(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (availableDeviceStatusCallback_ == nullptr) {
        IAM_LOGE("availableDeviceStatusCallback_ is nullptr");
        return GENERAL_ERROR;
    }

    napi_value argv[ARGS_ONE];
    size_t argc = ARGS_ONE;
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail, ret:%{public}d", ret);
        return GENERAL_ERROR;
    }
    if (argc != ARGS_ONE) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        return GENERAL_ERROR;
    }
    return SetAvailableDeviceStatusCallback(env, argv[PARAM0]);
}

int32_t StatusMonitor::OffAvailableDeviceChange(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (availableDeviceStatusCallback_ == nullptr) {
        IAM_LOGE("availableDeviceStatusCallback_ is nullptr");
        return GENERAL_ERROR;
    }

    napi_value argv[ARGS_ONE];
    size_t argc = ARGS_ONE;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (status != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail, ret:%{public}d", status);
        return GENERAL_ERROR;
    }

    if (argc == 0) {
        int32_t ret =
            CompanionDeviceAuthClient::GetInstance().UnsubscribeAvailableDeviceStatus(availableDeviceStatusCallback_);
        if (ret != SUCCESS) {
            IAM_LOGE("UnsubscribeAvailableDeviceStatus fail, ret:%{public}d", ret);
            return ret;
        }
        availableDeviceStatusCallback_->ClearCallback();
        IAM_LOGI("ClearCallback success");
        return SUCCESS;
    }

    if (argc != ARGS_ONE) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        return GENERAL_ERROR;
    }
    return RemoveSingleAvailableDeviceStatusCallback(env, argv[PARAM0]);
}

int32_t StatusMonitor::OnContinuousAuthChange(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    napi_value argv[ARGS_TWO];
    size_t argc = ARGS_TWO;
    napi_status ret = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (ret != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail, ret:%{public}d", ret);
        return GENERAL_ERROR;
    }
    if (argc != ARGS_TWO) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        return GENERAL_ERROR;
    }

    napi_value continuousAuthParamValue = argv[PARAM0];

    bool hasTemplateId = false;
    napi_value templateIdValue = nullptr;
    napi_status status = napi_has_named_property(env, continuousAuthParamValue, "templateId", &hasTemplateId);
    if (status != napi_ok) {
        IAM_LOGE("fail to check templateId property");
        return GENERAL_ERROR;
    }

    if (!hasTemplateId) {
        IAM_LOGI("templateId not provided in ContinuousAuthParam");
    } else {
        status = napi_get_named_property(env, continuousAuthParamValue, "templateId", &templateIdValue);
        if (status != napi_ok) {
            IAM_LOGE("fail to get templateId property");
            return GENERAL_ERROR;
        }
    }
    return SetContinuousAuthStatusCallback(env, templateIdValue, argv[PARAM1]);
}

int32_t StatusMonitor::OffContinuousAuthChange(napi_env env, napi_callback_info info)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (continuousAuthStatusCallbacks_.empty()) {
        IAM_LOGE("continuousAuthStatusCallbacks_ is empty");
        return GENERAL_ERROR;
    }

    napi_value argv[ARGS_ONE];
    size_t argc = ARGS_ONE;
    napi_status status = napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr);
    if (status != napi_ok) {
        IAM_LOGE("napi_get_cb_info fail, ret:%{public}d", status);
        return GENERAL_ERROR;
    }

    if (argc == 0) {
        for (auto &continuousAuthStatusCallback : continuousAuthStatusCallbacks_) {
            int32_t ret = CompanionDeviceAuthClient::GetInstance().UnsubscribeContinuousAuthStatusChange(
                continuousAuthStatusCallback);
            if (ret != SUCCESS) {
                IAM_LOGE("UnsubscribeContinuousAuthStatusChange fail, ret:%{public}d", ret);
                return ret;
            }
            continuousAuthStatusCallback->ClearCallback();
        }
    }
    if (argc != ARGS_ONE) {
        IAM_LOGE("invalid param, argc:%{public}zu", argc);
        return GENERAL_ERROR;
    }
    return RemoveSingleContinuousAuthStatusCallback(env, argv[PARAM0]);
}

int32_t StatusMonitor::RemoveSingleTemplateStatusChangedCallback(napi_env env, napi_value value)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    auto callbackRef = std::make_shared<JsRefHolder>(env, value);
    ENSURE_OR_RETURN_VAL(callbackRef != nullptr, INVALID_PARAMETERS);
    if (!callbackRef->IsValid()) {
        IAM_LOGE("generate callbackRef fail");
        return INVALID_PARAMETERS;
    }

    if (!templateStatusCallback_->HasCallback()) {
        IAM_LOGE("no callback registered yet");
        return GENERAL_ERROR;
    }
    int32_t ret = templateStatusCallback_->RemoveSingleCallback(callbackRef);
    if (ret != SUCCESS) {
        IAM_LOGE("RemoveSingleCallback fail, ret:%{public}d", ret);
        return ret;
    }

    if (!templateStatusCallback_->HasCallback()) {
        ret = CompanionDeviceAuthClient::GetInstance().UnsubscribeTemplateStatusChange(templateStatusCallback_);
        if (ret != SUCCESS) {
            IAM_LOGE("UnsubscribeTemplateStatusChange fail, ret:%{public}d", ret);
            return ret;
        }
    }
    IAM_LOGI("success");
    return SUCCESS;
}

int32_t StatusMonitor::RemoveSingleAvailableDeviceStatusCallback(napi_env env, napi_value value)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    auto callbackRef = std::make_shared<JsRefHolder>(env, value);
    ENSURE_OR_RETURN_VAL(callbackRef != nullptr, INVALID_PARAMETERS);
    if (!callbackRef->IsValid()) {
        IAM_LOGE("generate callbackRef fail");
        return INVALID_PARAMETERS;
    }

    if (!availableDeviceStatusCallback_->HasCallback()) {
        IAM_LOGE("no callback registered yet");
        return GENERAL_ERROR;
    }

    int32_t ret = availableDeviceStatusCallback_->RemoveSingleCallback(callbackRef);
    if (ret != SUCCESS) {
        IAM_LOGE("RemoveSingleCallback fail, ret:%{public}d", ret);
        return ret;
    }

    if (!availableDeviceStatusCallback_->HasCallback()) {
        ret = CompanionDeviceAuthClient::GetInstance().UnsubscribeAvailableDeviceStatus(availableDeviceStatusCallback_);
        if (ret != SUCCESS) {
            IAM_LOGE("UnsubscribeAvailableDeviceStatus fail, ret:%{public}d", ret);
            return ret;
        }
    }
    IAM_LOGI("success");
    return SUCCESS;
}

int32_t StatusMonitor::RemoveSingleContinuousAuthStatusCallback(napi_env env, napi_value value)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    auto callbackRef = std::make_shared<JsRefHolder>(env, value);
    ENSURE_OR_RETURN_VAL(callbackRef != nullptr, INVALID_PARAMETERS);
    if (!callbackRef->IsValid()) {
        IAM_LOGE("generate callbackRef fail");
        return INVALID_PARAMETERS;
    }

    int32_t ret = GENERAL_ERROR;
    for (auto it = continuousAuthStatusCallbacks_.begin(); it != continuousAuthStatusCallbacks_.end();) {
        if (!(*it)->HasSameCallback(callbackRef)) {
            it++;
            continue;
        }
        ret = (*it)->RemoveSingleCallback(callbackRef);
        if (ret != SUCCESS) {
            IAM_LOGE("RemoveSingleContinuousAuthStatusCallback fail, ret:%{public}d", ret);
            return GENERAL_ERROR;
        }
        if ((*it)->HasCallback()) {
            it++;
            continue;
        }
        ret = CompanionDeviceAuthClient::GetInstance().UnsubscribeContinuousAuthStatusChange(*it);
        if (ret != SUCCESS) {
            IAM_LOGE("UnsubscribeContinuousAuthStatusChange fail, ret:%{public}d", ret);
            return GENERAL_ERROR;
        }
        it = continuousAuthStatusCallbacks_.erase(it);
    }

    if (ret != SUCCESS) {
        IAM_LOGE("no same callback registered yet");
        return GENERAL_ERROR;
    }
    IAM_LOGI("success");
    return SUCCESS;
}

int32_t StatusMonitor::SetTemplateStatusCallback(napi_env env, napi_value value)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    auto callbackRef = std::make_shared<JsRefHolder>(env, value);
    ENSURE_OR_RETURN_VAL(callbackRef != nullptr, INVALID_PARAMETERS);
    if (!callbackRef->IsValid()) {
        IAM_LOGE("generate callbackRef fail");
        return INVALID_PARAMETERS;
    }

    if (!templateStatusCallback_->HasCallback()) {
        templateStatusCallback_->SetCallback(callbackRef);
        int32_t ret = CompanionDeviceAuthClient::GetInstance().SubscribeTemplateStatusChange(localUserId_,
            templateStatusCallback_);
        if (ret != SUCCESS) {
            IAM_LOGE("SubscribeTemplateStatusChange fail, ret:%{public}d", ret);
            templateStatusCallback_->ClearCallback();
            return ret;
        }
    } else {
        templateStatusCallback_->SetCallback(callbackRef);
    }

    IAM_LOGI("success");
    return SUCCESS;
}

int32_t StatusMonitor::SetAvailableDeviceStatusCallback(napi_env env, napi_value value)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    auto callbackRef = std::make_shared<JsRefHolder>(env, value);
    ENSURE_OR_RETURN_VAL(callbackRef != nullptr, INVALID_PARAMETERS);
    if (!callbackRef->IsValid()) {
        IAM_LOGE("generate callbackRef fail");
        return INVALID_PARAMETERS;
    }

    if (!availableDeviceStatusCallback_->HasCallback()) {
        availableDeviceStatusCallback_->SetCallback(callbackRef);
        int32_t ret = CompanionDeviceAuthClient::GetInstance().SubscribeAvailableDeviceStatus(localUserId_,
            availableDeviceStatusCallback_);
        if (ret != SUCCESS) {
            IAM_LOGE("SubscribeAvailableDeviceStatus fail, ret:%{public}d", ret);
            availableDeviceStatusCallback_->ClearCallback();
            return ret;
        }
    } else {
        availableDeviceStatusCallback_->SetCallback(callbackRef);
    }

    IAM_LOGI("success");
    return SUCCESS;
}

int32_t StatusMonitor::SetContinuousAuthStatusCallback(napi_env env, napi_value paramValue, napi_value callbackValue)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    auto callbackRef = std::make_shared<JsRefHolder>(env, callbackValue);
    ENSURE_OR_RETURN_VAL(callbackRef != nullptr, GENERAL_ERROR);
    if (!callbackRef->IsValid()) {
        IAM_LOGE("generate callbackRef fail");
        return GENERAL_ERROR;
    }

    if (paramValue == nullptr) {
        return SetContinuousAuthStatusCallbackWithoutTemplateId(env, callbackRef);
    }

    uint64_t templateId {};
    napi_status status = CompanionDeviceAuthNapiHelper::ConvertNapiUint8ArrayToUint64(env, paramValue, templateId);
    if (status != napi_ok) {
        IAM_LOGE("ConvertNapiUint8ArrayToUint64 fail, ret:%{public}d", status);
        return GENERAL_ERROR;
    }
    return SetContinuousAuthStatusCallbackWithTemplateId(env, templateId, callbackRef);
}

int32_t StatusMonitor::SetContinuousAuthStatusCallbackWithTemplateId(napi_env env, uint64_t templateId,
    const std::shared_ptr<JsRefHolder> &callbackRef)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    int32_t ret = UpdateContinuousAuthStatusCallback(callbackRef, templateId);
    if (ret == SUCCESS) {
        IAM_LOGI("same type callback already set");
        return ret;
    }
    IAM_LOGI("same type callback not set yet");
    auto callback = std::make_shared<NapiContinuousAuthStatusCallback>(env);
    ENSURE_OR_RETURN_VAL(callback != nullptr, GENERAL_ERROR);
    callback->SetTemplateId(templateId);
    callback->SetUserId(localUserId_);
    callback->SetCallback(callbackRef);
    continuousAuthStatusCallbacks_.push_back(callback);

    ret = CompanionDeviceAuthClient::GetInstance().SubscribeContinuousAuthStatusChange(localUserId_, callback,
        templateId);
    if (ret != SUCCESS) {
        IAM_LOGE("SubscribeContinuousAuthStatusChange fail, ret:%{public}d", ret);
        continuousAuthStatusCallbacks_.pop_back();
        return ret;
    }
    return ret;
}

int32_t StatusMonitor::SetContinuousAuthStatusCallbackWithoutTemplateId(napi_env env,
    const std::shared_ptr<JsRefHolder> &callbackRef)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    int32_t ret = UpdateContinuousAuthStatusCallback(callbackRef);
    if (ret == SUCCESS) {
        IAM_LOGI("same type callback already set");
        return ret;
    }
    IAM_LOGI("same type callback not set yet");
    auto callback = std::make_shared<NapiContinuousAuthStatusCallback>(env);
    ENSURE_OR_RETURN_VAL(callback != nullptr, GENERAL_ERROR);
    callback->SetUserId(localUserId_);
    callback->SetCallback(callbackRef);
    continuousAuthStatusCallbacks_.push_back(callback);
    ret = CompanionDeviceAuthClient::GetInstance().SubscribeContinuousAuthStatusChange(localUserId_, callback);
    if (ret != SUCCESS) {
        IAM_LOGE("SubscribeContinuousAuthStatusChange fail, ret:%{public}d", ret);
        continuousAuthStatusCallbacks_.pop_back();
        return ret;
    }
    return ret;
}

int32_t StatusMonitor::UpdateContinuousAuthStatusCallback(const std::shared_ptr<JsRefHolder> &callbackRef,
    const std::optional<uint64_t> templateId)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (!templateId.has_value()) {
        for (auto &callback : continuousAuthStatusCallbacks_) {
            if (callback->GetTemplateId().has_value()) {
                continue;
            }
            callback->SetCallback(callbackRef);
            return SUCCESS;
        }
    } else {
        uint64_t templateIdValue = templateId.value();
        for (auto &callback : continuousAuthStatusCallbacks_) {
            if (!callback->GetTemplateId().has_value()) {
                continue;
            }
            uint64_t callbackTemplateId = callback->GetTemplateId().value();
            if (callbackTemplateId != templateIdValue) {
                continue;
            }
            callback->SetCallback(callbackRef);
            return SUCCESS;
        }
    }
    return GENERAL_ERROR;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS