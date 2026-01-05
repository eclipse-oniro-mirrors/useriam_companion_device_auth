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

#ifndef NAPI_TEMPLATE_STATUS_CALLBACK_H
#define NAPI_TEMPLATE_STATUS_CALLBACK_H

#include <mutex>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "nocopyable.h"

#include "common_defines.h"
#include "companion_device_auth_napi_helper.h"
#include "itemplate_status_callback.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class NapiTemplateStatusCallback : public ITemplateStatusCallback,
                                   public std::enable_shared_from_this<NapiTemplateStatusCallback>,
                                   public NoCopyable {
public:
    NapiTemplateStatusCallback(napi_env env);
    ~NapiTemplateStatusCallback() override;

    void OnTemplateStatusChange(const std::vector<ClientTemplateStatus> templateStatusList) override;
    int32_t GetUserId() override;

    bool IsCallbackExists(const std::shared_ptr<JsRefHolder> &callback);
    napi_status DoCallback(const std::vector<ClientTemplateStatus> templateStatusList);
    ResultCode SetCallback(const std::shared_ptr<JsRefHolder> &callback);
    ResultCode ClearCallback();
    ResultCode RemoveSingleCallback(const std::shared_ptr<JsRefHolder> &callback);
    bool HasCallback();
    void SetUserId(int32_t userId);

private:
    napi_env env_ { nullptr };
    std::recursive_mutex mutex_;
    std::vector<std::shared_ptr<JsRefHolder>> callbacks_;
    int32_t userId_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // NAPI_TEMPLATE_STATUS_CALLBACK_H