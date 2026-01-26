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

#ifndef NAPI_CONTINUOUS_AUTH_STATUS_CALLBACK_H
#define NAPI_CONTINUOUS_AUTH_STATUS_CALLBACK_H

#include <mutex>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "nocopyable.h"

#include "common_defines.h"
#include "companion_device_auth_napi_helper.h"
#include "icontinuous_auth_status_callback.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class NapiContinuousAuthStatusCallback : public std::enable_shared_from_this<NapiContinuousAuthStatusCallback>,
                                         public IContinuousAuthStatusCallback,
                                         public NoCopyable {
public:
    NapiContinuousAuthStatusCallback(napi_env env);
    ~NapiContinuousAuthStatusCallback() override;

    void OnContinuousAuthStatusChange(const bool isAuthPassed,
        const std::optional<int32_t> authTrustLevel = std::nullopt) override;
    int32_t GetUserId() override;
    std::optional<uint64_t> GetTemplateId() override;

    napi_status DoCallback(const bool isAuthPassed, const std::optional<int32_t> authTrustLevel = std::nullopt);
    ResultCode SetCallback(const std::shared_ptr<JsRefHolder> &callback);
    ResultCode ClearCallback();
    bool HasCallback();
    ResultCode RemoveSingleCallback(const std::shared_ptr<JsRefHolder> &callback);
    bool IsCallbackExists(const std::shared_ptr<JsRefHolder> &callback);
    void SetUserId(int32_t userId);
    void SetTemplateId(uint64_t templateId);

private:
    napi_env env_ { nullptr };
    std::recursive_mutex mutex_;
    std::vector<std::shared_ptr<JsRefHolder>> callbacks_;
    int32_t userId_;
    std::optional<uint64_t> templateId_ { std::nullopt };
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // NAPI_CONTINUOUS_AUTH_STATUS_CALLBACK_H