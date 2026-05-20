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

#ifndef NAPI_PASSCODE_PROMPT_CALLBACK_H
#define NAPI_PASSCODE_PROMPT_CALLBACK_H

#include <mutex>

#include "napi/native_api.h"
#include "napi/native_common.h"
#include "nocopyable.h"

#include "companion_device_auth_napi_helper.h"
#include "ipasscode_prompt_callback.h"
#include "ipasscode_submit_callback.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class NapiPasscodePromptCallback : public std::enable_shared_from_this<NapiPasscodePromptCallback>,
                                   public IPasscodePromptCallback,
                                   public NoCopyable {
public:
    explicit NapiPasscodePromptCallback(napi_env env);
    ~NapiPasscodePromptCallback() override;

    void OnPasscodePrompt(const std::shared_ptr<PasscodeSubmitCallback> &submit,
        const ClientPasscodePromptParams &options) override;
    void SetCallback(const std::shared_ptr<JsRefHolder> &callback);

private:
    napi_env env_ = nullptr;
    std::recursive_mutex mutex_;
    std::shared_ptr<JsRefHolder> callback_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // NAPI_PASSCODE_PROMPT_CALLBACK_H
