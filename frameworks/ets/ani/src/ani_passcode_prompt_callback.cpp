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

#include "ani_passcode_prompt_callback.h"

#include "taihe/invoke.hpp"
#include "taihe/runtime.hpp"

#include "iam_check.h"
#include "iam_logger.h"

#include "companion_device_auth_ani_helper.h"

#define LOG_TAG "CDA_ANI"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class PasscodeSubmitter {
public:
    explicit PasscodeSubmitter(std::shared_ptr<PasscodeSubmitCallback> submit) : submit_(std::move(submit))
    {
    }

    void operator()(::taihe::array_view<uint8_t> passcode)
    {
        IAM_LOGI("start");
        ENSURE_OR_RETURN(submit_ != nullptr);
        std::vector<uint8_t> passcodeVec(passcode.begin(), passcode.end());
        submit_->OnPasscodeSubmit(passcodeVec);
        IAM_LOGI("end");
    }

private:
    std::shared_ptr<PasscodeSubmitCallback> submit_;
};

AniPasscodePromptCallback::AniPasscodePromptCallback()
{
}

AniPasscodePromptCallback::~AniPasscodePromptCallback()
{
}

void AniPasscodePromptCallback::OnPasscodePrompt(const std::shared_ptr<PasscodeSubmitCallback> &submit,
    const ClientPasscodePromptParams &options)
{
    IAM_LOGI("start");
    ENSURE_OR_RETURN(submit != nullptr);
    auto passcodePromptCallback = GetCallback();
    if (passcodePromptCallback == nullptr) {
        IAM_LOGE("passcodePromptCallback is null");
        return;
    }

    // Invoked from a binder thread; attach to the ArkTS VM before calling into ArkTS.
    ::taihe::env_guard guard;
    ENSURE_OR_RETURN(guard.get_env() != nullptr);

    auto submitCb =
        taihe::make_holder<PasscodeSubmitter, ::taihe::callback<void(::taihe::array_view<uint8_t>)>>(submit);

    companionDeviceAuth::PasscodePromptOptions aniOptions = {
        taihe::array<uint8_t>(taihe::copy_data_t {}, options.challenge.data(), options.challenge.size()),
    };

    (**passcodePromptCallback)(submitCb, aniOptions);
    IAM_LOGI("end");
}

void AniPasscodePromptCallback::SetCallback(taihe::optional<PasscodePromptCallback> callback)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    callback_ = std::make_shared<taihe::optional<PasscodePromptCallback>>(callback);
}

PasscodePromptCallbackPtr AniPasscodePromptCallback::GetCallback()
{
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    return callback_;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
