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

#ifndef ANI_PASSCODE_PROMPT_CALLBACK_H
#define ANI_PASSCODE_PROMPT_CALLBACK_H

#include <mutex>

#include "nocopyable.h"

#include "companion_device_auth_common_defines.h"
#include "ipasscode_prompt_callback.h"
#include "ohos.userIAM.companionDeviceAuth.proj.hpp"

namespace companionDeviceAuth = ohos::userIAM::companionDeviceAuth;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
using PasscodePromptCallback = ::taihe::callback<void(::taihe::callback_view<void(::taihe::array_view<uint8_t>)>,
    const companionDeviceAuth::PasscodePromptOptions &)>;
using PasscodePromptCallbackPtr = std::shared_ptr<taihe::optional<PasscodePromptCallback>>;
class AniPasscodePromptCallback : public std::enable_shared_from_this<AniPasscodePromptCallback>,
                                  public IPasscodePromptCallback,
                                  public NoCopyable {
public:
    explicit AniPasscodePromptCallback();
    ~AniPasscodePromptCallback() override;
    void OnPasscodePrompt(const std::shared_ptr<PasscodeSubmitCallback> &submit,
        const ClientPasscodePromptParams &options) override;
    void SetCallback(taihe::optional<PasscodePromptCallback> callback);

private:
    PasscodePromptCallbackPtr GetCallback();

    std::recursive_mutex mutex_;
    PasscodePromptCallbackPtr callback_ { nullptr };
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // ANI_PASSCODE_PROMPT_CALLBACK_H
