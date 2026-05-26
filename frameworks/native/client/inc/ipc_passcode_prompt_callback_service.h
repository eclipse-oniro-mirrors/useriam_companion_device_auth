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

#ifndef IPC_PASSCODE_PROMPT_CALLBACK_SERVICE_H
#define IPC_PASSCODE_PROMPT_CALLBACK_SERVICE_H

#include <mutex>

#include "ipasscode_prompt_callback.h"
#include "ipc_passcode_prompt_callback_stub.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class IpcPasscodePromptCallbackService : public IpcPasscodePromptCallbackStub {
public:
    explicit IpcPasscodePromptCallbackService(const std::shared_ptr<IPasscodePromptCallback> &impl);
    ~IpcPasscodePromptCallbackService() override = default;
    int32_t OnPasscodePrompt(const sptr<IIpcPasscodeSubmitCallback> &submitCallback,
        const IpcPasscodePromptOptions &options) override;
    int32_t CallbackEnter([[maybe_unused]] uint32_t code) override;
    int32_t CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result) override;

private:
    std::shared_ptr<IPasscodePromptCallback> callback_ { nullptr };
    std::recursive_mutex mutex_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // IPC_PASSCODE_PROMPT_CALLBACK_SERVICE_H
