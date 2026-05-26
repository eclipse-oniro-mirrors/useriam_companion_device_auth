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

#include "ipc_passcode_prompt_callback_service.h"

#include <memory>

#include "iam_check.h"
#include "iam_logger.h"

#include "asym_encryptor.h"
#include "passcode_submit_callback_impl.h"

#define LOG_TAG "CDA_SDK"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
IpcPasscodePromptCallbackService::IpcPasscodePromptCallbackService(const std::shared_ptr<IPasscodePromptCallback> &impl)
    : callback_(impl)
{
}

int32_t IpcPasscodePromptCallbackService::OnPasscodePrompt(const sptr<IIpcPasscodeSubmitCallback> &submitCallback,
    const IpcPasscodePromptOptions &options)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (callback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        return GENERAL_ERROR;
    }

    ENSURE_OR_RETURN_VAL(submitCallback != nullptr, GENERAL_ERROR);
    uint8_t rawAlgorithm = options.asymEncryptAlgorithm;
    ENSURE_OR_RETURN_VAL(IsValidAsymEncryptAlgorithm(rawAlgorithm), GENERAL_ERROR);
    auto algorithm = static_cast<AsymEncryptAlgorithm>(rawAlgorithm);
    std::vector<uint8_t> publicKey(options.publicKey.begin(), options.publicKey.end());
    std::unique_ptr<AsymEncryptor> encryptor = CreateAsymEncryptor(algorithm, std::move(publicKey));
    ENSURE_OR_RETURN_VAL(encryptor != nullptr, GENERAL_ERROR);
    auto submitImpl = std::make_shared<PasscodeSubmitCallbackImpl>(submitCallback, std::move(encryptor));
    ENSURE_OR_RETURN_VAL(submitImpl != nullptr, GENERAL_ERROR);
    ClientPasscodePromptParams clientOptions;
    clientOptions.challenge = options.challenge;
    callback_->OnPasscodePrompt(submitImpl, clientOptions);
    return SUCCESS;
}

int32_t IpcPasscodePromptCallbackService::CallbackEnter([[maybe_unused]] uint32_t code)
{
    IAM_LOGI("start, code:%{public}u", code);
    return SUCCESS;
}

int32_t IpcPasscodePromptCallbackService::CallbackExit([[maybe_unused]] uint32_t code, [[maybe_unused]] int32_t result)
{
    IAM_LOGI("leave, code:%{public}u, result:%{public}d", code, result);
    return SUCCESS;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
