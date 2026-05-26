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

#include "passcode_submit_callback_impl.h"

#include "iam_check.h"
#include "iam_logger.h"

#define LOG_TAG "CDA_SDK"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
PasscodeSubmitCallbackImpl::PasscodeSubmitCallbackImpl(const sptr<IIpcPasscodeSubmitCallback> &callback,
    std::unique_ptr<AsymEncryptor> encryptor)
    : callback_(callback),
      encryptor_(std::move(encryptor))
{
}

void PasscodeSubmitCallbackImpl::OnPasscodeSubmit(const std::vector<uint8_t> &passcode)
{
    IAM_LOGI("start");
    std::lock_guard<std::recursive_mutex> guard(mutex_);
    if (callback_ == nullptr) {
        IAM_LOGE("callback is nullptr");
        return;
    }

    if (encryptor_ == nullptr) {
        IAM_LOGE("no valid encryptor");
        return;
    }

    auto encryptResult = encryptor_->Encrypt(passcode);
    if (!encryptResult.has_value()) {
        IAM_LOGE("asymmetric encrypt failed");
        return;
    }

    ErrCode ret = callback_->OnPasscodeSubmit(*encryptResult);
    if (ret != ERR_OK) {
        IAM_LOGE("OnPasscodeSubmit failed, ret:%{public}d", ret);
    }
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
