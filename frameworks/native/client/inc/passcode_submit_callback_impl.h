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

#ifndef PASSCODE_SUBMIT_CALLBACK_IMPL_H
#define PASSCODE_SUBMIT_CALLBACK_IMPL_H

#include <memory>
#include <mutex>
#include <vector>

#include "asym_encryptor.h"
#include "ipasscode_submit_callback.h"
#include "ipc_passcode_submit_callback_proxy.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class PasscodeSubmitCallbackImpl : public PasscodeSubmitCallback {
public:
    explicit PasscodeSubmitCallbackImpl(const sptr<IIpcPasscodeSubmitCallback> &callback,
        std::unique_ptr<AsymEncryptor> encryptor);
    ~PasscodeSubmitCallbackImpl() override = default;
    void OnPasscodeSubmit(const std::vector<uint8_t> &passcode) override;

private:
    sptr<IIpcPasscodeSubmitCallback> callback_ { nullptr };
    std::recursive_mutex mutex_;
    std::unique_ptr<AsymEncryptor> encryptor_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // PASSCODE_SUBMIT_CALLBACK_IMPL_H
