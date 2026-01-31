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

#ifndef CONTINUOUS_AUTH_STATUS_CALLBACK_WRAPPER_H
#define CONTINUOUS_AUTH_STATUS_CALLBACK_WRAPPER_H

#include "icontinuous_auth_status_callback.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
template <typename T>
class ContinuousAuthStatusCallbackWrapper : public IContinuousAuthStatusCallback {
public:
    ContinuousAuthStatusCallbackWrapper(T callback) : callback_(callback) {}
    ~ContinuousAuthStatusCallbackWrapper() = default;

    void OnContinuousAuthStatusChange(const bool isAuthPassed, const std::optional<int32_t> authTrustLevel) override;

    bool operator==(const ContinuousAuthStatusCallbackWrapper& other) const
    {
        return callback_ == other.GetCallback();
    }
    const T &GetCallback() const { return callback_; }

private:
    T callback_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // CONTINUOUS_AUTH_STATUS_CALLBACK_WRAPPER_H