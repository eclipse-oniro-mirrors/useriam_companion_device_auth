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

#ifndef COMPANION_DEVICE_AUTH_ERROR_GUARD_H
#define COMPANION_DEVICE_AUTH_ERROR_GUARD_H

#include <functional>
#include <utility>

#include "common_defines.h"
#include "nocopyable.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class ErrorGuard : public NoCopyable {
public:
    using ErrorHandler = std::function<void(ResultCode)>;

    explicit ErrorGuard(ErrorHandler &&handler) : handler_(std::forward<ErrorHandler>(handler))
    {
    }

    ~ErrorGuard() override
    {
        if (handler_ != nullptr) {
            try {
                handler_(resultCode_);
            } catch (...) {
                return;
            }
        }
    }

    void UpdateErrorCode(ResultCode resultCode)
    {
        resultCode_ = resultCode;
    }

    void Cancel()
    {
        handler_ = nullptr;
    }

private:
    ErrorHandler handler_;
    ResultCode resultCode_ { ResultCode::GENERAL_ERROR };
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_ERROR_GUARD_H
