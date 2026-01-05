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

/**
 * @file continuous_auth_status_callback.h
 *
 * @brief Callback invoked when continuous authentication results change.
 */

#ifndef ICONTINUOUS_AUTH_STATUS_CALLBACK_H
#define ICONTINUOUS_AUTH_STATUS_CALLBACK_H

#include <iostream>
#include <optional>

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class IContinuousAuthStatusCallback {
public:
    /**
     * @brief Callback invoked when continuous authentication results change.
     *
     * @param isAuthPassed Whether the continuous authentication passes.
     * @param authTrustLevel Optional trust level when passed.
     */
    virtual void OnContinuousAuthStatusChange(const bool isAuthPassed,
        const std::optional<int32_t> authTrustLevel = std::nullopt) = 0;

    /**
     * @brief Get user identifier for callback.
     *
     * @return user identifier.
     */
    virtual int32_t GetUserId() = 0;

    /**
     * @brief Get template identifier (optional) for callback.
     *
     * @return Template identifier (optional).
     */
    virtual std::optional<uint64_t> GetTemplateId() = 0;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // ICONTINUOUS_AUTH_STATUS_CALLBACK_H