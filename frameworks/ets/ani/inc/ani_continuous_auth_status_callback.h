/**
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

#ifndef ANI_CONTINUOUS_AUTH_STATUS_CALLBACK_H
#define ANI_CONTINUOUS_AUTH_STATUS_CALLBACK_H

#include <mutex>
#include <vector>

#include "nocopyable.h"

#include "companion_device_auth_common_defines.h"
#include "icontinuous_auth_status_callback.h"
#include "ohos.userIAM.companionDeviceAuth.proj.hpp"

namespace companionDeviceAuth = ohos::userIAM::companionDeviceAuth;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
using ContinuousAuthStatusCallback = ::taihe::callback<void(bool isAuthPassed,
    ::taihe::optional_view<::ohos::userIAM::userAuth::userAuth::AuthTrustLevel> authTrustLevel)>;
using ContinuousAuthStatusCallbackPtr = std::shared_ptr<taihe::optional<ContinuousAuthStatusCallback>>;
class AniContinuousAuthStatusCallback : public IContinuousAuthStatusCallback,
                                        public std::enable_shared_from_this<AniContinuousAuthStatusCallback>,
                                        public NoCopyable {
public:
    explicit AniContinuousAuthStatusCallback();
    ~AniContinuousAuthStatusCallback() override;
    void OnContinuousAuthStatusChange(const bool isAuthPassed,
        const std::optional<int32_t> authTrustLevel = std::nullopt) override;
    int32_t GetUserId() override;
    std::optional<uint64_t> GetTemplateId() override;

    int32_t SetCallback(taihe::optional<ContinuousAuthStatusCallback> callback);
    void ClearCallback();
    bool HasCallback();
    void RemoveSingleCallback(taihe::optional<ContinuousAuthStatusCallback> callback);
    bool HasSameCallback(taihe::optional<ContinuousAuthStatusCallback> callback);
    void SetUserId(int32_t userId);
    void SetTemplateId(uint64_t templateId);

private:
    void DoCallback(ContinuousAuthStatusCallbackPtr callback, const bool isAuthPassed,
        const std::optional<int32_t> authTrustLevel = std::nullopt);

    std::recursive_mutex mutex_;
    std::vector<ContinuousAuthStatusCallbackPtr> callbacks_;
    int32_t userId_;
    std::optional<uint64_t> templateId_ { std::nullopt };
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // ANI_CONTINUOUS_AUTH_STATUS_CALLBACK_H