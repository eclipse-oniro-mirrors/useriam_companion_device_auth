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

#ifndef ANI_TEMPLATE_STATUS_CALLBACK_H
#define ANI_TEMPLATE_STATUS_CALLBACK_H

#include <mutex>
#include <vector>

#include "nocopyable.h"

#include "companion_device_auth_common_defines.h"
#include "itemplate_status_callback.h"
#include "ohos.userIAM.companionDeviceAuth.proj.hpp"
#include "taihe/runtime.hpp"

namespace companionDeviceAuth = ohos::userIAM::companionDeviceAuth;

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
using TemplateStatusCallback = ::taihe::callback<void(
    ::taihe::array_view<::ohos::userIAM::companionDeviceAuth::TemplateStatus> templateStatusList)>;
using TemplateStatusCallbackPtr = std::shared_ptr<taihe::optional<TemplateStatusCallback>>;
class AniTemplateStatusCallback : public std::enable_shared_from_this<AniTemplateStatusCallback>,
                                  public ITemplateStatusCallback,
                                  public NoCopyable {
public:
    explicit AniTemplateStatusCallback();
    ~AniTemplateStatusCallback() override;
    void OnTemplateStatusChange(const std::vector<ClientTemplateStatus> templateStatusList) override;
    int32_t GetUserId() override;

    void SetCallback(taihe::optional<TemplateStatusCallback> callback);
    void ClearCallback();
    bool HasCallback();
    int32_t RemoveSingleCallback(taihe::optional<TemplateStatusCallback> callback);
    void SetUserId(int32_t userId);

private:
    void DoCallback(const std::vector<ClientTemplateStatus> templateStatusList, TemplateStatusCallbackPtr callback);
    bool HasSameCallback(taihe::optional<TemplateStatusCallback> callback);

    std::recursive_mutex mutex_;
    std::vector<TemplateStatusCallbackPtr> callbacks_;
    ani_env *env_ { nullptr };
    ani_vm *vm_ { nullptr };
    int32_t userId_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // ANI_TEMPLATE_STATUS_CALLBACK_H