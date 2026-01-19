/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef COMPANION_DEVICE_AUTH_SERVICE_H
#define COMPANION_DEVICE_AUTH_SERVICE_H

#include <chrono>
#include <cstdint>
#include <future>
#include <memory>
#include <mutex>
#include <optional>
#include <type_traits>
#include <vector>

#include "errors.h"
#include "nocopyable.h"
#include "system_ability.h"

#include "adapter_manager.h"
#include "common_defines.h"
#include "companion_device_auth_stub.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class CompanionDeviceAuthService : public SystemAbility, public CompanionDeviceAuthStub, public NoCopyable {
    DECLEAR_SYSTEM_ABILITY(CompanionDeviceAuthService);

public:
    CompanionDeviceAuthService();
    ~CompanionDeviceAuthService() override = default;
    static sptr<CompanionDeviceAuthService> GetInstance();

    ErrCode SubscribeAvailableDeviceStatus(int32_t localUserId,
        const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback,
        int32_t &companionDeviceAuthResult) override;

    ErrCode UnsubscribeAvailableDeviceStatus(const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback,
        int32_t &companionDeviceAuthResult) override;

    ErrCode SubscribeTemplateStatusChange(int32_t localUserId,
        const sptr<IIpcTemplateStatusCallback> &templateStatusCallback, int32_t &companionDeviceAuthResult) override;

    ErrCode UnsubscribeTemplateStatusChange(const sptr<IIpcTemplateStatusCallback> &templateStatusCallback,
        int32_t &companionDeviceAuthResult) override;

    ErrCode SubscribeContinuousAuthStatusChange(
        const IpcSubscribeContinuousAuthStatusParam &subscribeContinuousAuthStatusParam,
        const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback,
        int32_t &companionDeviceAuthResult) override;

    ErrCode UnsubscribeContinuousAuthStatusChange(
        const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback,
        int32_t &companionDeviceAuthResult) override;

    ErrCode UpdateTemplateEnabledBusinessIds(uint64_t templateId, const std::vector<int32_t> &enabledBusinessIds,
        int32_t &companionDeviceAuthResult) override;

    ErrCode GetTemplateStatus(int32_t localUserId, std::vector<IpcTemplateStatus> &templateStatusArray,
        int32_t &companionDeviceAuthResult) override;

    ErrCode RegisterDeviceSelectCallback(const sptr<IIpcDeviceSelectCallback> &deviceSelectCallback,
        int32_t &companionDeviceAuthResult) override;

    ErrCode UnregisterDeviceSelectCallback(int32_t &companionDeviceAuthResult) override;

    ErrCode CheckLocalUserIdValid(int32_t localUserId, bool &isUserIdValid,
        int32_t &companionDeviceAuthResult) override;

    int32_t CallbackEnter(uint32_t code) override;
    int32_t CallbackExit(uint32_t code, int32_t result) override;

    class CompanionDeviceAuthServiceInner;

protected:
    void OnStart() override;
    void OnStop() override;

private:
    bool CheckPermission(int32_t &companionDeviceAuthResult);

    template <typename Func>
    std::optional<typename std::invoke_result<Func>::type> RunOnResidentSync(Func &&func,
        uint32_t timeoutSec = MAX_SYNC_WAIT_TIME_SEC);

    std::shared_ptr<CompanionDeviceAuthServiceInner> inner_;
    std::mutex innerMutex_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SERVICE_H
