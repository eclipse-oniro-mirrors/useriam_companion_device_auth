/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef BASE_SERVICE_CORE_H
#define BASE_SERVICE_CORE_H

#include <cstdint>
#include <memory>
#include <vector>

#include "iremote_object.h"
#include "nocopyable.h"

#include "common_defines.h"
#include "companion_device_auth_stub.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class SubscriptionManager;
class BaseServiceCore : public NoCopyable {
public:
    static std::shared_ptr<BaseServiceCore> Create(const std::shared_ptr<SubscriptionManager> &subscriptionManager,
        const std::vector<BusinessId> &supportedBusinessIds);

    ResultCode SubscribeAvailableDeviceStatus(int32_t localUserId,
        const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback);
    ResultCode UnsubscribeAvailableDeviceStatus(const sptr<IIpcAvailableDeviceStatusCallback> &deviceStatusCallback);
    ResultCode SubscribeTemplateStatusChange(int32_t localUserId,
        const sptr<IIpcTemplateStatusCallback> &templateStatusCallback);
    ResultCode UnsubscribeTemplateStatusChange(const sptr<IIpcTemplateStatusCallback> &templateStatusCallback);
    ResultCode SubscribeContinuousAuthStatusChange(
        const IpcSubscribeContinuousAuthStatusParam &subscribeContinuousAuthStatusParam,
        const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback);
    ResultCode UnsubscribeContinuousAuthStatusChange(
        const sptr<IIpcContinuousAuthStatusCallback> &continuousAuthStatusCallback);
    ResultCode UpdateTemplateEnabledBusinessIds(uint64_t templateId, const std::vector<int32_t> &enabledBusinessIds);
    ResultCode GetTemplateStatus(int32_t localUserId, std::vector<IpcTemplateStatus> &templateStatusArray);
    ResultCode RegisterDeviceSelectCallback(uint32_t tokenId,
        const sptr<IIpcDeviceSelectCallback> &deviceSelectCallback);
    ResultCode UnregisterDeviceSelectCallback(uint32_t tokenId);
    ResultCode RegisterPasscodePromptCallback(uint32_t tokenId,
        const sptr<IIpcPasscodePromptCallback> &passcodePromptCallback);
    ResultCode UnregisterPasscodePromptCallback(uint32_t tokenId);
    bool CheckLocalUserIdValid(int32_t localUserId);

private:
    explicit BaseServiceCore(std::shared_ptr<SubscriptionManager> subscriptionManager,
        const std::vector<BusinessId> &supportedBusinessIds);

    bool IsValidBusinessId(BusinessId businessId) const;

    std::shared_ptr<SubscriptionManager> subscriptionManager_;
    std::vector<BusinessId> supportedBusinessIds_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // BASE_SERVICE_CORE_H
