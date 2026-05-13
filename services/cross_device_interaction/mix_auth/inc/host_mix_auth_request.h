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

#ifndef COMPANION_DEVICE_HOST_MIX_AUTH_REQUEST_H
#define COMPANION_DEVICE_HOST_MIX_AUTH_REQUEST_H

#include <unordered_map>

#include "base_request.h"
#include "host_delegate_auth_request.h"
#include "host_token_auth_request.h"
#include "request_factory.h"
#include "request_manager.h"
#include "task_runner_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class HostMixAuthRequest : public std::enable_shared_from_this<HostMixAuthRequest>, public BaseRequest {
public:
    HostMixAuthRequest(const HostMixAuthParams &params, FwkResultCallback &&requestCallback);

    void Start() override final;
    bool Cancel(ResultCode resultCode) override final;

    uint32_t GetMaxConcurrency() const override;
    bool ShouldCancelOnNewRequest(RequestType newRequestType, const std::optional<DeviceKey> &newPeerDevice,
        uint32_t subsequentSameTypeCount) const override;

private:
    void CompleteWithError(ResultCode result) override;
    void CompleteWithSuccess(TemplateId templateId, const std::vector<uint8_t> &extraInfo);
    void Destroy();
    void InvokeCallback(ResultCode result, const std::vector<uint8_t> &extraInfo);

    void HandleAuthResult(TemplateId templateId, ResultCode result, const std::vector<uint8_t> &extraInfo);

    bool AnyTemplateValid() const;
    void HandleDeviceSelectResult(const std::vector<DeviceKey> &selectedDevices,
        const std::optional<std::vector<uint8_t>> &selectContext);
    std::vector<TemplateId> GetFilteredTemplateList(const std::vector<DeviceKey> &selectedDevices);
    void StartAuthWithTemplateList(const std::vector<TemplateId> &templateList);

    std::vector<uint8_t> fwkMsg_;
    UserId hostUserId_ = INVALID_USER_ID;
    std::vector<TemplateId> templateIdList_;
    std::optional<uint32_t> tokenId_;
    std::optional<BusinessId> businessId_;
    std::optional<std::vector<uint8_t>> selectContext_ = std::nullopt;
    int32_t authIntent_ = 0;
    UserAuth::AuthScene authScene_ {UserAuth::AUTH_SCENE_DEFAULT};
    std::string title_;
    FwkResultCallback requestCallback_;
    std::unordered_map<TemplateId, RequestId> requestMap_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_HOST_SINGLE_MIX_AUTH_REQUEST_H
