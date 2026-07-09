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

#ifndef COMPANION_DEVICE_AUTH_COMPANION_REQUEST_RESYNC_REQUEST_H
#define COMPANION_DEVICE_AUTH_COMPANION_REQUEST_RESYNC_REQUEST_H

#include <memory>
#include <string>

#include "outbound_request.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class CompanionRequestResyncRequest : public std::enable_shared_from_this<CompanionRequestResyncRequest>,
                                      public OutboundRequest {
public:
    CompanionRequestResyncRequest(const DeviceKey &hostDeviceKey, const std::string &triggerReason);
    ~CompanionRequestResyncRequest() override = default;

    uint32_t GetMaxConcurrency() const override;
    bool ShouldCancelOnNewRequest(const IRequest &newRequest, uint32_t subsequentSameTypeCount) const override;

protected:
    void OnConnected() override;
    std::weak_ptr<OutboundRequest> GetWeakPtr() override;
    void CompleteWithError(ResultCode result) override;

private:
    void SendRequestDeviceResyncRequest();
    void HandleRequestDeviceResyncReply(const Attributes &message);

    void CompleteWithSuccess();
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_COMPANION_REQUEST_RESYNC_REQUEST_H
