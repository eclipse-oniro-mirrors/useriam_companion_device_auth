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

#ifndef COMPANION_DEVICE_AUTH_HOST_REVOKE_TOKEN_HANDLER_H
#define COMPANION_DEVICE_AUTH_HOST_REVOKE_TOKEN_HANDLER_H

#include "companion_manager.h"
#include "security_agent.h"
#include "sync_incoming_message_handler.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class HostRevokeTokenHandler : public SyncIncomingMessageHandler {
public:
    HostRevokeTokenHandler();
    ~HostRevokeTokenHandler() override = default;

#ifndef ENABLE_TEST
protected:
#endif
    void HandleRequest(const Attributes &request, Attributes &reply) override;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_HOST_REVOKE_TOKEN_HANDLER_H
