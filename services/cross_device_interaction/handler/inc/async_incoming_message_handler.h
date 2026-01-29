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

#ifndef COMPANION_DEVICE_AUTH_ASYNC_INCOMING_MESSAGE_HANDLER_H
#define COMPANION_DEVICE_AUTH_ASYNC_INCOMING_MESSAGE_HANDLER_H

#include <memory>

#include "cross_device_comm_manager.h"
#include "incoming_message_handler.h"
#include "subscription.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class AsyncIncomingMessageHandler : public IncomingMessageHandler {
public:
    explicit AsyncIncomingMessageHandler(MessageType messageType);
    ~AsyncIncomingMessageHandler() override = default;

    void Register() override;
    void HandleIncomingMessage(const Attributes &request, OnMessageReply &onMessageReply) override;
    MessageType GetMessageType() const override;

protected:
    virtual void HandleRequest(const Attributes &request, OnMessageReply &onMessageReply) = 0;

private:
    const MessageType messageType_ { MessageType::INVALID };
    std::unique_ptr<Subscription> subscription_;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_ASYNC_INCOMING_MESSAGE_HANDLER_H
