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

#include "async_incoming_message_handler.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
AsyncIncomingMessageHandler::AsyncIncomingMessageHandler(MessageType messageType) : messageType_(messageType)
{
}

void AsyncIncomingMessageHandler::Register()
{
    if (subscription_ != nullptr) {
        IAM_LOGE("handler already registered");
        return;
    }
    subscription_ = GetCrossDeviceCommManager().SubscribeIncomingConnection(messageType_,
        [this](const Attributes &request, OnMessageReply &onMessageReply) {
            HandleIncomingMessage(request, onMessageReply);
        });
    ENSURE_OR_RETURN(subscription_ != nullptr);
}

void AsyncIncomingMessageHandler::HandleIncomingMessage(const Attributes &request, OnMessageReply &onMessageReply)
{
    IAM_LOGI("start");
    ENSURE_OR_RETURN(onMessageReply != nullptr);
    HandleRequest(request, onMessageReply);
}

MessageType AsyncIncomingMessageHandler::GetMessageType() const
{
    return messageType_;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
