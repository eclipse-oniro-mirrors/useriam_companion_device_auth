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

#ifndef COMPANION_DEVICE_AUTH_COMMON_INCOMING_MESSAGE_HANDLER_REGISTRY_H
#define COMPANION_DEVICE_AUTH_COMMON_INCOMING_MESSAGE_HANDLER_REGISTRY_H

#include <memory>
#include <vector>

#include "nocopyable.h"

#include "incoming_message_handler.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class IncomingMessageHandlerRegistry : public NoCopyable {
public:
    static std::shared_ptr<IncomingMessageHandlerRegistry> Create();

    bool Initialize();
    void AddHandler(std::shared_ptr<IncomingMessageHandler> handler);
    bool RegisterHandlers();
    ~IncomingMessageHandlerRegistry() = default;

private:
    IncomingMessageHandlerRegistry() = default;

    std::vector<std::shared_ptr<IncomingMessageHandler>> handlers_;
    bool initialized_ = false;
    bool handlersRegistered_ = false;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_COMMON_INCOMING_MESSAGE_HANDLER_REGISTRY_H
