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

#include "incoming_message_handler_registry.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "companion_init_key_negotiation_handler.h"
#include "companion_pre_issue_token_handler.h"
#include "companion_remove_host_binding_handler.h"
#include "companion_start_delegate_auth_handler.h"
#include "companion_sync_device_status_handler.h"
#include "companion_token_auth_handler.h"
#include "host_pre_obtain_token_handler.h"
#include "host_revoke_token_handler.h"
#include "incoming_message_handler.h"
#include "keep_alive_handler.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
std::shared_ptr<IncomingMessageHandlerRegistry> IncomingMessageHandlerRegistry::Create()
{
    auto registry = std::shared_ptr<IncomingMessageHandlerRegistry>(new IncomingMessageHandlerRegistry());
    if (registry == nullptr) {
        return nullptr;
    }
    if (!registry->Initialize()) {
        IAM_LOGE("IncomingMessageHandlerRegistry initialize failed");
        return nullptr;
    }
    return registry;
}

bool IncomingMessageHandlerRegistry::Initialize()
{
    if (initialized_) {
        return true;
    }

    initialized_ = true;
    return true;
}

void IncomingMessageHandlerRegistry::AddHandler(std::shared_ptr<IncomingMessageHandler> handler)
{
    ENSURE_OR_RETURN(handler != nullptr);
    if (handlersRegistered_) {
        handler->Register();
    }
    handlers_.push_back(handler);
}

bool IncomingMessageHandlerRegistry::RegisterHandlers()
{
    if (handlersRegistered_) {
        IAM_LOGE("handlers already registered");
        return true;
    }

    // Register supported handlers; other features are disabled in this build
    std::shared_ptr<IncomingMessageHandler> handler = std::make_shared<CompanionSyncDeviceStatusHandler>();
    ENSURE_OR_RETURN_VAL(handler != nullptr, false);
    handlers_.push_back(handler);

    handler = std::make_shared<KeepAliveHandler>();
    ENSURE_OR_RETURN_VAL(handler != nullptr, false);
    handlers_.push_back(handler);

    handler = std::make_shared<CompanionTokenAuthHandler>();
    ENSURE_OR_RETURN_VAL(handler != nullptr, false);
    handlers_.push_back(handler);

    handler = std::make_shared<CompanionInitKeyNegotiationHandler>();
    ENSURE_OR_RETURN_VAL(handler != nullptr, false);
    handlers_.push_back(handler);

    handler = std::make_shared<CompanionRemoveHostBindingHandler>();
    ENSURE_OR_RETURN_VAL(handler != nullptr, false);
    handlers_.push_back(handler);

    handler = std::make_shared<CompanionPreIssueTokenHandler>();
    ENSURE_OR_RETURN_VAL(handler != nullptr, false);
    handlers_.push_back(handler);

    handler = std::make_shared<HostPreObtainTokenHandler>();
    ENSURE_OR_RETURN_VAL(handler != nullptr, false);
    handlers_.push_back(handler);

    handler = std::make_shared<HostRevokeTokenHandler>();
    ENSURE_OR_RETURN_VAL(handler != nullptr, false);
    handlers_.push_back(handler);

    handler = std::make_shared<CompanionStartDelegateAuthHandler>();
    ENSURE_OR_RETURN_VAL(handler != nullptr, false);
    handlers_.push_back(handler);

    for (const auto &handler : handlers_) {
        ENSURE_OR_RETURN_VAL(handler != nullptr, false);
        handler->Register();
    }

    handlersRegistered_ = true;
    IAM_LOGI("registered %{public}zu handlers", handlers_.size());
    return true;
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
