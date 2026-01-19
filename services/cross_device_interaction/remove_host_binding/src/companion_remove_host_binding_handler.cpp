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

#include "companion_remove_host_binding_handler.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "error_guard.h"
#include "remove_host_binding_message.h"
#include "singleton_manager.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
CompanionRemoveHostBindingHandler::CompanionRemoveHostBindingHandler()
    : SyncIncomingMessageHandler(MessageType::REMOVE_HOST_BINDING)
{
}

void CompanionRemoveHostBindingHandler::HandleRequest(const Attributes &request, Attributes &reply)
{
    IAM_LOGI("start");

    ErrorGuard errorGuard([&reply](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
    });

    auto requestMsgOpt = DecodeRemoveHostBindingRequest(request);
    if (!requestMsgOpt.has_value()) {
        IAM_LOGE("DecodeRemoveHostBindingRequest failed");
        return;
    }
    const auto &requestMsg = *requestMsgOpt;

    ResultCode ret = GetHostBindingManager().RemoveHostBinding(requestMsg.companionUserId, requestMsg.hostDeviceKey);
    if (ret != ResultCode::SUCCESS) {
        IAM_LOGE("RemoveHostBinding failed ret=%{public}d", ret);
        errorGuard.UpdateErrorCode(ret);
        return;
    }

    RemoveHostBindingReply replyMsg = { .result = ResultCode::SUCCESS };
    bool encodeRet = EncodeRemoveHostBindingReply(replyMsg, reply);
    if (!encodeRet) {
        IAM_LOGE("EncodeRemoveHostBindingReply failed");
        return;
    }
    errorGuard.Cancel();
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
