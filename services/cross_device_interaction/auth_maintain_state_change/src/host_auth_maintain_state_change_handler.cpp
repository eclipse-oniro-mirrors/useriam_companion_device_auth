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

#include "host_auth_maintain_state_change_handler.h"

#include "error_guard.h"
#include "iam_check.h"
#include "iam_logger.h"

#include "auth_maintain_state_change_message.h"
#include "singleton_manager.h"
#include "task_runner_manager.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
void HostAuthMaintainStateChangeHandler::HandleRequest(const Attributes &request, Attributes &reply)
{
    IAM_LOGI("start");

    ErrorGuard errorGuard([&reply](ResultCode result) {
        (void)reply.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(result));
    });

    auto requestMsgOpt = DecodeAuthMaintainStateChangeRequest(request);
    ENSURE_OR_RETURN(requestMsgOpt.has_value());

    if (onStateChange_) {
        TaskRunnerManager::GetInstance().PostTaskOnResident(
            [cb = onStateChange_, authMaintainState = requestMsgOpt->authMaintainState]() mutable {
                if (cb) {
                    cb(authMaintainState);
                }
            });
    }

    if (requestMsgOpt->authMaintainState) {
        IAM_LOGI("auth maintain state is true");
    } else {
        IAM_LOGI("auth maintain state is false");
    }
    AuthMaintainStateChangeReplyMsg replyMsg = { .result = ResultCode::SUCCESS };
    bool encodeRet = EncodeAuthMaintainStateChangeReply(replyMsg, reply);
    ENSURE_OR_RETURN(encodeRet);
    errorGuard.Cancel();
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
