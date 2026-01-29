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

#include "request_aborted_message.h"

#include <optional>

#include "iam_check.h"
#include "iam_logger.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

void EncodeRequestAbortedRequest(const RequestAbortedRequest &request, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(request.result));
    if (!request.reason.empty()) {
        attributes.SetStringValue(Attributes::ATTR_CDA_SA_REASON, request.reason);
    }
}

std::optional<RequestAbortedRequest> DecodeRequestAbortedRequest(const Attributes &attributes)
{
    int32_t resultCode = 0;
    bool getResultRet = attributes.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, resultCode);
    ENSURE_OR_RETURN_VAL(getResultRet, std::nullopt);

    RequestAbortedRequest request {};
    request.result = static_cast<ResultCode>(resultCode);

    // Reason is optional
    (void)attributes.GetStringValue(Attributes::ATTR_CDA_SA_REASON, request.reason);

    return request;
}

void EncodeRequestAbortedReply(const RequestAbortedReply &reply, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(reply.result));
}

std::optional<RequestAbortedReply> DecodeRequestAbortedReply(const Attributes &attributes)
{
    int32_t resultCode = 0;
    bool getResultRet = attributes.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, resultCode);
    ENSURE_OR_RETURN_VAL(getResultRet, std::nullopt);

    RequestAbortedReply reply {};
    reply.result = static_cast<ResultCode>(resultCode);
    return reply;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
