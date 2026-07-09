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

#include "resync_device_status_message.h"

#include <optional>

#include "iam_check.h"
#include "iam_logger.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_RESYNC_DEVICE_STATUS_MESSAGE

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

void EncodeRequestDeviceResyncRequest(const RequestDeviceResyncRequest &request, Attributes &attributes)
{
    EncodeCompanionDeviceKey(request.companionDeviceKey, attributes);
}

std::optional<RequestDeviceResyncRequest> DecodeRequestDeviceResyncRequest(const Attributes &attributes)
{
    auto companionDeviceKey = DecodeCompanionDeviceKey(attributes);
    ENSURE_OR_RETURN_VAL(companionDeviceKey.has_value(), std::nullopt);

    RequestDeviceResyncRequest request {};
    request.companionDeviceKey = *companionDeviceKey;
    return request;
}

void EncodeRequestDeviceResyncReply(const RequestDeviceResyncReply &reply, Attributes &attributes)
{
    attributes.SetInt32Value(Attributes::ATTR_CDA_SA_RESULT, static_cast<int32_t>(reply.result));
}

std::optional<RequestDeviceResyncReply> DecodeRequestDeviceResyncReply(const Attributes &attributes)
{
    int32_t resultCode = 0;
    bool getResultRet = attributes.GetInt32Value(Attributes::ATTR_CDA_SA_RESULT, resultCode);
    ENSURE_OR_RETURN_VAL(getResultRet, std::nullopt);

    RequestDeviceResyncReply reply {};
    reply.result = static_cast<ResultCode>(resultCode);
    return reply;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
