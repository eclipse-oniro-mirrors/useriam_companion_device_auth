/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "iam_executor_iauth_executor_hdi.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

ResultCode IAuthExecutorHdi::Enroll(uint64_t scheduleId, const EnrollParam &param,
    const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    return ResultCode::GENERAL_ERROR;
}

ResultCode IAuthExecutorHdi::Authenticate(uint64_t scheduleId, const AuthenticateParam &param,
    const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    return ResultCode::GENERAL_ERROR;
}

ResultCode IAuthExecutorHdi::Collect(uint64_t scheduleId, const CollectParam &param,
    const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    return ResultCode::GENERAL_ERROR;
}

ResultCode IAuthExecutorHdi::Identify(uint64_t scheduleId, const IdentifyParam &param,
    const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    return ResultCode::GENERAL_ERROR;
}

ResultCode IAuthExecutorHdi::Delete(const std::vector<uint64_t> &templateIdList)
{
    return ResultCode::GENERAL_ERROR;
}

ResultCode IAuthExecutorHdi::SendCommand(PropertyMode commandId, const std::vector<uint8_t> &extraInfo,
    const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    return ResultCode::GENERAL_ERROR;
}

ResultCode IAuthExecutorHdi::GetProperty(const std::vector<uint64_t> &templateIdList,
    const std::vector<Attributes::AttributeKey> &keys, Property &property)
{
    return ResultCode::GENERAL_ERROR;
}

ResultCode IAuthExecutorHdi::SetCachedTemplates(const std::vector<uint64_t> &templateIdList)
{
    return ResultCode::GENERAL_ERROR;
}

ResultCode IAuthExecutorHdi::Abandon(uint64_t scheduleId, const DeleteParam &param,
    const std::shared_ptr<UserAuth::IExecuteCallback> &callbackObj)
{
    return ResultCode::GENERAL_ERROR;
}

ResultCode IAuthExecutorHdi::NotifyCollectorReady(uint64_t scheduleId)
{
    return ResultCode::GENERAL_ERROR;
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
