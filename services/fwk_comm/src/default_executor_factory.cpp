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

#include "default_executor_factory.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "companion_device_auth_all_in_one_executor.h"

#define LOG_TAG "CDA_SA"
#define LOG_FILE_ID LOG_FILE_DEFAULT_EXECUTOR_FACTORY

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::shared_ptr<ExecutorFactoryImpl> ExecutorFactoryImpl::Create()
{
    IAM_LOGI("start");
    auto factory = std::shared_ptr<ExecutorFactoryImpl>(new ExecutorFactoryImpl());
    ENSURE_OR_RETURN_VAL(factory != nullptr, nullptr);
    return factory;
}

std::shared_ptr<FwkIAuthExecutorHdi> ExecutorFactoryImpl::CreateExecutor()
{
    IAM_LOGI("start");
    return CompanionDeviceAuthAllInOneExecutor::Create();
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
