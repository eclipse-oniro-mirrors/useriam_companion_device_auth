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

#ifndef COMPANION_DEVICE_AUTH_FWK_COMMON_H
#define COMPANION_DEVICE_AUTH_FWK_COMMON_H

#include <optional>

#include "iam_executor_framework_types.h"
#include "iam_executor_iauth_driver_hdi.h"
#include "iam_executor_iauth_executor_hdi.h"
#include "iam_executor_iexecute_callback.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

// Framework type aliases
using FwkResultCode = UserAuth::ResultCode;
using FwkExecutorInfo = UserAuth::ExecutorInfo;
using FwkEnrollParam = UserAuth::EnrollParam;
using FwkAuthenticateParam = UserAuth::AuthenticateParam;
using FwkCollectParam = UserAuth::CollectParam;
using FwkIdentifyParam = UserAuth::IdentifyParam;
using FwkProperty = UserAuth::Property;
using FwkPropertyMode = UserAuth::PropertyMode;
using FwkAttribute = UserAuth::Attributes;
using FwkAttributeKey = UserAuth::Attributes::AttributeKey;

// Framework interface aliases
using FwkIAuthExecutorHdi = UserAuth::IAuthExecutorHdi;
using FwkIAuthDriverHdi = UserAuth::IAuthDriverHdi;
using FwkIExecuteCallback = UserAuth::IExecuteCallback;

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_FWK_COMMON_H
