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

#ifndef COMPANION_DEVICE_AUTH_EXECUTOR_CALLBACK_H
#define COMPANION_DEVICE_AUTH_EXECUTOR_CALLBACK_H

#include <cstdint>
#include <memory>
#include <vector>

#include "nocopyable.h"

#include "common_defines.h"
#include "fwk_common.h"
#include "irequest.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class CompanionDeviceAuthExecutorCallback {
public:
    CompanionDeviceAuthExecutorCallback(std::shared_ptr<FwkIExecuteCallback> frameworkCallback);

    void operator()(ResultCode result, const std::vector<uint8_t> &extraInfo);

#ifndef ENABLE_TEST
private:
#endif
    FwkResultCode ConvertResultCode(const ResultCode in);

    std::shared_ptr<FwkIExecuteCallback> frameworkCallback_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_EXECUTOR_CALLBACK_H
