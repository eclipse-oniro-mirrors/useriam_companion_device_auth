/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "driver_manager_adapter_impl.h"

#include <map>

#include "iam_check.h"
#include "iam_executor_idriver_manager.h"
#include "iam_logger.h"
#include "ipc_skeleton.h"
#include "token_setproc.h"

#include "companion_device_auth_driver.h"
#include "xcollie_helper.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

bool DriverManagerAdapterImpl::Start(std::shared_ptr<CompanionDeviceAuthDriver> driver)
{
    if (driver == nullptr) {
        IAM_LOGE("driver is null");
        return false;
    }

    IAM_LOGI("start DriverManagerAdapter");
    const uint16_t driverId = 1;
    const std::map<std::string, UserAuth::HdiConfig> hdiName2Config = {
        { "companion_device_auth", { driverId, driver } },
    };

    XCollieHelper xcollie("DriverManagerAdapterImpl-Start", API_CALL_TIMEOUT);

    SetFirstCallerTokenID(IPCSkeleton::GetCallingTokenID());
    int32_t ret = UserAuth::IDriverManager::Start(hdiName2Config, false);
    SetFirstCallerTokenID(0);

    if (ret != UserAuth::SUCCESS) {
        IAM_LOGE("start driver manager failed");
        return false;
    }
    return true;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
