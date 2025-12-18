/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "fwk_comm_manager.h"

#include <map>

#include "iam_check.h"
#include "iam_executor_idriver_manager.h"
#include "iam_logger.h"
#include "iam_ptr.h"

#include "companion_auth_interface_adapter.h"
#include "companion_device_auth_driver.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

std::shared_ptr<FwkCommManager> FwkCommManager::Create()
{
    auto manager = std::shared_ptr<FwkCommManager>(new (std::nothrow) FwkCommManager());
    ENSURE_OR_RETURN_VAL(manager != nullptr, nullptr);

    if (!manager->Initialize()) {
        IAM_LOGE("failed to Initialize FwkCommManager");
        return nullptr;
    }

    return manager;
}

bool FwkCommManager::Initialize()
{
    IAM_LOGI("start Initialize FwkCommManager");
    const uint16_t driverId = 1;
    const auto adapter = MakeShared<CompanionAuthInterfaceAdapter>();
    if (adapter == nullptr) {
        IAM_LOGE("make adapter failed");
        return false;
    }
    auto driver = MakeShared<CompanionDeviceAuthDriver>(adapter);
    if (driver == nullptr) {
        IAM_LOGE("make driver failed");
        return false;
    }
    const std::map<std::string, UserIam::UserAuth::HdiConfig> hdiName2Config = {
        { "companion_device_auth", { driverId, driver } },
    };

    int32_t ret = UserIam::UserAuth::IDriverManager::Start(hdiName2Config, false);
    if (ret != UserAuth::SUCCESS) {
        IAM_LOGE("start driver manager failed");
        return false;
    }
    return true;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
