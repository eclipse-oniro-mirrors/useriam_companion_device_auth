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

#include "fwk_comm_manager.h"

#include "iam_check.h"
#include "iam_logger.h"

#include "adapter_manager.h"
#include "companion_device_auth_driver.h"
#include "service_common.h"
#include "xcollie_helper.h"

#define LOG_TAG "CDA_SA"

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
    auto driver = std::make_shared<CompanionDeviceAuthDriver>();
    ENSURE_OR_RETURN_VAL(driver != nullptr, false);

    XCollieHelper xcollie("FwkCommManager-StartDriver", ADAPTER_CALL_TIMEOUT_SEC);
    return GetDriverManagerAdapter().Start(driver);
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
