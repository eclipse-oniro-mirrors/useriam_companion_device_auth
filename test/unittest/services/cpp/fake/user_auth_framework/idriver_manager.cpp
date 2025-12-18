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

#include <cstdint>
#include <map>
#include <memory>

#include "iam_executor_iauth_driver_hdi.h"
#include "iam_executor_idriver_manager.h"

namespace OHOS {
namespace UserIam {
namespace UserAuth {

int32_t IDriverManager::Start(const std::map<std::string, HdiConfig> &hdiName2Config, bool hasHdi)
{
    // Fake implementation: always succeed
    return 0;
}

} // namespace UserAuth
} // namespace UserIam
} // namespace OHOS
