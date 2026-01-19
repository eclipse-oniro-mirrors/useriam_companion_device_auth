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

#include "xcollie_helper.h"

#include <functional>
#include <memory>

#include "iam_logger.h"

#include "xcollie/xcollie.h"
#include "xcollie/xcollie_define.h"

#define LOG_TAG "CDA_SA"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
XCollieHelper::XCollieHelper(const std::string &name, unsigned int timeout)
{
    id_ = HiviewDFX::XCollie::GetInstance().SetTimer(name, timeout, nullptr, nullptr, HiviewDFX::XCOLLIE_FLAG_DEFAULT);
}

XCollieHelper::~XCollieHelper()
{
    HiviewDFX::XCollie::GetInstance().CancelTimer(id_);
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
