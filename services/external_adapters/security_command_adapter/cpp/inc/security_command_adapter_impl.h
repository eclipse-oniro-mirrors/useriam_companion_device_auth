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

#ifndef COMPANION_DEVICE_AUTH_SECURITY_COMMAND_ADAPTER_IMPL_H
#define COMPANION_DEVICE_AUTH_SECURITY_COMMAND_ADAPTER_IMPL_H

#include "security_command_adapter.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class SecurityCommandAdapterImpl : public ISecurityCommandAdapter {
public:
    ~SecurityCommandAdapterImpl() override;

    static std::shared_ptr<SecurityCommandAdapterImpl> Create();

    ResultCode InvokeCommand(int32_t commandId, const uint8_t *inputData, uint32_t inputDataLen, uint8_t *outputData,
        uint32_t outputDataLen) override;

private:
    ResultCode Initialize();
    SecurityCommandAdapterImpl();

    bool inited_ = false;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_SECURITY_COMMAND_ADAPTER_IMPL_H
