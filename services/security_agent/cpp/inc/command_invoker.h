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

#ifndef COMMAND_INVOKER_H
#define COMMAND_INVOKER_H

#include <cstddef>
#include <cstdint>

#include "icommand_invoker.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class CommandInvoker : public ICommandInvoker {
public:
    CommandInvoker();
    ~CommandInvoker();

    ResultCode Initialize() override;
    void Finalize() override;
    ResultCode InvokeCommand(int32_t commandId, const uint8_t *inputData, uint32_t inputDataLen, uint8_t *outputData,
        uint32_t outputDataLen) override;

private:
    bool inited_ = false;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMMAND_INVOKER_H
