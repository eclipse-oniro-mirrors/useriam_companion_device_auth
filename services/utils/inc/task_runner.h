/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef COMPANION_DEVICE_AUTH_TASK_RUNNER_H
#define COMPANION_DEVICE_AUTH_TASK_RUNNER_H

#include <functional>
#include <memory>

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class TaskRunner {
public:
    using Task = std::function<void(void)>;
    virtual ~TaskRunner() = default;
    virtual void PostTask(Task &&task) = 0;
    virtual void Suspend() = 0;
    static std::shared_ptr<TaskRunner> GetDefaultRunner();
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_TASK_RUNNER_H
