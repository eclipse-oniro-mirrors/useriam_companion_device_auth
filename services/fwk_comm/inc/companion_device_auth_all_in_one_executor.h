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

#ifndef COMPANION_DEVICE_AUTH_ALL_IN_ONE_EXECUTOR_H
#define COMPANION_DEVICE_AUTH_ALL_IN_ONE_EXECUTOR_H

#include <functional>
#include <future>
#include <memory>
#include <vector>

#include "nocopyable.h"

#include "iam_executor_iauth_executor_hdi.h"

#include "fwk_common.h"
#include "service_common.h"
#include "singleton_manager.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class CompanionDeviceAuthAllInOneExecutor : public FwkIAuthExecutorHdi,
                                            public NoCopyable,
                                            public std::enable_shared_from_this<CompanionDeviceAuthAllInOneExecutor> {
public:
    CompanionDeviceAuthAllInOneExecutor();
    ~CompanionDeviceAuthAllInOneExecutor() override = default;

    FwkResultCode GetExecutorInfo(FwkExecutorInfo &info) override;
    FwkResultCode OnRegisterFinish(const std::vector<uint64_t> &templateIdList,
        const std::vector<uint8_t> &frameworkPublicKey, const std::vector<uint8_t> &extraInfo) override;
    FwkResultCode SendMessage(uint64_t scheduleId, int32_t srcRole, const std::vector<uint8_t> &msg) override;
    FwkResultCode Enroll(uint64_t scheduleId, const FwkEnrollParam &param,
        const std::shared_ptr<FwkIExecuteCallback> &callbackObj) override;
    FwkResultCode Authenticate(uint64_t scheduleId, const FwkAuthenticateParam &param,
        const std::shared_ptr<FwkIExecuteCallback> &callbackObj) override;
    FwkResultCode Delete(const std::vector<uint64_t> &templateIdList) override;
    FwkResultCode Cancel(uint64_t scheduleId) override;
    FwkResultCode SendCommand(FwkPropertyMode commandId, const std::vector<uint8_t> &extraInfo,
        const std::shared_ptr<FwkIExecuteCallback> &callbackObj) override;
    FwkResultCode GetProperty(const std::vector<uint64_t> &templateIdList, const std::vector<FwkAttributeKey> &keys,
        FwkProperty &property) override;
    FwkResultCode SetCachedTemplates(const std::vector<uint64_t> &templateIdList) override;

    class CompanionDeviceAuthAllInOneExecutorInner;

#ifndef ENABLE_TEST
private:
#endif
    FwkResultCode RunOnResidentSync(std::function<FwkResultCode()> func, uint32_t timeoutSec = MAX_SYNC_WAIT_TIME_SEC);

    std::shared_ptr<CompanionDeviceAuthAllInOneExecutorInner> inner_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_ALL_IN_ONE_EXECUTOR_H
