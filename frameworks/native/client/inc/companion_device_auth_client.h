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

/**
 * @file companion_device_auth_client.h
 *
 * @brief companion device auth client interfaces.
 */

#ifndef COMPANION_DEVICE_AUTH_CLIENT_H
#define COMPANION_DEVICE_AUTH_CLIENT_H

#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

#include "common_defines.h"
#include "companion_device_auth_common_defines.h"
#include "iavailable_device_status_callback.h"
#include "icontinuous_auth_status_callback.h"
#include "idevice_select_callback.h"
#include "itemplate_status_callback.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
class CompanionDeviceAuthClient {
public:
    /**
     * @brief Get companion device auth client's instance.
     *
     * @return Companion device auth client's instance.
     */
    static CompanionDeviceAuthClient &GetInstance();

    /**
     * @brief Default destructor.
     */
    virtual ~CompanionDeviceAuthClient() = default;

    /**
     * @brief Register the device selection callback to provide customized device selection logic.
     *
     * @param callback Selector implementation that returns device candidates.
     * @return Return RegisterDeviceSelectCallback result(0:success; other:failed).
     */
    virtual int32_t RegisterDeviceSelectCallback(const std::shared_ptr<IDeviceSelectCallback> &callback) = 0;

    /**
     * @brief Unregister the currently registered device selection callback.
     *
     * @return Return UnregisterDeviceSelectCallback result(0:success; other:failed).
     */
    virtual int32_t UnregisterDeviceSelectCallback() = 0;

    /**
     * @brief Update the list of enabled business identifiers for the specified template.
     *        The new scope becomes effective after the returned promise resolves.
     *
     * @param templateId Identifier of the template to modify.
     * @param enabledBusinessIds Business identifiers that should remain enabled.
     * @return Return UpdateTemplateEnabledBusinessIds result(0:success; other:failed).
     */
    virtual int32_t UpdateTemplateEnabledBusinessIds(const uint64_t templateId,
        const std::vector<int32_t> enabledBusinessIds) = 0;

    /**
     * @brief Retrieve the full list of template statuses.
     *
     * @param localUserId Local user identifier.
     * @param templateStatusList Latest template status list.
     * @return Return GetTemplateStatus result(0:success; other:failed).
     */
    virtual int32_t GetTemplateStatus(const int32_t localUserId,
        std::vector<ClientTemplateStatus> &templateStatusList) = 0;

    /**
     * @brief Subscribe to template status changes.
     *        The callback receives all current templates after registration and every update.
     *
     * @param localUserId Local user identifier.
     * @param callback Handler that processes template status updates.
     * @return Return SubscribeTemplateStatusChange result(0:success; other:failed).
     */
    virtual int32_t SubscribeTemplateStatusChange(const int32_t localUserId,
        const std::shared_ptr<ITemplateStatusCallback> &callback) = 0;

    /**
     * @brief Cancel template status subscription.
     *
     * @param callback Target callback to remove.
     * @return Return UnsubscribeTemplateStatusChange result(0:success; other:failed).
     */
    virtual int32_t UnsubscribeTemplateStatusChange(const std::shared_ptr<ITemplateStatusCallback> &callback) = 0;

    /**
     * @brief Subscribe to continuous authentication updates for a template.
     *
     * @param localUserId Local user identifier.
     * @param callback Handler for continuous authentication outcomes.
     * @param templateId template identifier; omit the template identifier to
     *                   subscribe to continuous authentication updates for all templates.
     * @return Return SubscribeContinuousAuthStatusChange result(0:success; other:failed).
     */
    virtual int32_t SubscribeContinuousAuthStatusChange(const int32_t localUserId,
        const std::shared_ptr<IContinuousAuthStatusCallback> &callback,
        const std::optional<uint64_t> templateId = std::nullopt) = 0;

    /**
     * @brief Cancel continuous authentication subscription;
     *
     * @param callback Target callback to remove when provided.
     * @return Return UnsubscribeContinuousAuthStatusChange result(0:success; other:failed).
     */
    virtual int32_t UnsubscribeContinuousAuthStatusChange(
        const std::shared_ptr<IContinuousAuthStatusCallback> &callback) = 0;

    /**
     * @brief Subscribe to status changes of available devices.
     *
     * @param localUserId Local user identifier.
     * @param callback Callback executed when available device status changes.
     * @return Return SubscribeAvailableDeviceStatus result(0:success; other:failed).
     */
    virtual int32_t SubscribeAvailableDeviceStatus(const int32_t localUserId,
        const std::shared_ptr<IAvailableDeviceStatusCallback> &callback) = 0;

    /**
     * @brief Cancel available device status subscription.
     *
     * @param callback Target callback to unsubscribe.
     * @return Return UnsubscribeAvailableDeviceStatus result(0:success; other:failed).
     */
    virtual int32_t UnsubscribeAvailableDeviceStatus(
        const std::shared_ptr<IAvailableDeviceStatusCallback> &callback) = 0;

    /**
     * @brief Check whether input local user id valid or not.
     *
     * @param localUserId Local user identifier.
     * @param isUserIdValid check result for user id valid or not.
     * @return Return CheckLocalUserIdValid result(0:success; other:failed).
     */
    virtual int32_t CheckLocalUserIdValid(const int32_t localUserId, bool &isUserIdValid) = 0;
};
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
#endif // COMPANION_DEVICE_AUTH_CLIENT_H