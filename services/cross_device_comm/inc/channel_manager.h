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

#ifndef COMPANION_DEVICE_AUTH_CHANNEL_MANAGER_H
#define COMPANION_DEVICE_AUTH_CHANNEL_MANAGER_H

#include <algorithm>
#include <memory>
#include <optional>
#include <vector>

#include "nocopyable.h"

#include "icross_device_channel.h"
#include "service_common.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

class ChannelManager : public NoCopyable {
public:
    explicit ChannelManager(const std::vector<std::shared_ptr<ICrossDeviceChannel>> &channels);
    ~ChannelManager() = default;

    std::shared_ptr<ICrossDeviceChannel> GetPrimaryChannel();

    std::shared_ptr<ICrossDeviceChannel> GetChannelById(ChannelId channelId);

    std::vector<std::shared_ptr<ICrossDeviceChannel>> GetAllChannels() const
    {
        return channels_;
    }

private:
    std::vector<std::shared_ptr<ICrossDeviceChannel>> channels_;
};

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS

#endif // COMPANION_DEVICE_AUTH_CHANNEL_MANAGER_H
