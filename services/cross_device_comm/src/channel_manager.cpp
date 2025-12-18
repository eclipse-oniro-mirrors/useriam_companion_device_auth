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

#include "channel_manager.h"

#include <set>

#include "iam_check.h"
#include "iam_logger.h"

#define LOG_TAG "COMPANION_DEVICE_AUTH"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {

ChannelManager::ChannelManager(const std::vector<std::shared_ptr<ICrossDeviceChannel>> &channels)
{
    IAM_LOGI("constructing with %{public}zu channels", channels.size());

    std::set<ChannelId> registeredIds;
    for (const auto &channel : channels) {
        if (channel == nullptr) {
            IAM_LOGE("null channel detected in constructor, skipping");
            continue;
        }

        ChannelId channelId = channel->GetChannelId();
        if (!registeredIds.insert(channelId).second) {
            IAM_LOGE("duplicate channel detected: %{public}d, skipping", channelId);
            continue;
        }

        channels_.push_back(channel);
        IAM_LOGI("channel registered: %{public}d", channelId);
    }

    IAM_LOGI("constructed with %{public}zu valid channels", channels_.size());
}

std::shared_ptr<ICrossDeviceChannel> ChannelManager::GetPrimaryChannel()
{
    if (channels_.empty()) {
        return nullptr;
    }
    return channels_.front();
}

std::shared_ptr<ICrossDeviceChannel> ChannelManager::GetChannelById(ChannelId channelId)
{
    auto it = std::find_if(channels_.begin(), channels_.end(),
        [channelId](
            const std::shared_ptr<ICrossDeviceChannel> &channel) { return channel->GetChannelId() == channelId; });
    if (it != channels_.end()) {
        return *it;
    }

    IAM_LOGE("channel not found: %{public}d", channelId);
    return nullptr;
}

} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
