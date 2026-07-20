/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "interaction_desc.h"

#include <iomanip>
#include <sstream>

#include "iam_para2str.h"

namespace OHOS {
namespace UserIam {
namespace CompanionDeviceAuth {
InteractionDesc::InteractionDesc(const char *prefix, const char *type) : prefix_(prefix), type_(type)
{
    Rebuild();
}

void InteractionDesc::SetConnectionName(const std::string &connName)
{
    connectionName_ = connName;
    Rebuild();
}

void InteractionDesc::SetRequestId(RequestId requestId)
{
    requestId_ = requestId;
    Rebuild();
}

void InteractionDesc::SetContextId(uint64_t contextId)
{
    contextId_ = contextId;
    Rebuild();
}

void InteractionDesc::SetScheduleId(ScheduleId scheduleId)
{
    scheduleId_ = scheduleId;
    Rebuild();
}

void InteractionDesc::SetBindingId(BindingId bindingId)
{
    bindingId_ = bindingId;
    Rebuild();
}

void InteractionDesc::SetTemplateId(TemplateId templateId)
{
    templateId_ = templateId;
    templateIdList_.clear();
    Rebuild();
}

void InteractionDesc::SetTemplateIdList(const std::vector<TemplateId> &templateIdList)
{
    templateIdList_ = templateIdList;
    templateId_.reset();
    Rebuild();
}

void InteractionDesc::SetDeviceId(const DeviceKey &deviceKey)
{
    deviceId_ = GetTruncatedString(deviceKey.deviceId);
    deviceIdList_.clear();
    Rebuild();
}

void InteractionDesc::SetDeviceIdList(const std::vector<DeviceKey> &deviceKeyList)
{
    deviceIdList_.clear();
    deviceIdList_.reserve(deviceKeyList.size());
    for (const auto &key : deviceKeyList) {
        deviceIdList_.push_back(GetTruncatedString(key.deviceId));
    }
    deviceId_.clear();
    Rebuild();
}

void InteractionDesc::SetSubRequestIdList(const std::vector<RequestId> &subRequestIdList)
{
    subRequestIdList_ = subRequestIdList;
    Rebuild();
}

void InteractionDesc::SetUserId(UserId userId)
{
    userId_ = userId;
    Rebuild();
}

void InteractionDesc::SetPkgName(const std::string &pkgName)
{
    pkgName_ = pkgName;
    Rebuild();
}

const char *InteractionDesc::GetCStr() const
{
    return description_.c_str();
}

void InteractionDesc::AppendSubRequestIds(std::ostringstream &oss) const
{
    oss << ",SR=[";
    for (size_t i = 0; i < subRequestIdList_.size(); ++i) {
        if (i > 0) {
            oss << ",";
        }
        oss << std::hex << std::uppercase << std::setfill('0') << std::setw(TRUNCATED_WIDTH)
            << static_cast<uint16_t>(subRequestIdList_[i]) << std::dec;
    }
    oss << "]";
}

void InteractionDesc::AppendTemplateIds(std::ostringstream &oss) const
{
    oss << ",T=[";
    for (size_t i = 0; i < templateIdList_.size(); ++i) {
        if (i > 0) {
            oss << ",";
        }
        oss << GET_TRUNCATED_STRING(templateIdList_[i]);
    }
    oss << "]";
}

void InteractionDesc::AppendDeviceIds(std::ostringstream &oss) const
{
    oss << ",D=[";
    for (size_t i = 0; i < deviceIdList_.size(); ++i) {
        if (i > 0) {
            oss << ",";
        }
        oss << deviceIdList_[i];
    }
    oss << "]";
}

void InteractionDesc::Rebuild()
{
    constexpr int requestIdHexWidth = 8;
    std::ostringstream oss;
    oss << prefix_ << "(" << type_;
    if (!connectionName_.empty()) {
        oss << "," << connectionName_;
    }
    if (requestId_.has_value()) {
        oss << ",R:" << std::hex << std::uppercase << std::setfill('0') << std::setw(requestIdHexWidth) << *requestId_
            << std::dec;
    }
    if (contextId_.has_value()) {
        oss << ",C:" << GET_TRUNCATED_STRING(*contextId_);
    }
    if (scheduleId_.has_value()) {
        oss << ",S:" << GET_TRUNCATED_STRING(*scheduleId_);
    }
    if (!subRequestIdList_.empty()) {
        AppendSubRequestIds(oss);
    }
    if (bindingId_.has_value()) {
        oss << ",B:" << GET_TRUNCATED_STRING(*bindingId_);
    }
    if (!deviceId_.empty()) {
        oss << ",D:" << deviceId_;
    } else if (!deviceIdList_.empty()) {
        AppendDeviceIds(oss);
    }
    if (templateId_.has_value()) {
        oss << ",T:" << GET_TRUNCATED_STRING(*templateId_);
    }
    if (!templateIdList_.empty()) {
        AppendTemplateIds(oss);
    }
    if (userId_.has_value()) {
        oss << ",U:" << *userId_;
    }
    if (!pkgName_.empty()) {
        auto dotPos = pkgName_.rfind('.');
        oss << ",P:" << (dotPos == std::string::npos ? pkgName_ : pkgName_.substr(dotPos + 1));
    }
    oss << ")";
    description_ = oss.str();
}
} // namespace CompanionDeviceAuth
} // namespace UserIam
} // namespace OHOS
