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

#include "datashare_helper.h"

namespace OHOS {
namespace DataShare {
void ResetDataShareFake()
{
    g_lastRegisteredObserver = nullptr;
    g_registeredObservers.clear();
    g_queryResults.clear();
}

void SetSettingsValue(int32_t userId, const std::string &key, std::string value)
{
    g_queryResults[{ userId, key }] = std::move(value);
}

std::pair<int32_t, std::string> ParseSettingsUri(Uri &uri)
{
    const std::string secure = "USER_SETTINGSDATA_SECURE_";
    std::string path = uri.GetPath();
    std::string query = uri.GetQuery();
    int32_t userId = 0;
    auto pos = path.find(secure);
    if (pos != std::string::npos) {
        pos += secure.size();
        std::string num;
        while (pos < path.size() && path[pos] >= '0' && path[pos] <= '9') {
            num += path[pos++];
        }
        userId = num.empty() ? 0 : static_cast<int32_t>(std::stoi(num));
    }
    std::string key;
    const std::string keyEq = "key=";
    auto kpos = query.find(keyEq);
    if (kpos != std::string::npos) {
        kpos += keyEq.size();
        while (kpos < query.size() && query[kpos] != '&') {
            key += query[kpos++];
        }
    }
    return { userId, key };
}

std::shared_ptr<DataShareHelper> DataShareHelper::Creator(const sptr<IRemoteObject> &, const std::string &,
    const std::string &, const int, bool)
{
    return std::make_shared<DataShareHelper>();
}

std::pair<int, std::shared_ptr<DataShareHelper>> DataShareHelper::Create(const sptr<IRemoteObject> &,
    const std::string &, const std::string &, const int)
{
    return { DataShare::E_OK, std::make_shared<DataShareHelper>() };
}

bool DataShareHelper::Release()
{
    return true;
}

std::shared_ptr<DataShareResultSet> DataShareHelper::Query(Uri &uri, const DataSharePredicates &,
    std::vector<std::string> &, DatashareBusinessError *)
{
    auto [userId, key] = ParseSettingsUri(uri);
    auto it = g_queryResults.find({ userId, key });
    if (it == g_queryResults.end()) {
        return std::make_shared<DataShareResultSet>();
    }
    return std::make_shared<DataShareResultSet>(it->second);
}

int DataShareHelper::RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &observer)
{
    g_lastRegisteredObserver = observer;
    g_registeredObservers[uri.ToString()] = observer;
    return DataShare::E_OK;
}

int DataShareHelper::UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &)
{
    g_registeredObservers.erase(uri.ToString());
    return DataShare::E_OK;
}
} // namespace DataShare
} // namespace OHOS
