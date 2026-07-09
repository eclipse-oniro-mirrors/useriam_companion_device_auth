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

#ifndef FAKE_DATASHARE_HELPER_H
#define FAKE_DATASHARE_HELPER_H

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "data_ability_observer_interface.h"
#include "datashare_errno.h"
#include "datashare_predicates.h"
#include "datashare_result_set.h"
#include "iremote_object.h"
#include "uri.h"

using Uri = OHOS::Uri;

namespace OHOS {
namespace DataShare {
class DatashareBusinessError {};

// Observer registry seam: tracks every registered observer by URI string so tests can assert
// multi-key observation, active-user re-pointing (old URI removed, new URI added), and teardown.
// g_lastRegisteredObserver is kept as the most-recently-registered one for backward compatibility.
inline sptr<AAFwk::IDataAbilityObserver> g_lastRegisteredObserver;
inline std::map<std::string, sptr<AAFwk::IDataAbilityObserver>> g_registeredObservers;

// Query-result seam: keyed by (userId, settings key). Query parses the URI to look the value up, so a
// per-user isolation regression (wrong userId in the URI) is detectable rather than silently masked.
inline std::map<std::pair<int32_t, std::string>, std::string> g_queryResults;

void ResetDataShareFake();
void SetSettingsValue(int32_t userId, const std::string &key, std::string value);

// Extracts (userId, key) from a settings URI of the form
// ".../USER_SETTINGSDATA_SECURE_<userId>?Proxy=true&key=<key>". On parse failure the userId stays 0
// and/or the key stays empty, which simply yields a query miss.
std::pair<int32_t, std::string> ParseSettingsUri(Uri &uri);

class DataShareHelper {
public:
    virtual ~DataShareHelper() = default;

    static std::shared_ptr<DataShareHelper> Creator(const sptr<IRemoteObject> &, const std::string &,
        const std::string &, const int = 2, bool = false);

    static std::pair<int, std::shared_ptr<DataShareHelper>> Create(const sptr<IRemoteObject> &, const std::string &,
        const std::string &, const int = 2);

    bool Release();

    std::shared_ptr<DataShareResultSet> Query(Uri &uri, const DataSharePredicates &, std::vector<std::string> &,
        DatashareBusinessError *);

    int RegisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &observer);

    int UnregisterObserver(const Uri &uri, const sptr<AAFwk::IDataAbilityObserver> &);
};
} // namespace DataShare
} // namespace OHOS
#endif // FAKE_DATASHARE_HELPER_H
