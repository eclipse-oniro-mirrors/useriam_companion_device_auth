/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

use crate::singleton_registry;
use crate::CString;
use crate::{log_e, Vec};
#[cfg(any(test, feature = "test-utils"))]
use mockall::automock;

#[derive(Clone, Copy, PartialEq, Debug, Default)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
#[repr(i32)]
pub enum EventType {
    #[default]
    Empty = 0,
    Command = 1,
    Error = 2,
    BigData = 3,
    FatalError = 4,
}

#[derive(Clone, Default)]
#[cfg_attr(feature = "test-utils", derive(serde::Serialize, serde::Deserialize))]
pub struct Event {
    pub time: u64,
    pub file_name: CString,
    pub line_number: u32,
    pub event_type: EventType,
    pub event_info: CString,
}

#[cfg_attr(any(test, feature = "test-utils"), automock)]
pub trait EventManager {
    fn record_event(&mut self, event: &Event) -> ();
    fn has_fatal_error(&self) -> bool;
    fn drain_all_events(&mut self) -> Vec<Event>;
}

pub struct DummyEventManager;

impl EventManager for DummyEventManager {
    fn record_event(&mut self, _event: &Event) -> () {
        log_e!("not implemented");
    }

    fn has_fatal_error(&self) -> bool {
        log_e!("not implemented");
        false
    }

    fn drain_all_events(&mut self) -> Vec<Event> {
        log_e!("not implemented");
        Vec::new()
    }
}

singleton_registry!(EventManagerRegistry, EventManager, DummyEventManager);

#[cfg(test)]
mod tests {
    use std::hint::assert_unchecked;

    use super::*;

    #[test]
    fn dummy_event_manager_test() {
        let mut dummy_event_manager = DummyEventManager;
        dummy_event_manager.record_event(&Event {
            time: 0,
            file_name: CString::default(),
            line_number: 0,
            event_type: EventType::BigData,
            event_info: CString::default(),
        });
        assert_eq!(dummy_event_manager.has_fatal_error(), false);
        assert!(dummy_event_manager.drain_all_events().is_empty());
    }
}
