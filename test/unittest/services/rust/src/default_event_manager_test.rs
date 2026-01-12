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

use crate::common::constants::MAX_EVENT_NUM;
use crate::impls::default_event_manager::DefaultEventManager;
use crate::log_i;
use crate::traits::event_manager::{Event, EventManager, EventType};
use crate::ut_registry_guard;
use std::ffi::CString;

fn create_test_event(event_type: EventType) -> Event {
    Event {
        time: 1000,
        file_name: CString::new("file_name").expect("CString::new failed"),
        line_number: 1,
        event_type,
        event_info: CString::new("event_info").expect("CString::new failed"),
    }
}

#[test]
fn default_event_manager_new_test() {
    let _guard = ut_registry_guard!();
    log_i!("default_event_manager_new_test start");

    let manager = DefaultEventManager::new();
    assert_eq!(manager.has_fatal_error(), false);
}

#[test]
fn default_event_manager_record_event_test_command() {
    let _guard = ut_registry_guard!();
    log_i!("default_event_manager_record_event_test_command start");

    let mut manager = DefaultEventManager::new();
    let event = create_test_event(EventType::Command);

    manager.record_event(&event);

    assert_eq!(manager.has_fatal_error(), false);
    let events = manager.drain_all_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, EventType::Command);
}

#[test]
fn default_event_manager_record_event_test_fatal_error() {
    let _guard = ut_registry_guard!();
    log_i!("default_event_manager_record_event_test_fatal_error start");

    let mut manager = DefaultEventManager::new();
    let event = create_test_event(EventType::FatalError);

    manager.record_event(&event);

    assert_eq!(manager.has_fatal_error(), true);
    let events = manager.drain_all_events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].event_type, EventType::FatalError);
}

#[test]
fn default_event_manager_record_event_test_max_events_remove_command() {
    let _guard = ut_registry_guard!();
    log_i!("default_event_manager_record_event_test_max_events_remove_command start");

    let mut manager = DefaultEventManager::new();

    for _i in 0..MAX_EVENT_NUM {
        let event = create_test_event(EventType::Command);
        manager.record_event(&event);
    }

    let new_event = create_test_event(EventType::Command);
    manager.record_event(&new_event);

    let events = manager.drain_all_events();
    assert_eq!(events.len(), MAX_EVENT_NUM);
}

#[test]
fn default_event_manager_record_event_test_max_events_remove_empty() {
    let _guard = ut_registry_guard!();
    log_i!("default_event_manager_record_event_test_max_events_remove_empty start");

    let mut manager = DefaultEventManager::new();

    for _i in 0..MAX_EVENT_NUM {
        let event = create_test_event(EventType::Empty);
        manager.record_event(&event);
    }

    let new_event = create_test_event(EventType::Empty);
    manager.record_event(&new_event);

    let events = manager.drain_all_events();
    assert_eq!(events.len(), MAX_EVENT_NUM + 1);
}
