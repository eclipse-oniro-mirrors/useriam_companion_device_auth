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

extern crate alloc;

use crate::vec;

use crate::common::constants::MAX_EVENT_NUM;
use crate::log_e;
use crate::traits::event_manager::{Event, EventManager, EventType};
use crate::Vec;

pub struct DefaultEventManager {
    events: Vec<Event>,
    has_fatal_error: bool,
}

impl DefaultEventManager {
    pub fn new() -> Self {
        Self { events: vec![], has_fatal_error: false }
    }

    fn remove_first_event(&mut self, event_type: EventType) -> Option<Event> {
        for i in 0..self.events.len() {
            if self.events[i].event_type == event_type {
                return Some(self.events.remove(i));
            }
        }
        None
    }
}

impl EventManager for DefaultEventManager {
    fn record_event(&mut self, event: &Event) {
        if event.event_type == EventType::FatalError {
            log_e!("record fatal error");
            self.has_fatal_error = true;
        }

        self.events.push(event.clone());
        while self.events.len() > MAX_EVENT_NUM {
            // avoid infinite loop
            let mut removed = false;
            for event_type in [EventType::Command, EventType::Error, EventType::BigData, EventType::FatalError] {
                if let Some(_event) = self.remove_first_event(event_type) {
                    removed = true;
                    break;
                }
            }
            if !removed {
                break;
            }
        }
    }

    fn has_fatal_error(&self) -> bool {
        self.has_fatal_error
    }

    fn drain_all_events(&mut self) -> Vec<Event> {
        let events = self.events.drain(..).collect();
        events
    }
}

impl Default for DefaultEventManager {
    fn default() -> Self {
        Self::new()
    }
}
