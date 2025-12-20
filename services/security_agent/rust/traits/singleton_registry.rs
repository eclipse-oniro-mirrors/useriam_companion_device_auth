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

#[macro_export]
macro_rules! singleton_registry {
    ($registry_name:ident, $trait_name:ident, $dummy_type:ident) => {
        static mut INSTANCE: Option<crate::Box<dyn $trait_name>> = None;

        pub struct $registry_name;

        impl $registry_name {
            #[allow(static_mut_refs)]
            pub fn get() -> &'static crate::Box<dyn $trait_name> {
                unsafe {
                    if INSTANCE.is_none() {
                        INSTANCE = Some(crate::Box::new($dummy_type));
                    }
                    INSTANCE.as_ref().unwrap()
                }
            }

            #[allow(static_mut_refs)]
            pub fn get_mut() -> &'static mut crate::Box<dyn $trait_name> {
                unsafe {
                    if INSTANCE.is_none() {
                        INSTANCE = Some(crate::Box::new($dummy_type));
                    }
                    INSTANCE.as_mut().unwrap()
                }
            }

            pub fn set(instance: crate::Box<dyn $trait_name>) {
                unsafe {
                    INSTANCE = Some(instance);
                }
            }

            pub fn reset() {
                unsafe {
                    INSTANCE = Some(crate::Box::new($dummy_type));
                }
            }
        }
    };
}
