# Windows API hashing in Rust

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![crates.io v0.1.0](https://img.shields.io/crates/v/winapi-hash)](https://crates.io/crates/obfstr)
[![docs.io v0.1.0](https://img.shields.io/docsrs/winapi-hash)](https://docs.rs/crate/winapi-hash/)

Don't use

## Example Usage

```rust
// Const trait impls are currently experimental still
#![feature(const_trait_impl)]
#![allow(incomplete_features)]

#[macro_use]
extern crate winapi_hash;

// https://github.com/HindrikStegenga/const-fnv1a-hash
pub struct FNV1A64;
impl const winapi_hash::HashFunction for FNV1A64 {
    const OUTPUT_SIZE: usize = 8;
    fn digest(data: &[u8]) -> [u8; Self::OUTPUT_SIZE] {
        const FNV_OFFSET_BASIS_64: u64 = 0xcbf29ce484222325;
        const FNV_PRIME_64: u64 = 0x00000100000001B3;

        let mut hash = FNV_OFFSET_BASIS_64;
        let mut i = 0;
        while i < data.len() {
            hash ^= data[i] as u64;
            hash = hash.wrapping_mul(FNV_PRIME_64);
            i += 1;
        }
        hash.to_be_bytes()
    }
}

fn main() {
    use std::ffi::CString;
    use winapi::shared::ntdef::NULL;
    use winapi::um::winuser::{MB_ICONINFORMATION, MB_OK};
    use winapi_hash::HashFunction;

    let resolver = winapi_hash::ApiHashResolver::<FNV1A64>::new();
    let lp_text = CString::new("Hello, world!").unwrap();
    let lp_caption = CString::new("MessageBox Example").unwrap();

    // Automatically resolves then calls MessageBoxA and stores the result
    // If you don't care about what the function returns,
    // call the macro as "let _: () = api_call!(...);"
    let _message_box_a_result: u32 = winapi_hash::api_call!(
        resolver, FNV1A64, 
        "user32.dll" -> "MessageBoxA" (NULL, lp_text.as_ptr(), lp_caption.as_ptr(), MB_OK | MB_ICONINFORMATION)
    );
}
```