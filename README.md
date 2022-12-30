# Windows API hashing in Rust

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![crates.io v0.1.0](https://img.shields.io/crates/v/winapi-hash)](https://crates.io/crates/winapi-hash)
[![docs.io v0.1.0](https://img.shields.io/docsrs/winapi-hash)](https://docs.rs/crate/winapi-hash/)

Highly experimental and untested.

## Example Usage & Demonstration
### MessageBoxW Example
#### Source
```rust
use windows::{
    Win32::UI::WindowsAndMessaging::{MessageBoxW, MB_OK},
    w,
};

fn main() {
    unsafe {
        MessageBoxW(None, w!("Hello, World!"), w!("MessageBox Example"), MB_OK);
    }
}
```
#### Decompilation
```c
int sub_140001000()
{
  const WCHAR *v0; // rsi
  const WCHAR *v1; // rdi
  HWND v2; // rax

  v0 = (const WCHAR *)sub_140001120(L"Hello, World!");
  v1 = (const WCHAR *)sub_140001120(L"Message Box Example");
  v2 = (HWND)sub_140001110(0i64);
  return MessageBoxW(v2, v0, v1, 0);
}
```
### After
```rust
#![feature(const_trait_impl)]

#[macro_use]
extern crate winapi_hash;

use winapi_hash::HashFunction;
use windows::{
    Win32::{Foundation::HWND, UI::WindowsAndMessaging::MB_OK},
    w,
};

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
    let resolver = winapi_hash::ApiHashResolver::<FNV1A64>::new();

    let _message_box_w_result: u32 = winapi_hash::api_call!(
        resolver, FNV1A64,
        "user32.dll" -> "MessageBoxW" (HWND::from(None), w!("Hello, World!"), w!("MessageBox Example"), MB_OK)
    );
}
```
Decompilation
```c
__int64 sub_140001B80()
{
  __int64 (__fastcall *v0)(__int64, __int64, __int64, _QWORD); // rdx
  __int64 (__fastcall *v1)(__int64, __int64, __int64, _QWORD); // rbx
  __int64 v2; // rsi
  __int64 v3; // rdi
  __int64 v4; // rax
  __int64 v6; // [rsp+38h] [rbp-20h]

  v6 = sub_140001100();
  if ( sub_140001000(&v6, "user32.dll", 10i64, 7995333796877250590i64) )
    sub_14001C4A0((__int64)"called `Result::unwrap()` on an `Err` value");
  v1 = v0;
  v2 = sub_140001CB0(0i64);
  v3 = sub_140001CC0(L"Hello, World!");
  v4 = sub_140001CC0(L"MessageBox Example");
  return v1(v2, v3, v4, 0i64);
}
```
The resulting decompilation has some obvious downsides to it as of this moment, it is immediately clear what the routine is doing however there are many potential improvements for the future. MessageBoxW at least does not show up in the IAT or strings.