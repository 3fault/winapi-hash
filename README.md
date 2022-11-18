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
__int64 sub_140001640()
{
  __int64 (__fastcall *v0)(__int64); // rdi
  __int64 v1; // rsi
  __int64 v2; // rdi
  __int64 (__fastcall *v3)(__int64, __int64, __int64, _QWORD); // rdx
  __int64 (__fastcall *v4)(__int64, __int64, __int64, _QWORD); // rbx
  __int64 v5; // rsi
  __int64 v6; // rdi
  __int64 v7; // rax
  __int64 v9; // [rsp+28h] [rbp-38h]
  __int64 v10; // [rsp+30h] [rbp-30h]
  const char *v11; // [rsp+40h] [rbp-20h]
  char *v12; // [rsp+48h] [rbp-18h]
  __int16 v13; // [rsp+50h] [rbp-10h]
  int v14; // [rsp+58h] [rbp-8h]
  __int64 v15; // [rsp+60h] [rbp+0h]

  v15 = -2i64;
  v0 = (__int64 (__fastcall *)(__int64))sub_140001000();
  v11 = "user32.dll";
  v12 = "";
  v13 = 0;
  v14 = 1;
  sub_1400017F0(&v9, &v11);
  v1 = v9;
  v2 = v0(v9);
  if ( v10 )
    sub_140001CC0(v1, 2 * v10, 2i64);
  if ( sub_1400012E0(v2, 7995333796877250590i64) )
    sub_14001BF20((__int64)"called `Result::unwrap()` on an `Err` value");
  v4 = v3;
  v5 = sub_140001CF0(0i64);
  v6 = sub_140001D00(L"Hello, World!");
  v7 = sub_140001D00(L"MessageBox Example");
  return v4(v5, v6, v7, 0i64);
}
```
The resulting decompilation has some obvious downsides to it as of this moment, it is immediately clear what the routine is doing however there are many potential improvements for the future. MessageBoxW at least does not show up in the IAT or strings.