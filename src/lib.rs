/*!
This crate is a simple implementation of Windows API hashing using
some expiremental features such as [generic_const_exprs](https://github.com/rust-lang/rust/issues/76560) 
and [adt_const_params](https://github.com/rust-lang/rust/issues/44580).
It should be noted that this crate is very unsafe and should be used with
extreme caution or just as a proof of concept.

There are many good resources outlining the concept behind API hashing such as
on [ired.team](https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware), 
or on [0xf0x's blog](https://neil-fox.github.io/Anti-analysis-using-api-hashing/).
*/

#![feature(adt_const_params)]
#![feature(const_trait_impl)]
#![feature(generic_const_exprs)]
#![feature(associated_type_defaults)]
#![allow(dead_code)]
#![allow(incomplete_features)]
#![warn(missing_docs)]
//#![warn(rustdoc::missing_doc_code_examples)]

pub use winapi;
mod util;

use crate::util::wide::*;
use winapi::{
    shared::{basetsd::ULONG_PTR, minwindef::HMODULE},
    um::winnt::LPCWSTR,
};

/// A trait providing a common digest function and length to be used by the
/// [ApiHashResolver](struct.ApiHashResolver.html).
#[const_trait]
pub trait HashFunction {
    /// The output size of the digest in bytes, the [digest function](#tymethod.digest)
    /// will return an array of [`u8`] of the output size.
    const OUTPUT_SIZE: usize;

    /// Generic digest algorithm that takes an array of [`u8`],
    /// and return an array of [`u8`] with a size of [OUTPUT_SIZE](#associatedconstant.OUTPUT_SIZE),
    /// also known as the digest length. For example, a [SHA256](https://docs.rs/sha2-const/0.1.1/sha2_const/) 
    /// implementation would use an [OUTPUT_SIZE](#associatedconstant.OUTPUT_SIZE) of 32.
    fn digest(data: &[u8]) -> [u8; Self::OUTPUT_SIZE];
}

/// Generic structure holding a [HashFunction](trait.HashFunction.html) trait with
/// associated functions used for resolving windows APIs dynamically.
pub struct ApiHashResolver<H> {
    load_library: fn(LPCWSTR) -> HMODULE,
    _marker: core::marker::PhantomData<H>,
}

impl<H: HashFunction> ApiHashResolver<H>
where
    [(); H::OUTPUT_SIZE]: ,
{
    /// Creates a new API hash resolver structure.
    /// 
    /// This automatically resolves 
    /// [LoadLibraryW](https://docs.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-loadlibraryw/)
    /// in Kernel32.dll to be used in the future by the resolution functions.
    pub fn new() -> Self {
        let load_library = unsafe {
            std::mem::transmute::<ULONG_PTR, fn(LPCWSTR) -> HMODULE>(
                ApiHashResolver::<H>::resolve(
                    ApiHashResolver::<H>::get_module_base("KERNEL32.DLL").unwrap(),
                    H::digest("LoadLibraryW".as_bytes()),
                )
                .unwrap(),
            )
        };
        Self {
            load_library,
            _marker: core::marker::PhantomData,
        }
    }

    /// A function that will resolve a module and function name hash 
    /// into a [ULONG_PTR](https://docs.rs/winapi/0.3.9/winapi/shared/basetsd/type.ULONG_PTR.html) ([`usize`]).
    /// 
    /// To then use this function, it will have to be transmuted
    /// into a function pointer with with the correct signature.
    /// See the [std::mem::transmute examples](https://doc.rust-lang.org/stable/std/mem/fn.transmute.html#examples)
    /// or the [api_call](macro.api_call.html) macro for more information.
    pub unsafe fn resolve_fn(
        &self,
        module_name: &[u8],
        hash: [u8; H::OUTPUT_SIZE],
    ) -> Result<ULONG_PTR, ()> {
        let module: HMODULE = (self.load_library)(ToWide::to_wide_null(&std::str::from_utf8(module_name).unwrap()).as_ptr());
        ApiHashResolver::<H>::resolve(module, hash)
    }

    unsafe fn resolve(handle: HMODULE, hash: [u8; H::OUTPUT_SIZE]) -> Result<ULONG_PTR, ()> {
        use crate::util::image_export_directory::ExportDirectoryList;
        use winapi::um::winnt::*;

        if !ApiHashResolver::<H>::is_valid_module(handle) {
            return Err(());
        }

        let dos_hdr: IMAGE_DOS_HEADER = *(handle as PIMAGE_DOS_HEADER);
        let nt_hdr: IMAGE_NT_HEADERS = *(to_va!(handle, dos_hdr.e_lfanew) as PIMAGE_NT_HEADERS);
        let exp_dir: IMAGE_EXPORT_DIRECTORY = *(to_va!(
            handle,
            nt_hdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
                .VirtualAddress
        ) as PIMAGE_EXPORT_DIRECTORY);

        let export_list = ExportDirectoryList::new(handle, exp_dir);
        for export in export_list {
            if hash == H::digest(export.1.as_bytes()) {
                return Ok(export.0);
            }
        }

        Err(())
    }

    unsafe fn get_module_base(module: &str) -> Result<HMODULE, ()> {
        use crate::util::module_entry_list::ModuleEntryList;
        use ntapi::winapi_local::um::winnt::NtCurrentTeb;
        use std::ffi::OsString;

        for entry in ModuleEntryList::new(
            &mut (*(*(*(NtCurrentTeb())).ProcessEnvironmentBlock).Ldr).InMemoryOrderModuleList,
        ) {
            let entry_name: OsString = FromWide::from_wide_ptr_null(entry.BaseDllName.Buffer);

            if module == entry_name.to_string_lossy().into_owned() {
                return Ok(entry.DllBase as HMODULE);
            }
        }

        Err(())
    }

    unsafe fn is_valid_module(handle: HMODULE) -> bool {
        use winapi::{
            shared::{minwindef::DWORD, ntdef::NULL},
            um::winnt::*,
        };

        if handle == NULL as HMODULE {
            return false;
        }

        let dos_hdr = *(handle as PIMAGE_DOS_HEADER) as IMAGE_DOS_HEADER;
        if dos_hdr.e_magic != IMAGE_DOS_SIGNATURE {
            return false;
        }

        let nt_hdr = *(to_va!(handle, dos_hdr.e_lfanew) as PIMAGE_NT_HEADERS) as IMAGE_NT_HEADERS;
        if nt_hdr.Signature as DWORD != IMAGE_NT_SIGNATURE {
            return false;
        }
        if nt_hdr.FileHeader.Characteristics & IMAGE_FILE_DLL == 0 {
            return false;
        }

        let data_dir = nt_hdr.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
        if data_dir.VirtualAddress == 0 || data_dir.Size == 0 {
            return false;
        }

        true
    }
}
