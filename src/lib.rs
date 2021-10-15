#![feature(asm)]
#![feature(adt_const_params)]
#![feature(generic_const_exprs)]
#![allow(dead_code)]
#![allow(incomplete_features)]

pub use winapi;
mod util;

use winapi::{
    shared::{basetsd::ULONG_PTR, minwindef::HMODULE},
    um::winnt::LPCWSTR,
};

pub trait HashFunction {
    const OUTPUT_SIZE: usize;
    fn digest(data: &[u8]) -> [u8; Self::OUTPUT_SIZE];
}

pub struct ApiHashResolver<H> {
    pub load_library: fn(LPCWSTR) -> HMODULE,
    _marker: core::marker::PhantomData<H>,
}

impl<H: HashFunction> ApiHashResolver<H>
where
    [(); H::OUTPUT_SIZE]: ,
{
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

    pub unsafe fn resolve_fn(
        &self,
        module_name: &str,
        hash: [u8; H::OUTPUT_SIZE],
    ) -> Result<ULONG_PTR, ()> {
        let module: HMODULE =
            (self.load_library)(util::wide::ToWide::to_wide_null(&module_name).as_ptr());
        ApiHashResolver::<H>::resolve(module, hash)
    }

    unsafe fn resolve(handle: HMODULE, hash: [u8; H::OUTPUT_SIZE]) -> Result<ULONG_PTR, ()> {
        use winapi::{
            shared::minwindef::{PDWORD, PWORD},
            um::winnt::*,
        };

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

        let exp_addrs = to_va!(handle, exp_dir.AddressOfFunctions) as PDWORD;
        let exp_names = to_va!(handle, exp_dir.AddressOfNames) as PDWORD;
        let exp_ords = to_va!(handle, exp_dir.AddressOfNameOrdinals) as PWORD;

        // TODO: Create an iterator util for this loop
        let mut i = 0;
        while i < exp_dir.NumberOfNames {
            let fn_name =
                std::ffi::CStr::from_ptr(to_va!(handle, *exp_names.add(i as usize)) as LPCSTR)
                    .to_str()
                    .unwrap();

            if hash == H::digest(fn_name.as_bytes()) {
                return Ok(to_va!(
                    handle,
                    *(exp_addrs.add(*(exp_ords.add(i as usize)) as usize))
                ) as ULONG_PTR);
            }

            i += 1;
        }

        Ok(0)
    }

    unsafe fn get_module_base(module: &str) -> Result<HMODULE, ()> {
        use ntapi::{
            ntldr::{LDR_DATA_TABLE_ENTRY, PLDR_DATA_TABLE_ENTRY},
            ntpebteb::PTEB,
            FIELD_OFFSET,
        };
        use std::ffi::OsString;
        use util::wide::FromWide;
        use winapi::shared::ntdef::PLIST_ENTRY;

        // TODO: Change from inline x86 to __readgsqword and __readfsdword macros for better cross-compatibility
        let mut pteb: PTEB;
        if cfg!(target_arch = "x86") {
            asm!("mov {0}, FS:[0x18]", out(reg) pteb);
        } else if cfg!(target_arch = "x86_64") {
            asm!("mov {0}, GS:[0x30]", out(reg) pteb);
        } else {
            return Err(());
        }

        let head: PLIST_ENTRY =
            &mut (*(*(*(pteb)).ProcessEnvironmentBlock).Ldr).InMemoryOrderModuleList;
        let mut curr: PLIST_ENTRY = (*head).Flink;

        // TODO: Create an iterator util for this linked list
        while curr != head {
            let entry = (curr as usize - FIELD_OFFSET!(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks))
                as PLDR_DATA_TABLE_ENTRY;

            let entry_name = {
                let entry_name: OsString =
                    FromWide::from_wide_ptr_null((*entry).BaseDllName.Buffer);
                entry_name.to_string_lossy().into_owned()
            };

            if module == entry_name {
                return Ok((*entry).DllBase as HMODULE);
            }

            curr = (*curr).Flink;
        }

        Err(())
    }

    unsafe fn is_valid_module(handle: HMODULE) -> bool {
        use winapi::{
            shared::{minwindef::DWORD, ntdef::NULL},
            um::winnt::{
                IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE,
                IMAGE_FILE_DLL, IMAGE_NT_HEADERS, IMAGE_NT_SIGNATURE, PIMAGE_DOS_HEADER,
                PIMAGE_NT_HEADERS,
            },
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
