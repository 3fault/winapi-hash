use crate::{to_va, winapi::um::winnt::LPCSTR};
use winapi::{
    shared::{
        basetsd::ULONG_PTR,
        minwindef::{HMODULE, PDWORD, PWORD},
    },
    um::winnt::IMAGE_EXPORT_DIRECTORY,
};

pub struct ExportDirectoryList {
    handle: HMODULE,
    exp_dir: IMAGE_EXPORT_DIRECTORY,
    index: u32,
}

impl ExportDirectoryList {
    pub fn new(handle: HMODULE, exp_dir: IMAGE_EXPORT_DIRECTORY) -> Self {
        Self {
            handle,
            exp_dir,
            index: 0,
        }
    }
}

impl Iterator for ExportDirectoryList {
    type Item = (ULONG_PTR, String);

    fn next(&mut self) -> Option<Self::Item> {
        if self.index > self.exp_dir.NumberOfNames {
            return None;
        }

        unsafe {
            let exp_addrs = to_va!(self.handle, self.exp_dir.AddressOfFunctions) as PDWORD;
            let exp_names = to_va!(self.handle, self.exp_dir.AddressOfNames) as PDWORD;
            let exp_ords = to_va!(self.handle, self.exp_dir.AddressOfNameOrdinals) as PWORD;

            let fn_name = std::ffi::CStr::from_ptr(to_va!(
                self.handle,
                *exp_names.add(self.index as usize)
            ) as LPCSTR)
            .to_str()
            .unwrap();

            let fn_ptr = to_va!(
                self.handle,
                *(exp_addrs.add(*(exp_ords.add(self.index as usize)) as usize))
            ) as ULONG_PTR;

            self.index += 1;

            Some((fn_ptr, fn_name.to_string()))
        }
    }
}
