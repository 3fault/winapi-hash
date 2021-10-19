use ntapi::{
    ntldr::{LDR_DATA_TABLE_ENTRY, PLDR_DATA_TABLE_ENTRY},
    FIELD_OFFSET,
};
use winapi::shared::ntdef::PLIST_ENTRY;

pub struct ModuleEntryList {
    head: PLIST_ENTRY,
    curr: PLIST_ENTRY,
}

impl ModuleEntryList {
    pub unsafe fn new(head: PLIST_ENTRY) -> Self {
        Self {
            head,
            curr: (*head).Flink,
        }
    }
}

impl Iterator for ModuleEntryList {
    type Item = LDR_DATA_TABLE_ENTRY;

    fn next(&mut self) -> Option<Self::Item> {
        if self.head == self.curr {
            return None;
        }

        unsafe {
            self.curr = (*self.curr).Flink;

            Some(
                (*((self.curr as usize - FIELD_OFFSET!(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks))
                    as PLDR_DATA_TABLE_ENTRY)) as LDR_DATA_TABLE_ENTRY,
            )
        }
    }
}
