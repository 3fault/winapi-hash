pub mod wide;

#[macro_export]
macro_rules! to_va {
    ($base:expr, $offset:expr) => {
        ($base as winapi::shared::minwindef::LPBYTE).offset($offset as isize)
    };
}
