pub mod image_export_directory;
pub mod module_entry_list;
pub mod wide;

#[doc(hidden)]
#[macro_export]
macro_rules! to_va {
    ($base:expr, $offset:expr) => {
        ($base as winapi::shared::minwindef::LPBYTE).offset($offset as isize)
    };
}

// I forget where I got this trick from, will credit when found
#[doc(hidden)]
#[macro_export]
macro_rules! infer_type {
    ($($tt:tt)*) => {
        _
    };
}

/// Macro that will automaically hash your function string, 
/// resolve and transmute the function, and finally call it.
/// 
/// This function will panic when the function cannot be resolved.
#[macro_export]
macro_rules! api_call {
    ($resolver:expr, $alg:ty, $mod:literal -> $fn:literal ($($arg:expr),* $(,)?)) => {{
        const FN_HASH: [u8; <$alg>::OUTPUT_SIZE] = <$alg>::digest($fn.as_bytes());
        let function: fn($(infer_type!($arg)),*) -> _ = unsafe {
            std::mem::transmute($resolver.resolve_fn($mod, FN_HASH).unwrap())
        };
        function($($arg),*)
    }};
}
