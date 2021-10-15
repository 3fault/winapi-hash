pub mod wide;

#[macro_export]
macro_rules! to_va {
    ($base:expr, $offset:expr) => {
        ($base as winapi::shared::minwindef::LPBYTE).offset($offset as isize)
    };
}

// I forget where I got this trick from, will credit when found
#[macro_export]
macro_rules! infer_type {
    ($($tt:tt)*) => {
        _
    };
}

// Once const generics mature to allow const fn in traits, this macro can be cleaned up to remove the $alg:ty
#[macro_export]
macro_rules! api_call {
    ($resolver:expr, $alg:ty, $mod:literal -> $fn:literal ($($arg:expr),* $(,)?)) => {{
        const FN_HASH: [u8; <$alg>::OUTPUT_SIZE] = <$alg>::digest($fn.as_bytes());
        let function: fn($(crate::infer_type!($arg)),*) -> _ = unsafe {
            std::mem::transmute($resolver.resolve_fn($mod, FN_HASH).unwrap())
        };
        function($($arg),*)
    }};
}