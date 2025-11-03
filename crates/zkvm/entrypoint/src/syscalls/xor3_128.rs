#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Executes the XOR of 3 128-bit values.
///
/// ### Safety
///
/// The caller must ensure that `inputs` and `result` are valid pointers to data that are aligned along
/// a four byte boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_xor3_128(inputs: *mut [u8; 48], result: *mut [u8; 16]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
        "syscall",
        in("$2") crate::syscalls::XOR3_128,
        in("$4") inputs,
        in("$5") result,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}