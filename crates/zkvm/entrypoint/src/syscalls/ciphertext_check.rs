#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Executes the check ciphertexts
///
/// ### Safety
///
/// The caller must ensure that `inputs` and `output` are valid pointers to data that are aligned along
/// a four byte boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_ciphertext_check(inputs: *mut [u8; 48], result: *mut u32) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
        "syscall",
        in("$2") crate::syscalls::CIPHERTEXT_CHECK,
        in("$4") inputs,
        in("$5") result,
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}