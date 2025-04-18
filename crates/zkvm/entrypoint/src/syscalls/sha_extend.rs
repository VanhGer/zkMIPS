#[cfg(target_os = "zkvm")]
use core::arch::asm;

/// Executes the SHA256 extend operation on the given word array.
///
/// ### Safety
///
/// The caller must ensure that `w` is valid pointer to data that is aligned along a four byte
/// boundary.
#[allow(unused_variables)]
#[no_mangle]
pub extern "C" fn syscall_sha256_extend(w: *mut [u32; 64]) {
    #[cfg(target_os = "zkvm")]
    unsafe {
        asm!(
            "syscall",
            in("$2") crate::syscalls::SHA_EXTEND,
            in("$4") w,
            in("$5") 0
        );
    }

    #[cfg(not(target_os = "zkvm"))]
    unreachable!()
}
