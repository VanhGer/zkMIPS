use crate::syscall_xor3_128;

/// Precompile of xor of 3 128-bit values.
pub fn xor3_128(
    a: &[u8; 16],
    b: &[u8; 16],
    c: &[u8; 16],
) -> [u8; 16] {
    // convert to u32 tro align the memory
    let mut inputs = [0u8; 48];
    let mut result = [0u8; 16];
    inputs[0..16].copy_from_slice(a);
    inputs[16..32].copy_from_slice(b);
    inputs[32..48].copy_from_slice(c);
    
    unsafe {
        syscall_xor3_128(&mut inputs, &mut result);
    }
    result
}