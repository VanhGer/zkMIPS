use crate::syscall_ciphertext_check;

pub fn ciphertext_check(
    gates_info: &[u8],
) -> bool {
    // assert the gates info
    assert_eq!(gates_info.len() % 64, 0);
    let num_gates = (gates_info.len() / 64) as u32;

    let mut input = num_gates.to_le_bytes().to_vec();
    input.extend_from_slice(gates_info);

    let mut output = 0_u32;
    unsafe {
        syscall_ciphertext_check(input.as_ptr(), &mut output);
    }
    assert!(output <= 1);
    output == 1
}