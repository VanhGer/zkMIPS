use crate::syscall_boolean_circuit_garble;

pub fn boolean_circuit_garble(gates_info: &[u8]) -> bool {
    // Validate layout
    assert_eq!(gates_info.len() % 68, 16);

    let num_gates = gates_info.len() / 68;
    let syscall_num = (num_gates - 1) / 62500 + 1;
    let base = num_gates / syscall_num;
    let remainder = num_gates - base * (syscall_num - 1);

    let base_bytes = base.to_le_bytes();
    let remainder_bytes = base.to_le_bytes();

    let delta = &gates_info[0..16];
    let mut output = 0_u32;
    let mut start_offset = 16;
    for _i in 0..syscall_num - 1 {
        // Gate data slice for this chunk
        let end_offset = start_offset + base * 68;
        // Precompute final input length: 4 (count) + 16 (delta) + gate bytes
        let input_len = 20 + base * 68;
        let mut input = vec![0u8; input_len];
        input[0..4].copy_from_slice(&base_bytes);
        input[4..20].copy_from_slice(delta);
        input[20..].copy_from_slice(&gates_info[start_offset..end_offset]);

        unsafe {
            syscall_boolean_circuit_garble(input.as_ptr(), &mut output);
        }
        assert!(output <= 1);
        if output == 0 {
            return false;
        }
        start_offset = end_offset;
    }

    let input_len = 20 + remainder * 68;
    let mut input = vec![0u8; input_len];
    input[0..4].copy_from_slice(&remainder_bytes);
    input[4..20].copy_from_slice(delta);
    input[20..].copy_from_slice(&gates_info[start_offset..]);
    unsafe {
        syscall_boolean_circuit_garble(input.as_ptr(), &mut output);
    }
    assert!(output <= 1);
    output == 1
}
