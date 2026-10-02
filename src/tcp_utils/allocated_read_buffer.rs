pub const READ_LOOP_SIZE: usize = 1024 * 1024;

pub fn allocated_read_buffer(size: Option<usize>) -> Vec<u8> {
    vec![0u8; size.unwrap_or(READ_LOOP_SIZE)]
}
