const BUFFER_CAPACITY: usize = 1024 * 1024;

/// The least room a read is given - the first read of a connection gets this much.
const MIN_READ_ROOM: usize = 16 * 1024;

pub struct LoopBuffer {
    /// Allocated once, at [`BUFFER_CAPACITY`]. Its length is how far it is zeroed: only that part
    /// is ever handed out, so no read gets memory nothing was written to.
    data: Vec<u8>,
    read_from: usize,
    read_to: usize,
    /// A read filled all the room it was given: the source has more at a time than that, and the
    /// next read is given twice the room.
    filled: bool,
}

impl LoopBuffer {
    pub fn new() -> Self {
        Self {
            data: Vec::with_capacity(BUFFER_CAPACITY),
            read_from: 0,
            read_to: 0,
            filled: false,
        }
    }

    pub fn advance(&mut self, size: usize) {
        debug_assert!(
            self.read_to + size <= self.data.len(),
            "advanced past the room handed out"
        );
        self.read_to += size;

        if size > 0 && self.read_to == self.data.len() {
            self.filled = true;
        }
    }

    fn gc(&mut self) {
        if self.read_from == 0 {
            return;
        }

        if self.read_from == self.read_to {
            self.read_from = 0;
            self.read_to = 0;
            return;
        }

        if BUFFER_CAPACITY - self.read_to > 65535 {
            return;
        }

        self.data.copy_within(self.read_from..self.read_to, 0);
        self.read_to -= self.read_from;
        self.read_from = 0;
    }

    pub fn get_mut(&mut self) -> Option<&mut [u8]> {
        self.gc();

        if self.read_to >= BUFFER_CAPACITY {
            return None;
        }

        // Zeroed ahead of a read, as far as the read is given room - which doubles while reads
        // fill it. A connection of small requests keeps to the start of the buffer and never
        // touches the rest; a large transfer reads as much at a time as before within a few
        // reads, whether its bytes stay in the buffer or are sent on after every read. No byte is
        // zeroed twice.
        if self.filled || self.data.len() - self.read_to < MIN_READ_ROOM {
            let zeroed = (self.data.len() * 2)
                .max(self.read_to + MIN_READ_ROOM)
                .min(BUFFER_CAPACITY);
            self.data.resize(zeroed, 0);
            self.filled = false;
        }

        Some(&mut self.data[self.read_to..])
    }

    pub fn get_data(&self) -> &[u8] {
        &self.data[self.read_from..self.read_to]
    }

    pub fn commit_read(&mut self, size: usize) {
        self.read_from += size;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What a socket read does: fills the room it is given, up to `available`.
    fn read_into(buffer: &mut LoopBuffer, byte: u8, available: usize) -> usize {
        let room = buffer.get_mut().expect("the buffer is full");
        let size = room.len().min(available);
        room[..size].fill(byte);
        buffer.advance(size);
        size
    }

    #[test]
    fn the_first_read_gets_a_zeroed_room_of_its_own_size_only() {
        let mut buffer = LoopBuffer::new();

        let room = buffer.get_mut().unwrap();
        assert_eq!(room.len(), MIN_READ_ROOM);
        assert!(room.iter().all(|byte| *byte == 0));

        assert!(
            buffer.data.capacity() >= BUFFER_CAPACITY,
            "allocated at once"
        );
    }

    #[test]
    fn small_requests_one_after_another_never_go_past_the_first_room() {
        let mut buffer = LoopBuffer::new();

        for _ in 0..100 {
            let size = read_into(&mut buffer, b'r', 700);
            assert_eq!(buffer.get_data().len(), size);
            buffer.commit_read(size);
        }

        assert_eq!(buffer.data.len(), MIN_READ_ROOM);
    }

    #[test]
    fn a_large_transfer_fills_the_whole_capacity_and_keeps_every_byte() {
        let mut buffer = LoopBuffer::new();
        let capacity = buffer.data.capacity();
        let mut total = 0;
        let mut reads = 0;

        while buffer.get_mut().is_some() {
            let byte = (reads % 251) as u8;
            let start = total;
            total += read_into(&mut buffer, byte, usize::MAX);
            reads += 1;

            assert!(buffer.get_data()[start..total].iter().all(|b| *b == byte));
        }

        assert_eq!(total, BUFFER_CAPACITY);
        assert_eq!(buffer.get_data().len(), BUFFER_CAPACITY);
        assert!(
            reads <= 8,
            "the zeroed part doubles: {reads} reads to fill it"
        );
        assert_eq!(buffer.data.capacity(), capacity, "never allocated again");
    }

    /// The body pumps send on all they hold before they read again: every read starts at the
    /// beginning of the buffer, and still gets more room while the source keeps filling it.
    #[test]
    fn a_transfer_sent_on_after_every_read_is_given_more_room_while_reads_come_full() {
        let mut buffer = LoopBuffer::new();
        let mut rooms = Vec::new();

        for _ in 0..10 {
            rooms.push(buffer.get_mut().unwrap().len());
            let size = read_into(&mut buffer, b'b', usize::MAX);
            buffer.commit_read(size);
        }

        assert_eq!(
            rooms,
            [16, 32, 64, 128, 256, 512, 1024, 1024, 1024, 1024].map(|kb| kb * 1024)
        );

        // A read which does not fill its room gets no more room after it.
        let mut buffer = LoopBuffer::new();
        let size = read_into(&mut buffer, b'c', MIN_READ_ROOM - 1);
        buffer.commit_read(size);
        assert_eq!(buffer.get_mut().unwrap().len(), MIN_READ_ROOM);
    }

    #[test]
    fn what_is_left_is_moved_to_the_start_when_the_end_is_near() {
        let mut buffer = LoopBuffer::new();

        while buffer.get_mut().is_some() {
            read_into(&mut buffer, b'a', usize::MAX);
        }

        // All but the last 10 bytes are taken; the next read finds them at the start.
        let mut data = buffer.get_data().to_vec();
        data[BUFFER_CAPACITY - 10..].fill(b'z');
        buffer.data[BUFFER_CAPACITY - 10..].fill(b'z');
        buffer.commit_read(BUFFER_CAPACITY - 10);

        let room = buffer.get_mut().unwrap();
        assert_eq!(room.len(), BUFFER_CAPACITY - 10);
        assert_eq!(buffer.get_data(), &data[BUFFER_CAPACITY - 10..]);
    }
}
