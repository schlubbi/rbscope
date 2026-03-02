// Stack frame serialization for rbscope.
//
// Stacks are serialized as a compact binary format using frame indices
// rather than string concatenation (original tracecap used newline-delimited
// "package:file:line:method\n" strings — 10-50x larger).
//
// Binary format (little-endian):
//   [u16: num_frames]
//   [FrameEntry × num_frames]:
//     u32: function_name_id  (index into string table)
//     u32: file_name_id      (index into string table)
//     u32: line_number
//
// The string table is maintained per-process by the collector, not
// transmitted with every sample. Frame IDs are resolved by the collector
// using /proc/<pid>/maps and DWARF info, or by reading the Ruby VM's
// string table via the USDT probe metadata.

use std::io::{self, Read, Write};

/// A single frame in a Ruby call stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StackFrame {
    pub function_name_id: u32,
    pub file_name_id: u32,
    pub line_number: u32,
}

/// A captured Ruby call stack.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stack {
    pub frames: Vec<StackFrame>,
}

impl Stack {
    pub fn new() -> Self {
        Self { frames: Vec::new() }
    }

    /// Serialize the stack to the compact binary format.
    pub fn serialize(&self, writer: &mut impl Write) -> io::Result<()> {
        let num_frames = self.frames.len().min(u16::MAX as usize) as u16;
        writer.write_all(&num_frames.to_le_bytes())?;

        for frame in self.frames.iter().take(num_frames as usize) {
            writer.write_all(&frame.function_name_id.to_le_bytes())?;
            writer.write_all(&frame.file_name_id.to_le_bytes())?;
            writer.write_all(&frame.line_number.to_le_bytes())?;
        }

        Ok(())
    }

    /// Deserialize a stack from the compact binary format.
    pub fn deserialize(reader: &mut impl Read) -> io::Result<Self> {
        let mut num_buf = [0u8; 2];
        reader.read_exact(&mut num_buf)?;
        let num_frames = u16::from_le_bytes(num_buf) as usize;

        let mut frames = Vec::with_capacity(num_frames);
        for _ in 0..num_frames {
            let mut buf = [0u8; 4];

            reader.read_exact(&mut buf)?;
            let function_name_id = u32::from_le_bytes(buf);

            reader.read_exact(&mut buf)?;
            let file_name_id = u32::from_le_bytes(buf);

            reader.read_exact(&mut buf)?;
            let line_number = u32::from_le_bytes(buf);

            frames.push(StackFrame {
                function_name_id,
                file_name_id,
                line_number,
            });
        }

        Ok(Self { frames })
    }

    /// Byte size of the serialized representation.
    pub fn serialized_size(&self) -> usize {
        2 + self.frames.len().min(u16::MAX as usize) * 12
    }
}

impl Default for Stack {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_empty_stack_round_trip() {
        let stack = Stack::new();
        let mut buf = Vec::new();
        stack.serialize(&mut buf).unwrap();
        assert_eq!(buf.len(), 2); // just the frame count

        let mut cursor = Cursor::new(&buf);
        let decoded = Stack::deserialize(&mut cursor).unwrap();
        assert_eq!(decoded, stack);
    }

    #[test]
    fn test_stack_round_trip() {
        let stack = Stack {
            frames: vec![
                StackFrame {
                    function_name_id: 1,
                    file_name_id: 100,
                    line_number: 42,
                },
                StackFrame {
                    function_name_id: 2,
                    file_name_id: 101,
                    line_number: 99,
                },
                StackFrame {
                    function_name_id: 3,
                    file_name_id: 100,
                    line_number: 7,
                },
            ],
        };

        let mut buf = Vec::new();
        stack.serialize(&mut buf).unwrap();
        assert_eq!(buf.len(), stack.serialized_size());

        let mut cursor = Cursor::new(&buf);
        let decoded = Stack::deserialize(&mut cursor).unwrap();
        assert_eq!(decoded, stack);
    }

    #[test]
    fn test_serialized_size() {
        let stack = Stack {
            frames: vec![StackFrame {
                function_name_id: 0,
                file_name_id: 0,
                line_number: 0,
            }; 5],
        };
        // 2 bytes header + 5 frames × 12 bytes each
        assert_eq!(stack.serialized_size(), 62);
    }

    #[test]
    fn test_truncation_at_max_frames() {
        let stack = Stack {
            frames: vec![StackFrame {
                function_name_id: 1,
                file_name_id: 2,
                line_number: 3,
            }; u16::MAX as usize + 100],
        };

        let mut buf = Vec::new();
        stack.serialize(&mut buf).unwrap();

        let mut cursor = Cursor::new(&buf);
        let decoded = Stack::deserialize(&mut cursor).unwrap();
        assert_eq!(decoded.frames.len(), u16::MAX as usize);
    }
}
