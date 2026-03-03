// Stack frame serialization for rbscope.
//
// Two formats are supported:
//
// Format v1 — ID-based (compact, requires external string table):
//   [u16: num_frames]
//   [FrameEntry × num_frames]:
//     u32: function_name_id  (index into string table)
//     u32: file_name_id      (index into string table)
//     u32: line_number
//
// Format v2 — Inline strings (self-describing, used for real stack capture):
//   [u8: version = 2]
//   [u16: num_frames]
//   [InlineFrameEntry × num_frames]:
//     u16: label_len
//     [label_len bytes: UTF-8 label, e.g. "UsersController#index"]
//     u16: path_len
//     [path_len bytes: UTF-8 file path]
//     u32: line_number
//
// The v2 format is produced by the gem's postponed job callback after
// calling rb_profile_thread_frames. The collector parses it directly
// into pprof Function/Location entries — no symbol resolution needed.

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

// --- Format v2: Inline string frames ---

/// Format version byte for inline string stacks.
pub const INLINE_FORMAT_VERSION: u8 = 2;

/// A single frame with embedded string data (format v2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineFrame {
    pub label: String, // e.g. "UsersController#index"
    pub path: String,  // e.g. "/app/controllers/users_controller.rb"
    pub line: u32,
}

/// A stack with inline string frames (format v2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineStack {
    pub frames: Vec<InlineFrame>,
}

impl InlineStack {
    pub fn new() -> Self {
        Self { frames: Vec::new() }
    }

    /// Serialize to format v2 (inline strings, little-endian).
    pub fn serialize(&self, writer: &mut impl Write) -> io::Result<()> {
        writer.write_all(&[INLINE_FORMAT_VERSION])?;

        let num_frames = self.frames.len().min(u16::MAX as usize) as u16;
        writer.write_all(&num_frames.to_le_bytes())?;

        for frame in self.frames.iter().take(num_frames as usize) {
            let label = frame.label.as_bytes();
            let label_len = label.len().min(u16::MAX as usize) as u16;
            writer.write_all(&label_len.to_le_bytes())?;
            writer.write_all(&label[..label_len as usize])?;

            let path = frame.path.as_bytes();
            let path_len = path.len().min(u16::MAX as usize) as u16;
            writer.write_all(&path_len.to_le_bytes())?;
            writer.write_all(&path[..path_len as usize])?;

            writer.write_all(&frame.line.to_le_bytes())?;
        }

        Ok(())
    }

    /// Deserialize from format v2 bytes. Assumes the version byte has
    /// already been read (or is still present — caller decides).
    pub fn deserialize_after_version(reader: &mut impl Read) -> io::Result<Self> {
        let mut buf2 = [0u8; 2];
        reader.read_exact(&mut buf2)?;
        let num_frames = u16::from_le_bytes(buf2) as usize;

        let mut frames = Vec::with_capacity(num_frames);
        for _ in 0..num_frames {
            // label
            reader.read_exact(&mut buf2)?;
            let label_len = u16::from_le_bytes(buf2) as usize;
            let mut label_buf = vec![0u8; label_len];
            reader.read_exact(&mut label_buf)?;
            let label = String::from_utf8_lossy(&label_buf).into_owned();

            // path
            reader.read_exact(&mut buf2)?;
            let path_len = u16::from_le_bytes(buf2) as usize;
            let mut path_buf = vec![0u8; path_len];
            reader.read_exact(&mut path_buf)?;
            let path = String::from_utf8_lossy(&path_buf).into_owned();

            // line
            let mut buf4 = [0u8; 4];
            reader.read_exact(&mut buf4)?;
            let line = u32::from_le_bytes(buf4);

            frames.push(InlineFrame { label, path, line });
        }

        Ok(Self { frames })
    }

    /// Deserialize from format v2 bytes including the version byte.
    pub fn deserialize(reader: &mut impl Read) -> io::Result<Self> {
        let mut ver = [0u8; 1];
        reader.read_exact(&mut ver)?;
        if ver[0] != INLINE_FORMAT_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("expected format version {}, got {}", INLINE_FORMAT_VERSION, ver[0]),
            ));
        }
        Self::deserialize_after_version(reader)
    }

    /// Estimated byte size of the serialized representation.
    pub fn serialized_size(&self) -> usize {
        let mut size = 1 + 2; // version + num_frames
        for frame in &self.frames {
            size += 2 + frame.label.len() + 2 + frame.path.len() + 4;
        }
        size
    }
}

impl Default for InlineStack {
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

    // --- InlineStack (format v2) tests ---

    #[test]
    fn test_inline_empty_round_trip() {
        let stack = InlineStack::new();
        let mut buf = Vec::new();
        stack.serialize(&mut buf).unwrap();
        // version(1) + num_frames(2) = 3 bytes
        assert_eq!(buf.len(), 3);
        assert_eq!(buf[0], INLINE_FORMAT_VERSION);

        let mut cursor = Cursor::new(&buf);
        let decoded = InlineStack::deserialize(&mut cursor).unwrap();
        assert_eq!(decoded, stack);
    }

    #[test]
    fn test_inline_round_trip() {
        let stack = InlineStack {
            frames: vec![
                InlineFrame {
                    label: "UsersController#index".to_string(),
                    path: "/app/controllers/users_controller.rb".to_string(),
                    line: 42,
                },
                InlineFrame {
                    label: "ActiveRecord::Base.find".to_string(),
                    path: "/gems/activerecord/lib/base.rb".to_string(),
                    line: 199,
                },
                InlineFrame {
                    label: "<main>".to_string(),
                    path: "<internal:kernel>".to_string(),
                    line: 0,
                },
            ],
        };

        let mut buf = Vec::new();
        stack.serialize(&mut buf).unwrap();
        assert_eq!(buf.len(), stack.serialized_size());

        let mut cursor = Cursor::new(&buf);
        let decoded = InlineStack::deserialize(&mut cursor).unwrap();
        assert_eq!(decoded, stack);
    }

    #[test]
    fn test_inline_serialized_size() {
        let stack = InlineStack {
            frames: vec![InlineFrame {
                label: "foo".to_string(),     // 3 bytes
                path: "bar.rb".to_string(),   // 6 bytes
                line: 1,
            }],
        };
        // version(1) + num_frames(2) + label_len(2) + "foo"(3) + path_len(2) + "bar.rb"(6) + line(4) = 20
        assert_eq!(stack.serialized_size(), 20);
    }

    #[test]
    fn test_inline_version_mismatch() {
        let bad_data = [1u8, 0, 0]; // version=1 (not inline)
        let mut cursor = Cursor::new(&bad_data);
        let result = InlineStack::deserialize(&mut cursor);
        assert!(result.is_err());
    }

    #[test]
    fn test_inline_utf8_lossy() {
        // Invalid UTF-8 in label should not panic
        let mut buf = Vec::new();
        buf.push(INLINE_FORMAT_VERSION);
        buf.extend_from_slice(&1u16.to_le_bytes()); // 1 frame
        // label: 3 bytes of invalid UTF-8
        buf.extend_from_slice(&3u16.to_le_bytes());
        buf.extend_from_slice(&[0xFF, 0xFE, 0xFD]);
        // path: empty
        buf.extend_from_slice(&0u16.to_le_bytes());
        // line
        buf.extend_from_slice(&1u32.to_le_bytes());

        let mut cursor = Cursor::new(&buf);
        let decoded = InlineStack::deserialize(&mut cursor).unwrap();
        assert_eq!(decoded.frames.len(), 1);
        assert_eq!(decoded.frames[0].line, 1);
        // Should contain replacement characters, not panic
        assert!(decoded.frames[0].label.contains('\u{FFFD}'));
    }
}
