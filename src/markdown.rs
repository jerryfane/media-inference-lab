//! Literal field rendering shared by local evidence reports.
use std::io::{self, Write};

fn fence(output: &mut impl Write, mut length: usize) -> io::Result<()> {
    const TICKS: &[u8] = b"````````````````````````````````````````````````````````````````";
    while length > 0 {
        let count = length.min(TICKS.len());
        output.write_all(&TICKS[..count])?;
        length -= count;
    }
    Ok(())
}

// All strings, including paths and hashes, are data, never Markdown or URLs.
// A delimiter longer than every embedded run cannot be closed by field content.
pub(crate) fn literal(output: &mut impl Write, value: &str) -> io::Result<()> {
    let mut longest = 0;
    let mut run = 0;
    for byte in value.bytes() {
        run = if byte == b'`' { run + 1 } else { 0 };
        longest = longest.max(run);
    }
    let length = (longest + 1).max(3);
    fence(output, length)?;
    output.write_all(b"\n")?;
    let mut start = 0;
    for (index, character) in value.char_indices() {
        if character.is_control() && character != '\n' && character != '\t' {
            output.write_all(&value.as_bytes()[start..index])?;
            write!(output, "\\u{{{:x}}}", character as u32)?;
            start = index + character.len_utf8();
        }
    }
    output.write_all(&value.as_bytes()[start..])?;
    output.write_all(b"\n")?;
    fence(output, length)?;
    output.write_all(b"\n\n")
}
