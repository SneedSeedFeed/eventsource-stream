use std::num::NonZero;

use nom::IResult;

/// ; ABNF definition from HTML spec
///
/// stream        = [ bom ] *event
/// event         = *( comment / field ) end-of-line
/// comment       = colon *any-char end-of-line
/// field         = 1*name-char [ colon [ space ] *any-char ] end-of-line
/// end-of-line   = ( cr lf / cr / lf )
///
/// ; characters
/// lf            = %x000A ; U+000A LINE FEED (LF)
/// cr            = %x000D ; U+000D CARRIAGE RETURN (CR)
/// space         = %x0020 ; U+0020 SPACE
/// colon         = %x003A ; U+003A COLON (:)
/// bom           = %xFEFF ; U+FEFF BYTE ORDER MARK
/// name-char     = %x0000-0009 / %x000B-000C / %x000E-0039 / %x003B-10FFFF
///                 ; a scalar value other than U+000A LINE FEED (LF), U+000D CARRIAGE RETURN (CR), or U+003A COLON (:)
/// any-char      = %x0000-0009 / %x000B-000C / %x000E-10FFFF
///                 ; a scalar value other than U+000A LINE FEED (LF) or U+000D CARRIAGE RETURN (CR)

#[derive(Debug)]
pub enum RawEventLine<'a> {
    Comment(&'a str),
    Field(&'a str, Option<&'a str>),
    Empty,
}

#[inline]
pub fn is_lf(c: char) -> bool {
    c == '\u{000A}'
}

#[inline]
pub fn is_bom(c: char) -> bool {
    c == '\u{feff}'
}

fn find_eol(bytes: &[u8]) -> Option<(usize, usize)> {
    const CR: u8 = b'\r';
    const LF: u8 = b'\n';
    let first_match = memchr::memchr2(CR, LF, bytes)?;

    match bytes[first_match] {
        LF => Some((first_match, first_match + 1)),
        CR => {
            if first_match + 1 >= bytes.len() {
                return None; // need more data to see if it's CRLF or just CR
            }

            // Cr lf
            if bytes[first_match + 1] == LF {
                Some((first_match, first_match + 2))
            } else {
                // just cr
                Some((first_match, first_match + 1))
            }
        }
        _ => unreachable!(),
    }
}

pub fn line(input: &str) -> IResult<&str, RawEventLine<'_>> {
    let (line_end, rem_start) = match find_eol(input.as_bytes()) {
        Some(some) => some,
        None => {
            // Only time we can fail to find EOL is when it's CR at the end of the input
            return Err(nom::Err::Incomplete(nom::Needed::Size(
                NonZero::new(1).unwrap(),
            )));
        }
    };

    let line = &input[..line_end];

    let rem = &input[rem_start..];

    if line.is_empty() {
        return Ok((rem, RawEventLine::Empty));
    }

    match memchr::memchr(b':', line.as_bytes()) {
        Some(0) => Ok((rem, RawEventLine::Comment(line))),
        Some(colon_pos) => {
            let value_start = if line.as_bytes().get(colon_pos + 1) == Some(&b' ') {
                colon_pos + 2
            } else {
                colon_pos + 1
            };

            Ok((
                rem,
                RawEventLine::Field(&line[..colon_pos], Some(&line[value_start..])),
            ))
        }
        None => Ok((rem, RawEventLine::Field(line, None))),
    }
}
