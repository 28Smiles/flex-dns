use core::fmt::Display;
use crate::{Buffer, DnsError, DnsMessage, DnsMessageError};
use crate::parse::ParseBytes;
use crate::write::WriteBytes;

/// A DNS message characters.
/// It is a sequence of characters, where the first byte is the length of the
/// sequence.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Characters<'a> {
    bytes: &'a [u8],
}

const MAX_CHARACTER_STRING_LENGTH: usize = 255;

/// Create a new [`Characters`] from a byte slice. The first byte of the slice
/// will be the length of the sequence. Only insert the characters, not the
/// length. The maximum length of the sequence is 255. This macro accepts an
/// expression as input, which is evaluated at compile time. If you want to
/// create a [`Characters`] from a byte slice of unknown length, use the
/// [`Characters::new`] function instead.
///
/// # Example
/// ```
/// use flex_dns::characters::Characters;
/// use flex_dns::dns_characters;
///
/// const CHARACTERS: Characters = dns_characters!(b"Hello World!");
/// ```
#[macro_export]
macro_rules! dns_characters {
    ($value:expr $(,)?) => {
        {
            const CHARACTERS: [u8; $value.len() + 1] = {
                if $value.len() > u8::MAX as usize {
                    panic!("Character string too long, maximum length is 255.");
                }

                let mut result = [0; $value.len() + 1];
                let mut index = 0;
                loop {
                    if index == $value.len() {
                        result[0] = index as u8;

                        break;
                    }

                    result[index + 1] = $value[index];
                    index += 1;
                }

                result
            };
            unsafe { ::flex_dns::characters::Characters::new_unchecked(&CHARACTERS) }
        }
    };
}

impl<'a> Characters<'a> {
    /// Create a new [`Characters`] from a byte slice. The first byte of the
    /// slice must be the length of the sequence. The maximum length of the
    /// sequence is checked and 255, the first byte, must be equal to the length
    /// of the slice minus 1, which is also checked. Use this function if you
    /// want to create a [`Characters`] from a byte slice of unknown length.
    /// If you know the length of the slice at compile time, use the
    /// [`dns_characters!`] macro instead.
    #[inline(always)]
    pub const fn new(bytes: &'a [u8]) -> Result<Self, DnsMessageError> {
        if bytes.len() > MAX_CHARACTER_STRING_LENGTH {
            return Err(DnsMessageError::DnsError(DnsError::CharacterStringTooLong));
        }

        if bytes[0] as usize + 1 != bytes.len() {
            return Err(DnsMessageError::DnsError(DnsError::CharacterStringInvalidLength));
        }

        Ok(Characters { bytes })
    }

    /// Create a new [`Characters`] from a byte slice. The first byte of the
    /// slice must be the length of the sequence. The maximum length of the
    /// sequence is not checked and 255, the first byte, must be equal to the
    /// length of the slice minus 1, which is also not checked, hence the
    /// `unsafe`. Using this function is unsafe cause it can lead to an invalid
    /// DNS message.
    #[inline(always)]
    pub const unsafe fn new_unchecked(bytes: &'a [u8]) -> Self {
        Characters { bytes }
    }
}

impl<'a> ParseBytes<'a> for Characters<'a> {
    #[inline]
    fn parse_bytes(bytes: &'a [u8], i: &mut usize) -> Result<Self, DnsMessageError> {
        let length = u8::parse_bytes(bytes, i)? as usize;

        if length > MAX_CHARACTER_STRING_LENGTH {
            return Err(DnsMessageError::DnsError(DnsError::CharacterStringTooLong));
        }

        if *i + length > bytes.len() {
            return Err(DnsMessageError::DnsError(DnsError::UnexpectedEndOfBuffer));
        }

        let bytes = &bytes[*i..*i + length];
        *i += length;

        Ok(Characters { bytes })
    }
}

impl<'a> WriteBytes for Characters<'a> {
    #[inline]
    fn write<const PTR_STORAGE: usize, const DNS_SECTION: usize, B: Buffer>(
        &self,
        message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>
    ) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += message.write_bytes(&[self.bytes.len() as u8])?;
        bytes += message.write_bytes(self.bytes)?;

        Ok(bytes)
    }
}

impl<'a> AsRef<[u8]> for Characters<'a> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.bytes[1..] // Skip the length byte.
    }
}

impl<'a> Display for Characters<'a> {
    #[inline]
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for &byte in self.bytes[1..].iter() {
            write!(f, "\\x{:02x}", byte)?;
        }

        Ok(())
    }
}