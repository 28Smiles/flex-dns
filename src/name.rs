use core::fmt::{Debug, Display, Formatter};
use crate::{Buffer, DnsError, DnsMessage, DnsMessageError, MutBuffer};
use crate::parse::ParseBytes;
use crate::write::WriteBytes;

const MAX_DOMAIN_NAME_DEPTH: usize = 128;
const MAX_DOMAIN_NAME_LABEL_LENGTH: usize = 63;

/// A DNS name.
#[derive(Clone, Copy)]
pub struct DnsName<'a> {
    bytes: &'a [u8],
    offset: usize,
}

/// Create a new [`DnsName`] from a byte slice. The domain name must
/// be dot separated. The constructor will check convert the domain name
/// to DNS wire format and check if it is valid.
/// This macro accepts an expression as input, which is evaluated at compile
/// time. If you want to create a [`DnsName`] from a byte slice of unknown
/// length, use the [`DnsName::new`] function instead.
///
/// # Example
/// ```
/// use flex_dns::dns_name;
/// use flex_dns::name::DnsName;
///
/// const NAME: DnsName = dns_name!(b"example.com");
/// ```
#[macro_export]
macro_rules! dns_name {
    ($value:expr $(,)?) => {
        {
            const NAME: [u8; $value.len() + 2] = {
                let mut result = [0; $value.len() + 2];
                let mut label_start = 0;
                let mut index = 0;
                loop {
                    if index == $value.len() {
                        if index - label_start > u8::MAX as usize {
                            panic!("Label too long, maximum length is 255.");
                        }

                        result[label_start] = (index - label_start) as u8;

                        break;
                    }

                    let byte = $value[index];
                    if byte == b'.' {
                        if index - label_start > u8::MAX as usize {
                            panic!("Label too long, maximum length is 255.");
                        }

                        result[label_start] = (index - label_start) as u8;
                        label_start = index + 1;
                    } else {
                        result[index + 1] = byte;
                    }

                    index += 1;
                }

                result
            };
            unsafe { flex_dns::name::DnsName::new_unchecked(&NAME) }
        }
    };
}

impl<'a> DnsName<'a> {
    /// Create a new [`DnsName`] from a byte slice. The bytes must be in DNS
    /// wire format. The constructor will check if the name is valid.
    #[inline(always)]
    pub fn new(bytes: &'a [u8]) -> Result<Self, DnsMessageError> {
        for part in (NameIterator {
            bytes,
            offset: 0,
            depth: 0,
        }) {
            part?;
        }

        Ok(Self { bytes, offset: 0 })
    }

    /// Create a new [`DnsName`] from a byte slice. The bytes must be in DNS
    /// wire format. The constructor will not check if the name is valid, hence
    /// the `unsafe`. Using this function is unsafe cause it can lead to an
    /// invalid DNS message.
    #[inline(always)]
    pub const unsafe fn new_unchecked(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    /// Return an iterator over the parts of the name.
    #[inline(always)]
    pub fn iter(&self) -> NameIterator<'a> {
        NameIterator {
            bytes: self.bytes,
            offset: self.offset,
            depth: 0,
        }
    }

    pub(crate) fn split_first(&self) -> Result<(&'a [u8], Option<Self>), DnsMessageError> {
        let mut iter = self.iter();
        let first = iter.next().unwrap()?;
        if let Some(next) = iter.next() {
            let next = next?;

            // Calculate offset from address of the second pointer.
            let offset = next.as_ptr() as usize - self.bytes.as_ptr() as usize - 1;

            Ok((first, Some(Self {
                bytes: self.bytes,
                offset,
            })))
        } else {
            Ok((first, None))
        }
    }
}

impl<'a> ParseBytes<'a> for DnsName<'a> {
    #[inline]
    fn parse_bytes(bytes: &'a [u8], i: &mut usize) -> Result<Self, DnsMessageError> {
        const MAX_LENGTH: usize = 255;
        let mut j = *i;

        loop {
            if j - *i >= MAX_LENGTH {
                return Err(DnsMessageError::DnsError(DnsError::NameTooLong));
            }

            match LabelType::from_bytes(bytes, &mut j)? {
                LabelType::Pointer(_) => {
                    break;
                }
                LabelType::Part(len) => {
                    j += len as usize;

                    if len == 0 {
                        break;
                    }

                    if len > MAX_DOMAIN_NAME_LABEL_LENGTH as u8 {
                        return Err(DnsMessageError::DnsError(DnsError::LabelTooLong));
                    }
                }
            }
        }

        let offset = *i;
        *i = j;

        Ok(Self { bytes, offset })
    }
}

impl<'a> WriteBytes for DnsName<'a> {
    #[inline(always)]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: MutBuffer + Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        message.write_name(*self)
    }
}

/// An iterator over the parts of a [`DnsName`]. By default, this iterator is
/// not cycle safe, meaning that it will not detect cycles in the name. If there
/// is a cycle, the iterator will loop till the maximum depth is reached (128).
pub struct NameIterator<'a> {
    bytes: &'a [u8],
    offset: usize,
    depth: usize,
}

impl<'a> NameIterator<'a> {
    /// Return a cycle safe version of this iterator. If there is a cycle in the
    /// name, the iterator will return an error. The cycle safe detection uses
    /// O(n^2) comparisons, where n is the number of parts in the name.
    pub fn cycle_safe(self) -> CycleSafeNameIterator<'a> {
        CycleSafeNameIterator {
            iter: self,
            depth: [0; MAX_DOMAIN_NAME_DEPTH],
        }
    }
}

impl<'a> Iterator for NameIterator<'a> {
    type Item = Result<&'a [u8], DnsMessageError>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut i = self.offset;
        loop {
            self.depth += 1;
            if self.depth > MAX_DOMAIN_NAME_DEPTH {
                return Some(Err(DnsMessageError::DnsError(DnsError::NameTooLong)));
            }

            match LabelType::from_bytes(self.bytes, &mut i).unwrap() {
                LabelType::Pointer(ptr) => {
                    if ptr < self.offset as u16 {
                        // The pointer points to an earlier part of the message.
                        i = ptr as usize;

                        continue;
                    } else {
                        // The pointer points into the future.
                        return Some(Err(DnsMessageError::DnsError(DnsError::PointerIntoTheFuture)));
                    }
                }
                LabelType::Part(len) => {
                    if len == 0 {
                        // We've reached the end of the name.
                        return None;
                    }

                    if len > MAX_DOMAIN_NAME_LABEL_LENGTH as u8 {
                        return Some(Err(DnsMessageError::DnsError(DnsError::LabelTooLong)));
                    }

                    if self.bytes.len() < i + len as usize {
                        // The name is longer than the buffer.
                        return Some(Err(DnsMessageError::DnsError(DnsError::MessageTooShort)));
                    }

                    let part = &self.bytes[i..i + len as usize];
                    self.offset = i + len as usize;

                    return Some(Ok(part))
                }
            }
        }
    }
}

/// A cycle safe version of [`NameIterator`]. If there is a cycle in the name,
/// the iterator will return an error.
pub struct CycleSafeNameIterator<'a> {
    iter: NameIterator<'a>,
    depth: [usize; MAX_DOMAIN_NAME_DEPTH],
}

impl<'a> Iterator for CycleSafeNameIterator<'a> {
    type Item = Result<&'a [u8], DnsMessageError>;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.iter.next();

        if let Some(Ok(part)) = next {
            let part = part.as_ptr() as usize;

            for &known_part in &self.depth[..self.iter.depth - 1] {
                if known_part == part {
                    return Some(Err(DnsMessageError::DnsError(DnsError::PointerCycle)));
                }
            }

            self.depth[self.iter.depth - 1] = part;
        }

        next
    }
}

impl PartialEq<DnsName<'_>> for DnsName<'_> {
    fn eq(&self, other: &DnsName<'_>) -> bool {
        for (a, b) in self.iter().zip(other.iter()) {
            match (a, b) {
                (Ok(a), Ok(b)) => {
                    if a != b {
                        return false;
                    }
                }
                _ => {
                    return false;
                }
            }
        }

        true
    }
}

impl Display for DnsName<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let mut first = true;
        for part in self.iter() {
            if first {
                first = false;
            } else {
                f.write_str(".")?;
            }

            let part = part.map_err(|_| core::fmt::Error)?;
            f.write_str(core::str::from_utf8(part).unwrap())?;
        }

        Ok(())
    }
}

impl Debug for DnsName<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("DnsName(")?;
        Display::fmt(self, f)?;
        f.write_str(")")?;

        Ok(())
    }
}

#[derive(PartialEq)]
enum LabelType {
    Pointer(u16),
    Part(u8),
}

impl LabelType {
    fn from_bytes(bytes: &[u8], i: &mut usize) -> Result<Self, DnsMessageError> {
        const PTR_MASK: u8 = 0b11000000;
        const LEN_MASK: u8 = !PTR_MASK;

        let c = u8::parse_bytes(bytes, i)?;

        if c & PTR_MASK == PTR_MASK {
            let c = c & LEN_MASK;
            let pointer = u16::from_be_bytes([c, u8::parse_bytes(bytes, i)?]);
            if pointer >= *i as u16 {
                // Cannot point to the future.
                return Err(DnsMessageError::DnsError(DnsError::PointerIntoTheFuture));
            }

            Ok(Self::Pointer(pointer))
        } else {
            let len = c & LEN_MASK;

            Ok(Self::Part(len))
        }
    }
}
