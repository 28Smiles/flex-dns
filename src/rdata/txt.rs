use crate::{Buffer, DnsError, DnsMessage, DnsMessageError, MutBuffer};
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # The txt record
/// This record is used to hold arbitrary text data.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Txt<'a> {
    /// The text data
    data: &'a [u8],
}

/// Create a new [`Txt`] from byte slices. The data will be concatenated and
/// converted to DNS wire format. The maximum length of a single text value is
/// 255 bytes. This macro accepts an expression as input, which is evaluated at
/// compile time. If you want to create a [`Txt`] from byte slices of unknown
/// length, use the [`Txt::new`] function instead.
///
/// # Example
/// ```
/// use flex_dns::rdata::Txt;
/// use flex_dns::dns_txt;
///
/// const TXT: Txt = dns_txt!(
///     b"Hello",
///     b"World!"
/// );
/// ```
#[macro_export]
macro_rules! dns_txt {
    ($value:expr $(, $values:expr)* $(,)?) => {
        {
            const TXT: [u8; { $value.len() + 1 $(+ $values.len() + 1)* }] = {
                if $value.len() > u8::MAX as usize {
                    panic!("Txt value too long, maximum length is 255.");
                }

                let mut result = [0; $value.len() + 1 $(+ $values.len() + 1)*];
                result[0] = $value.len() as u8;

                let mut index = 1;
                let mut r_index = 0;
                loop {
                    if r_index == $value.len() {
                        break;
                    }

                    result[index] = $value[r_index];
                    r_index += 1;
                    index += 1;
                }

                $(
                    if $values.len() > u8::MAX as usize {
                        panic!("Txt value too long, maximum length is 255.");
                    }

                    result[index] = $values.len() as u8;
                    index += 1;

                    let mut r_index = 0;
                    loop {
                        if r_index == $values.len() {
                            break;
                        }

                        result[index] = $values[r_index];
                        r_index += 1;
                        index += 1;
                    }
                )*

                result
            };

            unsafe { flex_dns::rdata::Txt::new_unchecked(&TXT) }
        }
    };
}

impl<'a> Txt<'a> {
    /// Creates a new txt record and checks the data. The data needs to be
    /// in DNS wire format. The maximum length of a single text value is 255.
    /// If the data is invalid, this function will return an error.
    ///
    /// # Example
    /// ```
    /// use flex_dns::rdata::Txt;
    ///
    /// let txt = Txt::new(
    ///    b"\x05Hello\x06World!"
    /// ).unwrap();
    /// ```
    #[inline(always)]
    pub fn new(data: &'a [u8]) -> Result<Self, DnsMessageError> {
        for r in (TxtIterator {
            data,
            pos: 0,
        }) {
            r?;
        }

        Ok(Self {
            data,
        })
    }

    /// Creates a new txt record without checking the data.
    /// This function is unsafe because it doesn't check the data.
    /// If the data is invalid it can lead to an invalid DNS message.
    #[inline(always)]
    pub const unsafe fn new_unchecked(data: &'a [u8]) -> Self {
        Self {
            data,
        }
    }

    /// Returns an iterator over the txt record data.
    #[inline(always)]
    pub fn iter(&self) -> TxtIterator<'a> {
        TxtIterator {
            data: self.data,
            pos: 0,
        }
    }
}

impl<'a> RDataParse<'a> for Txt<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let data = &rdata.buffer[*i..*i + rdata.len];
        *i += rdata.len;

        Ok(Self {
            data,
        })
    }
}

impl<'a> WriteBytes for Txt<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: MutBuffer + Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        message.write_bytes(self.data)
    }
}

/// An iterator over the txt record data.
#[derive(Copy, Clone, Debug)]
pub struct TxtIterator<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Iterator for TxtIterator<'a> {
    type Item = Result<&'a [u8], DnsMessageError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.data.len() {
            return None;
        }

        let len = self.data[self.pos] as usize;

        if len == 0 && self.pos + 1 == self.data.len() {
            return None;
        } else if len == 0 {
            return Some(Err(DnsMessageError::DnsError(DnsError::InvalidTxtRecord)));
        }

        self.pos += 1;

        let end = self.pos + len;

        if end > self.data.len() {
            return Some(Err(DnsMessageError::DnsError(DnsError::InvalidTxtRecord)));
        }

        let result = &self.data[self.pos..end];
        self.pos = end;

        Some(Ok(result))
    }
}