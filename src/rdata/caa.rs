use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Certificate authority authorization record (CAA)
/// This record is used to specify which certificate authorities (CAs) are
/// allowed to issue certificates for a domain.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Caa<'a> {
    /// The flags field is used to specify critical CAA flags.
    pub flags: u8,
    /// The tag field is used to specify the property represented by the record.
    pub tag: Characters<'a>,
    /// The value field is used to specify the value of the property.
    pub value: Characters<'a>,
}

impl<'a> RDataParse<'a> for Caa<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let flags = u8::parse(rdata, i)?;
        let tag = Characters::parse(rdata, i)?;
        let value = Characters::parse(rdata, i)?;

        Ok(Self {
            flags,
            tag,
            value,
        })
    }
}

impl<'a> WriteBytes for Caa<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.flags.write(message)?;
        bytes += self.tag.write(message)?;
        bytes += self.value.write(message)?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        23,
        [
            0x42, // flags
            0x05, // tag length
            b'i', b's', b's', b'u', b'e', // tag
            0x0f, // value length
            b'w', b'w', b'w', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', b't',
            b'e', b's', b't', // value
        ],
        Caa {
            flags: 0x42,
            tag: unsafe { Characters::new_unchecked(b"issue") },
            value: unsafe { Characters::new_unchecked(b"www.exampletest") },
        },
    );
}
