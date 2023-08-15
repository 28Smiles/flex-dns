use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Option record
/// This record is used to store options for the DNS protocol.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Opt<'a> {
    /// The code for the option.
    pub code: u16,
    /// The data for the option.
    pub data: Characters<'a>,
}

impl<'a> RDataParse<'a> for Opt<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let code = u16::parse(rdata.buffer, i)?;
        let data = Characters::parse(rdata.buffer, i)?;

        Ok(Self {
            code,
            data,
        })
    }
}

impl<'a> WriteBytes for Opt<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.code.write(message)?;
        bytes += self.data.write(message)?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        6,
        [
            0x00, 0x0e, // code
            0x03, // length
            b'w', b'w', b'w', // data
        ],
        Opt {
            code: 14,
            data: unsafe { Characters::new_unchecked(b"www") },
        },
    );
}
