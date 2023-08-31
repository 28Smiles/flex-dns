use crate::{Buffer, DnsMessage, DnsMessageError, MutBuffer};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # S/MIME cert association record (SMIMEA)
/// This record is used to store S/MIME certificate association
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct SmimeA<'a> {
    /// The usage of the certificate
    pub usage: u8,
    /// The selector of the certificate
    pub selector: u8,
    /// The matching type of the certificate
    pub matching_type: u8,
    /// The certificate data
    pub certificate: Characters<'a>,
}

impl<'a> RDataParse<'a> for SmimeA<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let usage = u8::parse(rdata, i)?;
        let selector = u8::parse(rdata, i)?;
        let matching_type = u8::parse(rdata, i)?;
        let certificate = Characters::parse(rdata, i)?;

        Ok(Self {
            usage,
            selector,
            matching_type,
            certificate,
        })
    }
}

impl<'a> WriteBytes for SmimeA<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: MutBuffer + Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.usage.write(message)?;
        bytes += self.selector.write(message)?;
        bytes += self.matching_type.write(message)?;
        bytes += self.certificate.write(message)?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        19,
        [
            0x0e, // usage
            0x0f, // selector
            0x10, // matching type
            0x0f, // length of certificate
            0x01, 0x02, 0x03, 0x04, 0x05,
            0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, // certificate
        ],
        SmimeA {
            usage: 0x0e,
            selector: 0x0f,
            matching_type: 0x10,
            certificate: unsafe { Characters::new_unchecked(&[
                0x01, 0x02, 0x03, 0x04, 0x05,
                0x06, 0x07, 0x08, 0x09, 0x0a,
                0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
            ]) },
        },
    );
}
