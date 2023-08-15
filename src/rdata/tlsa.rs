use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Transport Layer Security Authentication (TLSA) Record
/// This record is used to associate a TLS server certificate or public key with
/// the domain name where the record is found, thus forming a "TLSA certificate association".
/// This record type is described in [RFC 6698](https://tools.ietf.org/html/rfc6698).
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Tlsa<'a> {
    /// The usage of this TLSA record
    pub usage: u8,
    /// The selector of this TLSA record
    pub selector: u8,
    /// The matching type of this TLSA record
    pub matching_type: u8,
    /// The certificate association data
    pub certificate_association_data: Characters<'a>,
}

impl<'a> RDataParse<'a> for Tlsa<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let usage = u8::parse(rdata, i)?;
        let selector = u8::parse(rdata, i)?;
        let matching_type = u8::parse(rdata, i)?;
        let certificate_association_data = Characters::parse(rdata, i)?;

        Ok(Self {
            usage,
            selector,
            matching_type,
            certificate_association_data,
        })
    }
}

impl<'a> WriteBytes for Tlsa<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.usage.write(message)?;
        bytes += self.selector.write(message)?;
        bytes += self.matching_type.write(message)?;
        bytes += self.certificate_association_data.write(message)?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        7,
        [
            0x0a, // usage
            0x0b, // selector
            0x0c, // matching type
            0x03, // length of certificate association data
            0x77, 0x77, 0x77, // certificate association data
        ],
        Tlsa {
            usage: 10,
            selector: 11,
            matching_type: 12,
            certificate_association_data: unsafe { Characters::new_unchecked(b"www") },
        },
    );
}
