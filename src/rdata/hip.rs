use crate::{Buffer, DnsMessage, DnsMessageError, MutBuffer};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Host identity protocol (HIP) Record
/// This record is used to associate a HIP public key with a domain name.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Hip<'a> {
    /// The usage field is an 8-bit value that defines the semantics of the
    /// certificate association data field.
    pub usage: u8,
    /// The selector field is an 8-bit value that defines the type of data in the
    /// certificate association data field.
    pub selector: u8,
    /// The matching type field is an 8-bit value that defines the semantics of
    /// the certificate association data field.
    pub matching_type: u8,
    /// The certificate association data field is a variable-length string of octets
    /// that contains the certificate association data.
    pub certificate_association_data: Characters<'a>,
}

impl<'a> RDataParse<'a> for Hip<'a> {
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

impl<'a> WriteBytes for Hip<'a> {
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
            0x0e, // usage
            0x63, // selector
            0x43, // matching type
            0x03, // digest len
            b'w', b'w', b'w', // digest
        ],
        Hip {
            usage: 14,
            selector: 99,
            matching_type: 67,
            certificate_association_data: unsafe { Characters::new_unchecked(b"www") },
        },
    );
}
