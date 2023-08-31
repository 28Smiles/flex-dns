use crate::{Buffer, DnsMessage, DnsMessageError, MutBuffer};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Certificate record
/// This record lists the certificates used by the owner of the domain
/// name to sign other records in the zone.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct Cert<'a> {
    /// The type of certificate.
    pub cert_type: u16,
    /// The key tag of the certificate.
    pub key_tag: u16,
    /// The algorithm used to sign the certificate.
    pub algorithm: u8,
    /// The certificate data.
    pub certificate: Characters<'a>,
}

impl<'a> RDataParse<'a> for Cert<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let cert_type = u16::parse(rdata.buffer, i)?;
        let key_tag = u16::parse(rdata.buffer, i)?;
        let algorithm = u8::parse(rdata.buffer, i)?;
        let certificate = Characters::parse(rdata.buffer, i)?;

        Ok(Self {
            cert_type,
            key_tag,
            algorithm,
            certificate,
        })
    }
}

impl<'a> WriteBytes for Cert<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: MutBuffer + Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.cert_type.write(message)?;
        bytes += self.key_tag.write(message)?;
        bytes += self.algorithm.write(message)?;
        bytes += self.certificate.write(message)?;

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
            0x00, 0x01, // cert type
            0x02, 0x03, // key tag
            0x04, // algorithm
            0x00, // certificate length
        ],
        Cert {
            cert_type: 1,
            key_tag: 0x0203,
            algorithm: 4,
            certificate: unsafe { Characters::new_unchecked(&[]) },
        },
    );
}