use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # IPsec key record
/// This record is used to store a public key that is associated with a domain name.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct IpSecKey<'a> {
    /// The precedence of the key.
    pub precedence: u16,
    /// The gateway type.
    pub gateway_type: u8,
    /// The algorithm used for the key.
    pub algorithm: u8,
    /// The gateway data.
    pub gateway: Characters<'a>,
    /// The public key data.
    pub public_key: Characters<'a>,
}

impl<'a> RDataParse<'a> for IpSecKey<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let precedence = u16::parse(rdata.buffer, i)?;
        let gateway_type = u8::parse(rdata.buffer, i)?;
        let algorithm = u8::parse(rdata.buffer, i)?;
        let gateway = Characters::parse(rdata.buffer, i)?;
        let public_key = Characters::parse(rdata.buffer, i)?;

        Ok(Self {
            precedence,
            gateway_type,
            algorithm,
            gateway,
            public_key,
        })
    }
}

impl<'a> WriteBytes for IpSecKey<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.precedence.write(message)?;
        bytes += self.gateway_type.write(message)?;
        bytes += self.algorithm.write(message)?;
        bytes += self.gateway.write(message)?;
        bytes += self.public_key.write(message)?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        12,
        [
            0x01, 0x02, // precedence
            0x03, // gateway type
            0x04, // algorithm
            0x03, b'w', b'w', b'w', // gateway
            0x03, b'w', b'w', b'w', // public key
        ],
        IpSecKey {
            precedence: 0x0102,
            gateway_type: 0x03,
            algorithm: 0x04,
            gateway: unsafe { Characters::new_unchecked(b"www") },
            public_key: unsafe { Characters::new_unchecked(b"www") },
        },
    );
}
