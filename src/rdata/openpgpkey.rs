use crate::{Buffer, DnsMessage, DnsMessageError};
use crate::characters::Characters;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # OpenPGP Key Record (OPENPGPKEY)
/// This record is used as part of the DNS-Based Authentication of Named
/// Entities (DANE) protocol to associate a public key with a domain name.
/// The OPENPGPKEY record is intended to be used in conjunction with the
/// TLSA record [RFC6698].
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct OpenPgpKey<'a> {
    /// flags is a bitmap of flags (see [RFC 4880](https://tools.ietf.org/html/rfc4880))
    pub flags: u16,
    /// algorithm is the algorithm of the public key
    pub algorithm: u8,
    /// public_key is the public key
    pub public_key: Characters<'a>,
    /// fingerprint is the fingerprint of the referenced public key
    pub fingerprint: Characters<'a>,
}

impl<'a> RDataParse<'a> for OpenPgpKey<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let flags = u16::parse(rdata, i)?;
        let algorithm = u8::parse(rdata, i)?;
        let public_key = Characters::parse(rdata, i)?;
        let fingerprint = Characters::parse(rdata, i)?;

        Ok(Self {
            flags,
            algorithm,
            public_key,
            fingerprint
        })
    }
}

impl<'a> WriteBytes for OpenPgpKey<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.flags.write(message)?;
        bytes += self.algorithm.write(message)?;
        bytes += self.public_key.write(message)?;
        bytes += self.fingerprint.write(message)?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        11,
        [
            0x00, 0x0e, // flags
            0x0a, // algorithm
            0x03, b'w', b'w', b'w', // public key
            0x03, b'w', b'w', b'w', // fingerprint
        ],
        OpenPgpKey {
            flags: 0x000e,
            algorithm: 0x0a,
            public_key: unsafe { Characters::new_unchecked(b"www") },
            fingerprint: unsafe { Characters::new_unchecked(b"www") },
        },
    );
}
