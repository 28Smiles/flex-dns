use crate::{Buffer, DnsMessage, DnsMessageError, MutBuffer};
use crate::name::DnsName;
use crate::parse::Parse;
use crate::rdata::{RData, RDataParse};
use crate::write::WriteBytes;

/// # Incremental zone transfer record (IXFR)
/// This record is used to transfer a portion of a zone from a primary server to
/// a secondary server.
#[derive(Copy, Clone, Debug, PartialEq)]
pub struct IXfr<'a> {
    /// The domain name of the name server that was the
    /// original or primary source of data for this zone
    pub mname: DnsName<'a>,
    /// A domain name which specifies the mailbox of the
    /// person responsible for this zone
    pub rname: DnsName<'a>,
    /// The unsigned 32 bit version number of the original copy
    /// of the zone. Zone transfers preserve this value. This
    /// value wraps and should be compared using sequence space
    /// arithmetic
    pub serial: u32,
    /// A 32 bit time interval before the zone should be
    /// refreshed
    pub refresh: u32,
    /// A 32 bit time interval that should elapse before a
    /// failed refresh should be retried
    pub retry: u32,
    /// A 32 bit time value that specifies the upper limit on
    /// the time interval that can elapse before the zone is no
    /// longer authoritative
    pub expire: u32,
    /// The unsigned 32 bit minimum TTL field that should be
    /// exported with any RR from this zone
    pub minimum: u32,
}

impl<'a> RDataParse<'a> for IXfr<'a> {
    #[inline]
    fn parse(rdata: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError> {
        let mname = DnsName::parse(rdata.buffer, i)?;
        let rname = DnsName::parse(rdata.buffer, i)?;
        let serial = u32::parse(rdata.buffer, i)?;
        let refresh = u32::parse(rdata.buffer, i)?;
        let retry = u32::parse(rdata.buffer, i)?;
        let expire = u32::parse(rdata.buffer, i)?;
        let minimum = u32::parse(rdata.buffer, i)?;

        Ok(Self {
            mname,
            rname,
            serial,
            refresh,
            retry,
            expire,
            minimum,
        })
    }
}

impl<'a> WriteBytes for IXfr<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: MutBuffer + Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.mname.write(message)?;
        bytes += self.rname.write(message)?;
        bytes += self.serial.write(message)?;
        bytes += self.refresh.write(message)?;
        bytes += self.retry.write(message)?;
        bytes += self.expire.write(message)?;
        bytes += self.minimum.write(message)?;

        Ok(bytes)
    }
}

#[cfg(test)]
mod test {
    use crate::rdata::testutils::parse_write_test;

    use super::*;

    parse_write_test!(
        53,
        [
            3, b'w', b'w', b'w',
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm',
            0,
            3, b'w', b'w', b'w',
            6, b'g', b'o', b'o', b'g', b'l', b'e',
            3, b'c', b'o', b'm',
            0,
            0x00, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x0E, 0x10,
            0x00, 0x00, 0x03, 0x84,
            0x00, 0x09, 0x3A, 0x80,
            0x00, 0x00, 0x03, 0x84,
        ],
        IXfr {
            mname: unsafe { DnsName::new_unchecked(b"\x03www\x07example\x03com\x00") },
            rname: unsafe { DnsName::new_unchecked(b"\x03www\x06google\x03com\x00") },
            serial: 1,
            refresh: 3600,
            retry: 900,
            expire: 604800,
            minimum: 900,
        },
    );
}
