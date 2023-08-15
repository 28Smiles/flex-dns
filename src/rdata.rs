mod a;
mod ns;
mod cname;
mod soa;
mod ptr;
mod hinfo;
mod mx;
mod txt;
mod rp;
mod afsdb;
mod sig;
mod key;
mod aaaa;
mod loc;
mod srv;
mod naptr;
mod kx;
mod cert;
mod dname;
mod opt;
mod apl;
mod ds;
mod sshfp;
mod ipseckey;
mod rrsig;
mod nsec;
mod dnskey;
mod dhcid;
mod nsec3;
mod nsec3param;
mod tlsa;
mod smimea;
mod hip;
mod cds;
mod cdnskey;
mod openpgpkey;
mod csync;
mod zonemd;
mod svcb;
mod https;
mod eui48;
mod eui64;
mod tkey;
mod tsig;
mod ixfr;
mod axfr;
mod uri;
mod caa;
mod ta;
mod dlv;

pub use a::A;
pub use ns::Ns;
pub use cname::CName;
pub use soa::Soa;
pub use ptr::Ptr;
pub use hinfo::HInfo;
pub use mx::Mx;
pub use txt::Txt;
pub use rp::Rp;
pub use afsdb::AfsDb;
pub use sig::Sig;
pub use key::Key;
pub use aaaa::Aaaa;
pub use loc::Loc;
pub use srv::Srv;
pub use naptr::Naptr;
pub use kx::Kx;
pub use cert::Cert;
pub use dname::DName;
pub use opt::Opt;
pub use apl::Apl;
pub use ds::Ds;
pub use sshfp::SshFp;
pub use ipseckey::IpSecKey;
pub use rrsig::RRSig;
pub use nsec::Nsec;
pub use dnskey::DnsKey;
pub use dhcid::DhcId;
pub use nsec3::Nsec3;
pub use nsec3param::Nsec3Param;
pub use tlsa::Tlsa;
pub use smimea::SmimeA;
pub use hip::Hip;
pub use cds::Cds;
pub use cdnskey::CdnsKey;
pub use openpgpkey::OpenPgpKey;
pub use csync::CSync;
pub use zonemd::ZoneMd;
pub use svcb::Svcb;
pub use https::Https;
pub use eui48::EUI48;
pub use eui64::EUI64;
pub use tkey::TKey;
pub use tsig::TSig;
pub use ixfr::IXfr;
pub use axfr::AXfr;
pub use uri::Uri;
pub use caa::Caa;
pub use ta::Ta;
pub use dlv::Dlv;

use crate::{Buffer, DnsError, DnsMessage, DnsMessageError};
use crate::parse::{Parse, ParseData};
use crate::question::DnsQType;
use crate::write::WriteBytes;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RData<'a> {
    buffer: &'a [u8],
    pos: usize,
    len: usize,
    type_: DnsQType,
}

impl<'a> ParseData<'a> for RData<'a> {
    #[inline(always)]
    fn parse_data(&self) -> &'a [u8] {
        self.buffer
    }
}

impl<'a> ParseData<'a> for &'_ RData<'a> {
    #[inline(always)]
    fn parse_data(&self) -> &'a [u8] {
        self.buffer
    }
}

pub(crate) trait RDataParse<'a>: Sized {
    fn parse(bytes: &RData<'a>, i: &mut usize) -> Result<Self, DnsMessageError>;
}

impl<'a> RData<'a> {
    #[inline(always)]
    pub fn id(&self) -> u16 {
        self.type_.id()
    }

    pub fn parse(bytes: &'a [u8], i: &mut usize, type_: DnsQType) -> Result<Self, DnsMessageError> {
        let len = u16::parse(bytes, i)? as usize;
        let pos = *i;

        if pos + len > bytes.len() {
            return Err(DnsMessageError::DnsError(DnsError::RDataLongerThanMessage));
        }

        *i += len;

        Ok(RData { buffer: bytes, pos, len, type_ })
    }

    pub fn into_parsed(self) -> Result<DnsAType<'a>, DnsMessageError> {
        let mut pos = self.pos;

        Ok(match self.type_ {
            DnsQType::A => DnsAType::A(A::parse(&self, &mut pos)?),
            DnsQType::NS => DnsAType::NS(Ns::parse(&self, &mut pos)?),
            DnsQType::CNAME => DnsAType::CName(CName::parse(&self, &mut pos)?),
            DnsQType::SOA => DnsAType::Soa(Soa::parse(&self, &mut pos)?),
            DnsQType::PTR => DnsAType::Ptr(Ptr::parse(&self, &mut pos)?),
            DnsQType::HINFO => DnsAType::HInfo(HInfo::parse(&self, &mut pos)?),
            DnsQType::MX => DnsAType::MX(Mx::parse(&self, &mut pos)?),
            DnsQType::TXT => DnsAType::Txt(Txt::parse(&self, &mut pos)?),
            DnsQType::RP => DnsAType::RP(Rp::parse(&self, &mut pos)?),
            DnsQType::AFSDB => DnsAType::AFSDB(AfsDb::parse(&self, &mut pos)?),
            DnsQType::SIG => DnsAType::SIG(Sig::parse(&self, &mut pos)?),
            DnsQType::KEY => DnsAType::KEY(Key::parse(&self, &mut pos)?),
            DnsQType::AAAA => DnsAType::AAAA(Aaaa::parse(&self, &mut pos)?),
            DnsQType::LOC => DnsAType::Loc(Loc::parse(&self, &mut pos)?),
            DnsQType::SRV => DnsAType::Srv(Srv::parse(&self, &mut pos)?),
            DnsQType::NAPTR => DnsAType::Naptr(Naptr::parse(&self, &mut pos)?),
            DnsQType::KX => DnsAType::KX(Kx::parse(&self, &mut pos)?),
            DnsQType::CERT => DnsAType::Cert(Cert::parse(&self, &mut pos)?),
            DnsQType::DNAME => DnsAType::DName(DName::parse(&self, &mut pos)?),
            DnsQType::OPT => DnsAType::OPT(Opt::parse(&self, &mut pos)?),
            DnsQType::APL => DnsAType::APL(Apl::parse(&self, &mut pos)?),
            DnsQType::DS => DnsAType::DS(Ds::parse(&self, &mut pos)?),
            DnsQType::SSHFP => DnsAType::SSHFP(SshFp::parse(&self, &mut pos)?),
            DnsQType::IPSECKEY => DnsAType::IPSECKEY(IpSecKey::parse(&self, &mut pos)?),
            DnsQType::RRSIG => DnsAType::RRSIG(RRSig::parse(&self, &mut pos)?),
            DnsQType::NSEC => DnsAType::NSEC(Nsec::parse(&self, &mut pos)?),
            DnsQType::DNSKEY => DnsAType::DNSKEY(DnsKey::parse(&self, &mut pos)?),
            DnsQType::DHCID => DnsAType::DHCID(DhcId::parse(&self, &mut pos)?),
            DnsQType::NSEC3 => DnsAType::NSEC3(Nsec3::parse(&self, &mut pos)?),
            DnsQType::NSEC3PARAM => DnsAType::NSEC3PARAM(Nsec3Param::parse(&self, &mut pos)?),
            DnsQType::TLSA => DnsAType::TLSA(Tlsa::parse(&self, &mut pos)?),
            DnsQType::SMIMEA => DnsAType::SMIMEA(SmimeA::parse(&self, &mut pos)?),
            DnsQType::HIP => DnsAType::HIP(Hip::parse(&self, &mut pos)?),
            DnsQType::CDS => DnsAType::CDS(Cds::parse(&self, &mut pos)?),
            DnsQType::CDNSKEY => DnsAType::CDNSKEY(CdnsKey::parse(&self, &mut pos)?),
            DnsQType::OPENPGPKEY => DnsAType::OPENPGPKEY(OpenPgpKey::parse(&self, &mut pos)?),
            DnsQType::CSYNC => DnsAType::CSYNC(CSync::parse(&self, &mut pos)?),
            DnsQType::ZONEMD => DnsAType::ZONEMD(ZoneMd::parse(&self, &mut pos)?),
            DnsQType::SVCB => DnsAType::SVCB(Svcb::parse(&self, &mut pos)?),
            DnsQType::HTTPS => DnsAType::HTTPS(Https::parse(&self, &mut pos)?),
            DnsQType::EUI48 => DnsAType::EUI48(EUI48::parse(&self, &mut pos)?),
            DnsQType::EUI64 => DnsAType::EUI64(EUI64::parse(&self, &mut pos)?),
            DnsQType::TKEY => DnsAType::TKEY(TKey::parse(&self, &mut pos)?),
            DnsQType::TSIG => DnsAType::TSIG(TSig::parse(&self, &mut pos)?),
            DnsQType::IXFR => DnsAType::IXFR(IXfr::parse(&self, &mut pos)?),
            DnsQType::AXFR => DnsAType::AXFR(AXfr::parse(&self, &mut pos)?),
            DnsQType::ALL => return Err(DnsMessageError::DnsError(DnsError::InvalidAnswer)),
            DnsQType::URI => DnsAType::URI(Uri::parse(&self, &mut pos)?),
            DnsQType::CAA => DnsAType::CAA(Caa::parse(&self, &mut pos)?),
            DnsQType::TA => DnsAType::TA(Ta::parse(&self, &mut pos)?),
            DnsQType::DLV => DnsAType::DLV(Dlv::parse(&self, &mut pos)?),
            DnsQType::Reserved => return Err(DnsMessageError::DnsError(DnsError::InvalidAnswer)),
        })
    }
}

impl<'a> WriteBytes for RData<'a> {
    fn write<const PTR_STORAGE: usize, const DNS_SECTION: usize, B: Buffer>(
        &self,
        message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>
    ) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += (self.len as u16).write(message)?;
        bytes += message.write_bytes(&self.buffer[self.pos..self.pos + self.len])?;

        Ok(bytes)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DnsAType<'a> {
    A(A),
    NS(Ns<'a>),
    CName(CName<'a>),
    Soa(Soa<'a>),
    Ptr(Ptr<'a>),
    HInfo(HInfo<'a>),
    MX(Mx<'a>),
    Txt(Txt<'a>),
    RP(Rp<'a>),
    AFSDB(AfsDb<'a>),
    SIG(Sig<'a>),
    KEY(Key<'a>),
    AAAA(Aaaa),
    Loc(Loc),
    Srv(Srv<'a>),
    Naptr(Naptr<'a>),
    KX(Kx<'a>),
    Cert(Cert<'a>),
    DName(DName<'a>),
    OPT(Opt<'a>),
    APL(Apl<'a>),
    DS(Ds<'a>),
    SSHFP(SshFp<'a>),
    IPSECKEY(IpSecKey<'a>),
    RRSIG(RRSig<'a>),
    NSEC(Nsec<'a>),
    DNSKEY(DnsKey<'a>),
    DHCID(DhcId<'a>),
    NSEC3(Nsec3<'a>),
    NSEC3PARAM(Nsec3Param<'a>),
    TLSA(Tlsa<'a>),
    SMIMEA(SmimeA<'a>),
    HIP(Hip<'a>),
    CDS(Cds<'a>),
    CDNSKEY(CdnsKey<'a>),
    OPENPGPKEY(OpenPgpKey<'a>),
    CSYNC(CSync<'a>),
    ZONEMD(ZoneMd<'a>),
    SVCB(Svcb<'a>),
    HTTPS(Https<'a>),
    EUI48(EUI48),
    EUI64(EUI64),
    TKEY(TKey<'a>),
    TSIG(TSig<'a>),
    IXFR(IXfr<'a>),
    AXFR(AXfr<'a>),
    URI(Uri<'a>),
    CAA(Caa<'a>),
    TA(Ta<'a>),
    DLV(Dlv<'a>),
    /// Unknown
    Reserved,
}

impl<'a> Into<DnsQType> for DnsAType<'a> {
    #[inline(always)]
    fn into(self) -> DnsQType {
        match self {
            DnsAType::A(_) => DnsQType::A,
            DnsAType::NS(_) => DnsQType::NS,
            DnsAType::CName(_) => DnsQType::CNAME,
            DnsAType::Soa(_) => DnsQType::SOA,
            DnsAType::Ptr(_) => DnsQType::PTR,
            DnsAType::HInfo(_) => DnsQType::HINFO,
            DnsAType::MX(_) => DnsQType::MX,
            DnsAType::Txt(_) => DnsQType::TXT,
            DnsAType::RP(_) => DnsQType::RP,
            DnsAType::AFSDB(_) => DnsQType::AFSDB,
            DnsAType::SIG(_) => DnsQType::SIG,
            DnsAType::KEY(_) => DnsQType::KEY,
            DnsAType::AAAA(_) => DnsQType::AAAA,
            DnsAType::Loc(_) => DnsQType::LOC,
            DnsAType::Srv(_) => DnsQType::SRV,
            DnsAType::Naptr(_) => DnsQType::NAPTR,
            DnsAType::KX(_) => DnsQType::KX,
            DnsAType::Cert(_) => DnsQType::CERT,
            DnsAType::DName(_) => DnsQType::DNAME,
            DnsAType::OPT(_) => DnsQType::OPT,
            DnsAType::APL(_) => DnsQType::APL,
            DnsAType::DS(_) => DnsQType::DS,
            DnsAType::SSHFP(_) => DnsQType::SSHFP,
            DnsAType::IPSECKEY(_) => DnsQType::IPSECKEY,
            DnsAType::RRSIG(_) => DnsQType::RRSIG,
            DnsAType::NSEC(_) => DnsQType::NSEC,
            DnsAType::DNSKEY(_) => DnsQType::DNSKEY,
            DnsAType::DHCID(_) => DnsQType::DHCID,
            DnsAType::NSEC3(_) => DnsQType::NSEC3,
            DnsAType::NSEC3PARAM(_) => DnsQType::NSEC3PARAM,
            DnsAType::TLSA(_) => DnsQType::TLSA,
            DnsAType::SMIMEA(_) => DnsQType::SMIMEA,
            DnsAType::HIP(_) => DnsQType::HIP,
            DnsAType::CDS(_) => DnsQType::CDS,
            DnsAType::CDNSKEY(_) => DnsQType::CDNSKEY,
            DnsAType::OPENPGPKEY(_) => DnsQType::OPENPGPKEY,
            DnsAType::CSYNC(_) => DnsQType::CSYNC,
            DnsAType::ZONEMD(_) => DnsQType::ZONEMD,
            DnsAType::SVCB(_) => DnsQType::SVCB,
            DnsAType::HTTPS(_) => DnsQType::HTTPS,
            DnsAType::EUI48(_) => DnsQType::EUI48,
            DnsAType::EUI64(_) => DnsQType::EUI64,
            DnsAType::TKEY(_) => DnsQType::TKEY,
            DnsAType::TSIG(_) => DnsQType::TSIG,
            DnsAType::IXFR(_) => DnsQType::IXFR,
            DnsAType::AXFR(_) => DnsQType::AXFR,
            DnsAType::URI(_) => DnsQType::URI,
            DnsAType::CAA(_) => DnsQType::CAA,
            DnsAType::TA(_) => DnsQType::TA,
            DnsAType::DLV(_) => DnsQType::DLV,
            DnsAType::Reserved => DnsQType::Reserved,
        }
    }
}

impl<'a> WriteBytes for DnsAType<'a> {
    #[inline]
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        match self {
            DnsAType::A(r) => r.write(message),
            DnsAType::NS(r) => r.write(message),
            DnsAType::CName(r) => r.write(message),
            DnsAType::Soa(r) => r.write(message),
            DnsAType::Ptr(r) => r.write(message),
            DnsAType::HInfo(r) => r.write(message),
            DnsAType::MX(r) => r.write(message),
            DnsAType::Txt(r) => r.write(message),
            DnsAType::RP(r) => r.write(message),
            DnsAType::AFSDB(r) => r.write(message),
            DnsAType::SIG(r) => r.write(message),
            DnsAType::KEY(r) => r.write(message),
            DnsAType::AAAA(r) => r.write(message),
            DnsAType::Loc(r) => r.write(message),
            DnsAType::Srv(r) => r.write(message),
            DnsAType::Naptr(r) => r.write(message),
            DnsAType::KX(r) => r.write(message),
            DnsAType::Cert(r) => r.write(message),
            DnsAType::DName(r) => r.write(message),
            DnsAType::OPT(r) => r.write(message),
            DnsAType::APL(r) => r.write(message),
            DnsAType::DS(r) => r.write(message),
            DnsAType::SSHFP(r) => r.write(message),
            DnsAType::IPSECKEY(r) => r.write(message),
            DnsAType::RRSIG(r) => r.write(message),
            DnsAType::NSEC(r) => r.write(message),
            DnsAType::DNSKEY(r) => r.write(message),
            DnsAType::DHCID(r) => r.write(message),
            DnsAType::NSEC3(r) => r.write(message),
            DnsAType::NSEC3PARAM(r) => r.write(message),
            DnsAType::TLSA(r) => r.write(message),
            DnsAType::SMIMEA(r) => r.write(message),
            DnsAType::HIP(r) => r.write(message),
            DnsAType::CDS(r) => r.write(message),
            DnsAType::CDNSKEY(r) => r.write(message),
            DnsAType::OPENPGPKEY(r) => r.write(message),
            DnsAType::CSYNC(r) => r.write(message),
            DnsAType::ZONEMD(r) => r.write(message),
            DnsAType::SVCB(r) => r.write(message),
            DnsAType::HTTPS(r) => r.write(message),
            DnsAType::EUI48(r) => r.write(message),
            DnsAType::EUI64(r) => r.write(message),
            DnsAType::TKEY(r) => r.write(message),
            DnsAType::TSIG(r) => r.write(message),
            DnsAType::IXFR(r) => r.write(message),
            DnsAType::AXFR(r) => r.write(message),
            DnsAType::URI(r) => r.write(message),
            DnsAType::CAA(r) => r.write(message),
            DnsAType::TA(r) => r.write(message),
            DnsAType::DLV(r) => r.write(message),
            DnsAType::Reserved => Err(DnsMessageError::DnsError(DnsError::InvalidAnswer)),
        }
    }
}

impl<'a> DnsAType<'a> {
    #[inline(always)]
    pub fn id(&self) -> u16 {
        let qtype: DnsQType = (*self).into();
        qtype.id()
    }
}

#[cfg(test)]
mod testutils {
    use core::fmt::Debug;
    use super::*;

    #[cfg(feature = "vec")]
    extern crate alloc;

    pub(crate) fn parse_and_compare<
        'a,
        A: RDataParse<'a> + PartialEq + Debug,
    >(bytes: &'a [u8], expected: A) {
        let mut i = 0;
        let rdata = RData {
            buffer: bytes,
            pos: 0,
            len: bytes.len(),
            type_: DnsQType::ALL,
        };
        let parsed = A::parse(&rdata, &mut i).unwrap();
        assert_eq!(parsed, expected);
    }

    #[cfg(feature = "arrayvec")]
    pub(crate) fn write_and_compare_arrayvec<
        const N: usize,
        A: WriteBytes + PartialEq + Debug,
    >(a: A, expected: &[u8; N])
        where
            [(); crate::DNS_HEADER_SIZE + N]: Sized,
    {
        let mut message: DnsMessage<
            0, 0, arrayvec::ArrayVec<u8, { crate::DNS_HEADER_SIZE + N }>
        > = DnsMessage::new(arrayvec::ArrayVec::new()).unwrap();
        a.write(&mut message).unwrap();
        let buffer = message.abort().unwrap();
        assert_eq!(&buffer[crate::DNS_HEADER_SIZE..], expected.as_slice());
    }

    #[cfg(feature = "heapless")]
    pub(crate) fn write_and_compare_heapless<
        const N: usize,
        A: WriteBytes + PartialEq + Debug,
    >(a: A, expected: &[u8; N])
        where
            [(); crate::DNS_HEADER_SIZE + N]: Sized,
    {
        let mut message: DnsMessage<
            0, 0, heapless::Vec<u8, { crate::DNS_HEADER_SIZE + N }>
        > = DnsMessage::new(heapless::Vec::new()).unwrap();
        a.write(&mut message).unwrap();
        let buffer = message.abort().unwrap();
        assert_eq!(&buffer[crate::DNS_HEADER_SIZE..], expected.as_slice());
    }

    #[cfg(feature = "vec")]
    pub(crate) fn write_and_compare_alloc<
        const N: usize,
        A: WriteBytes + PartialEq + Debug,
    >(a: A, expected: &[u8; N])
        where
            [(); crate::DNS_HEADER_SIZE + N]: Sized,
    {
        let mut message: DnsMessage<
            0, 0, alloc::vec::Vec<u8>
        > = DnsMessage::new(alloc::vec::Vec::new()).unwrap();
        a.write(&mut message).unwrap();
        let buffer = message.abort().unwrap();
        assert_eq!(&buffer[crate::DNS_HEADER_SIZE..], expected.as_slice());
    }

    macro_rules! parse_write_test_macro {
        (
            $byte_count:literal,
            [ $( $bytes:literal ),* $(,)? ],
            $struct_name:ident { $( $content:ident: $content_builder:expr ),* $(,)? } $(,)?
        ) => {
            parse_write_test!(
                $byte_count,
                [ $( $bytes ),* ],
                $struct_name { $( $content: $content_builder ),* },
                parse,
                write,
            );
        };
        (
            $byte_count:literal,
            [ $( $bytes:literal ),* $(,)? ],
            $struct_name:ident { $( $content:ident: $content_builder:expr ),* $(,)? },
            $parse_name:ident,
            $write_name:ident $(,)?
        ) => {
            #[test]
            fn $parse_name() {
                const BYTES: [u8; $byte_count] = [ $( $bytes ),* ];
                const STRUCT: $struct_name = $struct_name {
                    $( $content: $content_builder ),*
                };

                crate::rdata::testutils::parse_and_compare(&BYTES, STRUCT);
            }

            #[cfg(any(feature = "heapless", feature = "arrayvec", feature = "vec"))]
            #[test]
            fn $write_name() {
                const BYTES: [u8; $byte_count] = [ $( $bytes ),* ];
                const STRUCT: $struct_name = $struct_name {
                    $( $content: $content_builder ),*
                };

                #[cfg(feature = "heapless")]
                {
                    crate::rdata::testutils::write_and_compare_heapless(STRUCT, &BYTES);
                }
                #[cfg(feature = "arrayvec")]
                {
                    crate::rdata::testutils::write_and_compare_arrayvec(STRUCT, &BYTES);
                }
                #[cfg(feature = "vec")]
                {
                    crate::rdata::testutils::write_and_compare_alloc(STRUCT, &BYTES);
                }
            }
        };
    }

    pub(crate) use parse_write_test_macro as parse_write_test;
}
