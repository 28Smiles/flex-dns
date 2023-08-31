use crate::{Buffer, DnsMessage, DnsMessageError, MutBuffer};
use crate::name::DnsName;
use crate::parse::{Parse, ParseBytes};
use crate::write::WriteBytes;

/// A DNS message questions section.
pub struct DnsQuestions<
    const PTR_STORAGE: usize,
    B: Buffer,
> {
    message: DnsMessage<PTR_STORAGE, 0, B>,
    remaining: usize,
}

impl<
    const PTR_STORAGE: usize,
    B: Buffer,
> DnsQuestions<PTR_STORAGE, B> {
    #[inline(always)]
    pub(crate) fn new(message: DnsMessage<PTR_STORAGE, 0, B>) -> Self {
        let remaining = message.header().unwrap().question_count() as usize;
        Self {
            message,
            remaining,
        }
    }

    /// Return an iterator over the question section.
    #[inline(always)]
    pub fn iter(&mut self) -> Result<DnsQuestionIterator, DnsMessageError> {
        let (bytes, position) = self.message.bytes_and_position();

        Ok(DnsQuestionIterator {
            buffer: bytes,
            current_position: position,
            remaining: &mut self.remaining,
        })
    }

    /// Complete the message. This will check the remaining questions and
    /// return the message if successful.
    #[inline(always)]
    pub fn complete(mut self) -> Result<DnsMessage<PTR_STORAGE, 1, B>, DnsMessageError> {
        if self.remaining != 0 {
            for x in self.iter()? { x?; }
        }

        Ok(DnsMessage {
            buffer: self.message.buffer,
            position: self.message.position,
            ptr_storage: self.message.ptr_storage,
            ptr_len: self.message.ptr_len,
        })
    }
}

impl<
    const PTR_STORAGE: usize,
    B: MutBuffer + Buffer,
> DnsQuestions<PTR_STORAGE, B> {
    /// Append a question to the message. This will override the next
    /// question or further sections, if any.
    pub fn append(&mut self, question: DnsQuestion) -> Result<(), DnsMessageError> {
        // Truncate the buffer to the current position.
        self.message.truncate()?;
        question.write(&mut self.message)?;
        // Set question_count in the header to the current question count + 1.
        let question_count = self.message.header().unwrap().question_count();
        let question_count = question_count + 1 - self.remaining as u16;
        self.message.header_mut()?.set_question_count(question_count);
        self.message.header_mut()?.set_answer_count(0);
        self.message.header_mut()?.set_name_server_count(0);
        self.message.header_mut()?.set_additional_records_count(0);
        self.remaining = 0;

        Ok(())
    }
}

/// An iterator over the questions section of a DNS message.
pub struct DnsQuestionIterator<'a> {
    buffer: &'a [u8],
    current_position: &'a mut usize,
    remaining: &'a mut usize,
}

impl<'a> Iterator for DnsQuestionIterator<'a> {
    type Item = Result<DnsQuestion<'a>, DnsMessageError>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if *self.remaining == 0 {
            return None;
        }

        let question = DnsQuestion::parse(
            self.buffer, self.current_position
        );
        *self.remaining -= 1;

        Some(question)
    }
}

/// A DNS message question.
#[derive(Debug, PartialEq)]
pub struct DnsQuestion<'a> {
    /// The domain name being queried.
    pub name: DnsName<'a>,
    /// The type of the query.
    pub qtype: DnsQType,
    /// The class of the query.
    pub qclass: DnsQClass,
}

impl<'a> ParseBytes<'a> for DnsQuestion<'a> {
    fn parse_bytes(bytes: &'a [u8], i: &mut usize) -> Result<Self, DnsMessageError> {
        let name = DnsName::parse(bytes, i)?;
        let qtype = u16::parse(bytes, i)?.into();
        let qclass = u16::parse(bytes, i)?.into();

        Ok(Self {
            name,
            qtype,
            qclass,
        })
    }
}

impl<'a> WriteBytes for DnsQuestion<'a> {
    fn write<
        const PTR_STORAGE: usize,
        const DNS_SECTION: usize,
        B: MutBuffer + Buffer,
    >(&self, message: &mut DnsMessage<PTR_STORAGE, DNS_SECTION, B>) -> Result<usize, DnsMessageError> {
        let mut bytes = 0;

        bytes += self.name.write(message)?;
        bytes += self.qtype.id().write(message)?;
        bytes += self.qclass.id().write(message)?;

        Ok(bytes)
    }
}

/// The kind of a DNS query.
///
/// According to [RFC 1035 Section 3.2.2](https://tools.ietf.org/rfc/rfc1035#section-3.2.2)
/// and [RFC 1035 Section 3.2.3](https://tools.ietf.org/rfc/rfc1035#section-3.2.3).
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u16)]
pub enum DnsQType {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    HINFO = 13,
    MX = 15,
    TXT = 16,
    RP = 17,
    AFSDB = 18,
    SIG = 24,
    KEY = 25,
    AAAA = 28,
    LOC = 29,
    SRV = 33,
    NAPTR = 35,
    KX = 36,
    CERT = 37,
    DNAME = 39,
    OPT = 41,
    APL = 42,
    DS = 43,
    SSHFP = 44,
    IPSECKEY = 45,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    DHCID = 49,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    TLSA = 52,
    SMIMEA = 53,
    HIP = 55,
    CDS = 59,
    CDNSKEY = 60,
    OPENPGPKEY = 61,
    CSYNC = 62,
    ZONEMD = 63,
    SVCB = 64,
    HTTPS = 65,
    EUI48 = 108,
    EUI64 = 109,
    TKEY = 249,
    TSIG = 250,
    IXFR = 251,
    AXFR = 252,
    ALL = 255,
    URI = 256,
    CAA = 257,
    TA = 32768,
    DLV = 32769,
    Reserved,
}

impl DnsQType {
    /// Create a new QType from an ID.
    #[inline(always)]
    pub fn from_id(id: u16) -> Self {
        match id {
            1..=2 | 5..=6 | 12..=13 | 15..=18 | 24..=25 | 28..=29
            | 33 | 35..=37 | 39 | 41..=53 | 55 | 59..=65
            | 108..=109 | 249..=252 | 255 | 256 | 257
            | 32768..=32769 => unsafe {
                core::mem::transmute(id)
            },
            _ => DnsQType::Reserved,
        }
    }

    /// Get the ID of the QType.
    #[inline(always)]
    pub fn id(&self) -> u16 {
        match self {
            DnsQType::Reserved => panic!("Reserved QType"),
            _ => *self as u16,
        }
    }
}

impl From<DnsQType> for u16 {
    #[inline(always)]
    fn from(q: DnsQType) -> Self {
        DnsQType::id(&q)
    }
}

impl From<u16> for DnsQType {
    #[inline(always)]
    fn from(n: u16) -> Self {
        DnsQType::from_id(n)
    }
}

/// The class of a DNS query.
///
/// According to [RFC 1035 Section 3.2.4](https://tools.ietf.org/rfc/rfc1035#section-3.2.4).
#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u16)]
pub enum DnsQClass {
    /// Internet
    IN = 1,
    /// CSNET
    CS = 2,
    /// CHAOS
    CH = 3,
    /// Hesiod
    HS = 4,
    /// Any
    ANY = 255,
    Reserved,
}

impl DnsQClass {
    /// Create a new QClass from an ID.
    #[inline(always)]
    pub fn from_id(id: u16) -> Self {
        match id {
            1..=4 | 255 => unsafe { core::mem::transmute(id) },
            _ => DnsQClass::Reserved,
        }
    }

    /// Get the ID of the QClass.
    #[inline(always)]
    pub fn id(&self) -> u16 {
        match self {
            DnsQClass::Reserved => panic!("Reserved QClass"),
            _ => *self as u16,
        }
    }
}

impl From<DnsQClass> for u16 {
    #[inline(always)]
    fn from(q: DnsQClass) -> Self {
        DnsQClass::id(&q)
    }
}

impl From<u16> for DnsQClass {
    #[inline(always)]
    fn from(n: u16) -> Self {
        DnsQClass::from_id(n)
    }
}
