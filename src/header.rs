/// A DNS header.
#[derive(Copy, Clone)]
#[repr(C)]
pub struct DnsHeader {
    id: [u8; 2],
    flags: [u8; 2],
    question_count: [u8; 2],
    answer_count: [u8; 2],
    name_server_count: [u8; 2],
    additional_records_count: [u8; 2],
}

impl DnsHeader {
    #[inline(always)]
    pub(crate) fn from_bytes_mut(bytes: &mut [u8]) -> &mut Self {
        unsafe { &mut *(bytes.as_mut_ptr() as *mut Self) }
    }

    #[inline(always)]
    pub(crate) fn from_bytes(bytes: &[u8]) -> &Self {
        unsafe { & *(bytes.as_ptr() as *const Self) }
    }

    /// The id of the DNS header.
    #[inline(always)]
    pub fn id(&self) -> u16 {
        u16::from_be_bytes(self.id)
    }

    /// The kind of the DNS header.
    #[inline(always)]
    pub fn kind(&self) -> DnsHeaderKind {
        if (self.flags[0] & 0b10000000) == 0 {
            DnsHeaderKind::Query
        } else {
            DnsHeaderKind::Response
        }
    }

    /// The opcode of the DNS header.
    #[inline(always)]
    pub fn opcode(&self) -> DnsHeaderOpcode {
        (self.flags[0] & 0b01111000).into()
    }

    /// Whether the DNS header is an authoritative answer.
    #[inline(always)]
    pub fn authoritative_answer(&self) -> bool {
        (self.flags[0] & 0b00000100) != 0
    }

    /// Whether the DNS header is truncated.
    #[inline(always)]
    pub fn truncated(&self) -> bool {
        (self.flags[0] & 0b00000010) != 0
    }

    /// Whether the DNS header recursion is desired.
    #[inline(always)]
    pub fn recursion_desired(&self) -> bool {
        (self.flags[0] & 0b00000001) != 0
    }

    /// Whether the DNS header recursion is available.
    #[inline(always)]
    pub fn recursion_available(&self) -> bool {
        (self.flags[1] & 0b10000000) != 0
    }

    /// The response code of the DNS header.
    #[inline(always)]
    pub fn response_code(&self) -> DnsHeaderResponseCode {
        (self.flags[1] & 0b00001111).into()
    }

    /// The number of questions in the DNS message.
    #[inline(always)]
    pub fn question_count(&self) -> u16 {
        u16::from_be_bytes(self.question_count)
    }

    /// The number of answers in the DNS message.
    #[inline(always)]
    pub fn answer_count(&self) -> u16 {
        u16::from_be_bytes(self.answer_count)
    }

    /// The number of name servers in the DNS message.
    #[inline(always)]
    pub fn name_server_count(&self) -> u16 {
        u16::from_be_bytes(self.name_server_count)
    }

    /// The number of additional records in the DNS message.
    #[inline(always)]
    pub fn additional_records_count(&self) -> u16 {
        u16::from_be_bytes(self.additional_records_count)
    }

    /// Set the id of the DNS header.
    #[inline(always)]
    pub fn set_id(&mut self, id: u16) {
        self.id = id.to_be_bytes();
    }

    /// Set the kind of the DNS header.
    #[inline(always)]
    pub fn set_kind(&mut self, kind: DnsHeaderKind) {
        match kind {
            DnsHeaderKind::Query => self.flags[0] &= 0b01111111,
            DnsHeaderKind::Response => self.flags[0] |= 0b10000000,
        }
    }

    /// Set the opcode of the DNS header.
    #[inline(always)]
    pub fn set_opcode(&mut self, opcode: DnsHeaderOpcode) {
        self.flags[0] &= 0b10000111;
        self.flags[0] |= (u8::from(opcode) & 0b0000_1111) << 3;
    }

    /// Set whether the DNS header is an authoritative answer.
    #[inline(always)]
    pub fn set_authoritative_answer(&mut self, authoritative_answer: bool) {
        if authoritative_answer {
            self.flags[0] |= 0b00000100;
        } else {
            self.flags[0] &= 0b11111011;
        }
    }

    /// Set whether the DNS header is truncated.
    #[inline(always)]
    pub fn set_truncated(&mut self, truncated: bool) {
        if truncated {
            self.flags[0] |= 0b00000010;
        } else {
            self.flags[0] &= 0b11111101;
        }
    }

    /// Set whether recursion is desired.
    #[inline(always)]
    pub fn set_recursion_desired(&mut self, recursion_desired: bool) {
        if recursion_desired {
            self.flags[0] |= 0b00000001;
        } else {
            self.flags[0] &= 0b11111110;
        }
    }

    /// Set whether recursion is available.
    #[inline(always)]
    pub fn set_recursion_available(&mut self, recursion_available: bool) {
        if recursion_available {
            self.flags[1] |= 0b10000000;
        } else {
            self.flags[1] &= 0b01111111;
        }
    }

    /// Set the response code of the DNS header.
    #[inline(always)]
    pub fn set_response_code(&mut self, response_code: DnsHeaderResponseCode) {
        self.flags[1] &= 0b11110000;
        self.flags[1] |= u8::from(response_code) & 0b00001111;
    }

    #[inline(always)]
    pub(crate) fn set_question_count(&mut self, question_count: u16) {
        self.question_count = question_count.to_be_bytes();
    }

    #[inline(always)]
    pub(crate) fn set_answer_count(&mut self, answer_count: u16) {
        self.answer_count = answer_count.to_be_bytes();
    }

    #[inline(always)]
    pub(crate) fn set_name_server_count(&mut self, name_server_count: u16) {
        self.name_server_count = name_server_count.to_be_bytes();
    }

    #[inline(always)]
    pub(crate) fn set_additional_records_count(&mut self, additional_records_count: u16) {
        self.additional_records_count = additional_records_count.to_be_bytes();
    }
}

impl core::fmt::Debug for DnsHeader {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Header")
            .field("id", &self.id())
            .field("kind", &self.kind())
            .field("opcode", &self.opcode())
            .field("authoritative_answer", &self.authoritative_answer())
            .field("truncated", &self.truncated())
            .field("recursion_desired", &self.recursion_desired())
            .field("recursion_available", &self.recursion_available())
            .field("response_code", &self.response_code())
            .field("question_count", &self.question_count())
            .field("answer_count", &self.answer_count())
            .field("name_server_count", &self.name_server_count())
            .field("additional_records_count", &self.additional_records_count())
            .finish()
    }
}

/// The kind of a DNS header.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum DnsHeaderKind {
    /// A DNS query.
    Query,
    /// A DNS response.
    Response,
}

/// A DNS opcode.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum DnsHeaderOpcode {
    Query,
    InverseQuery,
    Status,
    Notify,
    Update,
    Reserved(u8),
}

impl From<u8> for DnsHeaderOpcode {
    fn from(value: u8) -> Self {
        match value {
            0 => DnsHeaderOpcode::Query,
            1 => DnsHeaderOpcode::InverseQuery,
            2 => DnsHeaderOpcode::Status,
            4 => DnsHeaderOpcode::Notify,
            5 => DnsHeaderOpcode::Update,
            _ => DnsHeaderOpcode::Reserved(value),
        }
    }
}

impl From<DnsHeaderOpcode> for u8 {
    fn from(value: DnsHeaderOpcode) -> Self {
        match value {
            DnsHeaderOpcode::Query => 0,
            DnsHeaderOpcode::InverseQuery => 1,
            DnsHeaderOpcode::Status => 2,
            DnsHeaderOpcode::Notify => 4,
            DnsHeaderOpcode::Update => 5,
            DnsHeaderOpcode::Reserved(value) => value,
        }
    }
}

/// A DNS response code.
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum DnsHeaderResponseCode {
    NoError,
    FormatError,
    ServerFailure,
    NonExistentDomain,
    NotImplemented,
    Refused,
    ExistentDomain,
    ExistentRrSet,
    NonExistentRrSet,
    NotAuthoritative,
    NotZone,
    BadOptVersionOrBadSignature,
    BadKey,
    BadTime,
    BadMode,
    BadName,
    BadAlg,
    Reserved(u8),
}

impl From<DnsHeaderResponseCode> for u8 {
    fn from(r: DnsHeaderResponseCode) -> Self {
        match r {
            DnsHeaderResponseCode::NoError => 0,
            DnsHeaderResponseCode::FormatError => 1,
            DnsHeaderResponseCode::ServerFailure => 2,
            DnsHeaderResponseCode::NonExistentDomain => 3,
            DnsHeaderResponseCode::NotImplemented => 4,
            DnsHeaderResponseCode::Refused => 5,
            DnsHeaderResponseCode::ExistentDomain => 6,
            DnsHeaderResponseCode::ExistentRrSet => 7,
            DnsHeaderResponseCode::NonExistentRrSet => 8,
            DnsHeaderResponseCode::NotAuthoritative => 9,
            DnsHeaderResponseCode::NotZone => 10,
            DnsHeaderResponseCode::BadOptVersionOrBadSignature => 16,
            DnsHeaderResponseCode::BadKey => 17,
            DnsHeaderResponseCode::BadTime => 18,
            DnsHeaderResponseCode::BadMode => 19,
            DnsHeaderResponseCode::BadName => 20,
            DnsHeaderResponseCode::BadAlg => 21,
            DnsHeaderResponseCode::Reserved(n) => n,
        }
    }
}

impl From<u8> for DnsHeaderResponseCode {
    fn from(n: u8) -> Self {
        match n {
            0 => DnsHeaderResponseCode::NoError,
            1 => DnsHeaderResponseCode::FormatError,
            2 => DnsHeaderResponseCode::ServerFailure,
            3 => DnsHeaderResponseCode::NonExistentDomain,
            4 => DnsHeaderResponseCode::NotImplemented,
            5 => DnsHeaderResponseCode::Refused,
            6 => DnsHeaderResponseCode::ExistentDomain,
            7 => DnsHeaderResponseCode::ExistentRrSet,
            8 => DnsHeaderResponseCode::NonExistentRrSet,
            9 => DnsHeaderResponseCode::NotAuthoritative,
            10 => DnsHeaderResponseCode::NotZone,
            16 => DnsHeaderResponseCode::BadOptVersionOrBadSignature,
            17 => DnsHeaderResponseCode::BadKey,
            18 => DnsHeaderResponseCode::BadTime,
            19 => DnsHeaderResponseCode::BadMode,
            20 => DnsHeaderResponseCode::BadName,
            21 => DnsHeaderResponseCode::BadAlg,
            n => DnsHeaderResponseCode::Reserved(n),
        }
    }
}