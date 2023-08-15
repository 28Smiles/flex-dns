#[cfg(feature = "arrayvec")]
#[test]
fn comparison_question_compressed() {
    use simple_dns::{CLASS, Name, Packet, Question, TYPE};
    use flex_dns::{dns_name, DnsMessage};
    use flex_dns::header::{DnsHeaderOpcode, DnsHeaderResponseCode};
    use flex_dns::question::{DnsQClass, DnsQType, DnsQuestion};
    let mut packet = Packet::new_query(1);
    packet.questions.push(Question::new(
        Name::new_unchecked("_srv._udp.local"),
        TYPE::AAAA.into(),
        CLASS::IN.into(),
        false,
    ));
    packet.questions.push(Question::new(
        Name::new_unchecked("_srv._udp.local"),
        TYPE::TXT.into(),
        CLASS::IN.into(),
        false,
    ));
    let bytes_reference = packet.build_bytes_vec_compressed().unwrap();

    let buffer: arrayvec::ArrayVec<u8, 512> = arrayvec::ArrayVec::new();
    let mut message: DnsMessage<16, 0, _> = DnsMessage::new(buffer).unwrap();
    message.header_mut().unwrap().set_id(1);
    message.header_mut().unwrap().set_opcode(DnsHeaderOpcode::Query);
    message.header_mut().unwrap().set_authoritative_answer(false);
    message.header_mut().unwrap().set_truncated(false);
    message.header_mut().unwrap().set_recursion_desired(false);
    message.header_mut().unwrap().set_recursion_available(false);
    message.header_mut().unwrap().set_response_code(DnsHeaderResponseCode::NoError);
    let mut questions = message.questions();
    questions.append(DnsQuestion {
        name: dns_name!(b"_srv._udp.local"),
        qtype: DnsQType::AAAA,
        qclass: DnsQClass::IN,
    }).unwrap();
    questions.append(DnsQuestion {
        name: dns_name!(b"_srv._udp.local"),
        qtype: DnsQType::TXT,
        qclass: DnsQClass::IN,
    }).unwrap();
    let message = questions.complete().unwrap();
    let buffer = message.abort().unwrap();

    assert_eq!(bytes_reference.as_slice(), buffer.as_slice())
}

#[cfg(feature = "arrayvec")]
#[test]
fn comparison_question() {
    use simple_dns::{CLASS, Name, Packet, Question, TYPE};
    use flex_dns::{dns_name, DnsMessage};
    use flex_dns::header::{DnsHeaderOpcode, DnsHeaderResponseCode};
    use flex_dns::question::{DnsQClass, DnsQType, DnsQuestion};
    let mut packet = Packet::new_query(1);
    packet.questions.push(Question::new(
        Name::new_unchecked("_srv._udp.local"),
        TYPE::AAAA.into(),
        CLASS::IN.into(),
        false,
    ));
    packet.questions.push(Question::new(
        Name::new_unchecked("_srv._udp.local"),
        TYPE::TXT.into(),
        CLASS::IN.into(),
        false,
    ));
    let bytes_reference = packet.build_bytes_vec().unwrap();

    let buffer: arrayvec::ArrayVec<u8, 512> = arrayvec::ArrayVec::new();
    let mut message: DnsMessage<0, 0, _> = DnsMessage::new(buffer).unwrap();
    message.header_mut().unwrap().set_id(1);
    message.header_mut().unwrap().set_opcode(DnsHeaderOpcode::Query);
    message.header_mut().unwrap().set_authoritative_answer(false);
    message.header_mut().unwrap().set_truncated(false);
    message.header_mut().unwrap().set_recursion_desired(false);
    message.header_mut().unwrap().set_recursion_available(false);
    message.header_mut().unwrap().set_response_code(DnsHeaderResponseCode::NoError);
    let mut questions = message.questions();
    questions.append(DnsQuestion {
        name: dns_name!(b"_srv._udp.local"),
        qtype: DnsQType::AAAA,
        qclass: DnsQClass::IN,
    }).unwrap();
    questions.append(DnsQuestion {
        name: dns_name!(b"_srv._udp.local"),
        qtype: DnsQType::TXT,
        qclass: DnsQClass::IN,
    }).unwrap();
    let message = questions.complete().unwrap();
    let buffer = message.abort().unwrap();

    assert_eq!(bytes_reference.as_slice(), buffer.as_slice())
}

#[cfg(feature = "arrayvec")]
#[test]
fn comparison_answer_compressed() {
    use simple_dns::{CLASS, Name, Packet, ResourceRecord};
    use simple_dns::rdata::RData;
    use flex_dns::{dns_name, DnsMessage};
    use flex_dns::answer::{DnsAClass, DnsAnswer};
    use flex_dns::header::{DnsHeaderKind, DnsHeaderOpcode, DnsHeaderResponseCode};
    use flex_dns::rdata::{A, DnsAType, Txt};

    let mut packet = Packet::new_reply(1);
    packet.answers.push(ResourceRecord::new(
        Name::new_unchecked("_srv._udp.local"),
        CLASS::IN.into(),
        0,
        RData::A(simple_dns::rdata::A {
            address: 0x01020304
        }),
    ));
    packet.answers.push(ResourceRecord::new(
        Name::new_unchecked("_srv._udp.local"),
        CLASS::IN.into(),
        0,
        RData::TXT(simple_dns::rdata::TXT::new()
            .with_string("Hello, world!")
            .unwrap()
        ),
    ));
    let bytes_reference = packet.build_bytes_vec_compressed().unwrap();

    let buffer: arrayvec::ArrayVec<u8, 512> = arrayvec::ArrayVec::new();
    let mut message: DnsMessage<16, 1, _> = DnsMessage::new(buffer).unwrap();
    message.header_mut().unwrap().set_id(1);
    message.header_mut().unwrap().set_opcode(DnsHeaderOpcode::Query);
    message.header_mut().unwrap().set_kind(DnsHeaderKind::Response);
    message.header_mut().unwrap().set_authoritative_answer(false);
    message.header_mut().unwrap().set_truncated(false);
    message.header_mut().unwrap().set_recursion_desired(false);
    message.header_mut().unwrap().set_recursion_available(false);
    message.header_mut().unwrap().set_response_code(DnsHeaderResponseCode::NoError);
    let mut answers = message.answers();
    answers.append(DnsAnswer {
        name: dns_name!(b"_srv._udp.local"),
        rdata: DnsAType::A(A {
            address: [1, 2, 3, 4],
        }),
        cache_flush: false,
        aclass: DnsAClass::IN,
        ttl: 0,
    }).unwrap();
    answers.append(DnsAnswer {
        name: dns_name!(b"_srv._udp.local"),
        rdata: DnsAType::Txt(Txt::new(b"\x0dHello, world!").unwrap()),
        cache_flush: false,
        aclass: DnsAClass::IN,
        ttl: 0,
    }).unwrap();
    let message = answers.complete().unwrap();
    let buffer = message.abort().unwrap();

    assert_eq!(bytes_reference.as_slice(), buffer.as_slice())
}

#[cfg(feature = "arrayvec")]
#[test]
fn comparison_answer() {
    use simple_dns::{CLASS, Name, Packet, ResourceRecord};
    use simple_dns::rdata::RData;
    use flex_dns::{dns_name, DnsMessage};
    use flex_dns::answer::{DnsAClass, DnsAnswer};
    use flex_dns::header::{DnsHeaderKind, DnsHeaderOpcode, DnsHeaderResponseCode};
    use flex_dns::rdata::{A, DnsAType, Txt};

    let mut packet = Packet::new_reply(1);
    packet.answers.push(ResourceRecord::new(
        Name::new_unchecked("_srv._udp.local"),
        CLASS::IN.into(),
        0,
        RData::A(simple_dns::rdata::A {
            address: 0x01020304
        }),
    ));
    packet.answers.push(ResourceRecord::new(
        Name::new_unchecked("_srv._udp.local"),
        CLASS::IN.into(),
        0,
        RData::TXT(simple_dns::rdata::TXT::new()
            .with_string("Hello, world!")
            .unwrap()
        ),
    ));
    let bytes_reference = packet.build_bytes_vec().unwrap();

    let buffer: arrayvec::ArrayVec<u8, 512> = arrayvec::ArrayVec::new();
    let mut message: DnsMessage<0, 1, _> = DnsMessage::new(buffer).unwrap();
    message.header_mut().unwrap().set_id(1);
    message.header_mut().unwrap().set_opcode(DnsHeaderOpcode::Query);
    message.header_mut().unwrap().set_kind(DnsHeaderKind::Response);
    message.header_mut().unwrap().set_authoritative_answer(false);
    message.header_mut().unwrap().set_truncated(false);
    message.header_mut().unwrap().set_recursion_desired(false);
    message.header_mut().unwrap().set_recursion_available(false);
    message.header_mut().unwrap().set_response_code(DnsHeaderResponseCode::NoError);
    let mut answers = message.answers();
    answers.append(DnsAnswer {
        name: dns_name!(b"_srv._udp.local"),
        rdata: DnsAType::A(A {
            address: [1, 2, 3, 4],
        }),
        cache_flush: false,
        aclass: DnsAClass::IN,
        ttl: 0,
    }).unwrap();
    answers.append(DnsAnswer {
        name: dns_name!(b"_srv._udp.local"),
        rdata: DnsAType::Txt(Txt::new(b"\x0dHello, world!").unwrap()),
        cache_flush: false,
        aclass: DnsAClass::IN,
        ttl: 0,
    }).unwrap();
    let message = answers.complete().unwrap();
    let buffer = message.abort().unwrap();

    assert_eq!(bytes_reference.as_slice(), buffer.as_slice())
}

#[cfg(feature = "arrayvec")]
#[test]
fn comparison_mixed() {
    use simple_dns::{CLASS, Name, Packet, Question, ResourceRecord, TYPE};
    use simple_dns::rdata::RData;
    use flex_dns::{dns_name, dns_txt, DnsMessage};
    use flex_dns::answer::{DnsAClass, DnsAnswer};
    use flex_dns::header::{DnsHeaderKind, DnsHeaderOpcode, DnsHeaderResponseCode};
    use flex_dns::question::{DnsQClass, DnsQType, DnsQuestion};
    use flex_dns::rdata::{A, DnsAType};

    let mut packet = Packet::new_query(1);
    packet.questions.push(Question::new(
        Name::new_unchecked("esp32.local"),
        TYPE::AAAA.into(),
        CLASS::IN.into(),
        false,
    ));
    packet.questions.push(Question::new(
        Name::new_unchecked("_srv._udp.local"),
        TYPE::TXT.into(),
        CLASS::IN.into(),
        false,
    ));
    packet.answers.push(ResourceRecord::new(
        Name::new_unchecked("esp32.local"),
        CLASS::IN.into(),
        0,
        RData::A(simple_dns::rdata::A {
            address: 0x01020304
        }),
    ));
    packet.answers.push(ResourceRecord::new(
        Name::new_unchecked("_srv._udp.local"),
        CLASS::IN.into(),
        0,
        RData::TXT(simple_dns::rdata::TXT::new()
            .with_string("Hello, world!")
            .unwrap()
            .with_string("This is a test")
            .unwrap()
        ),
    ));
    let bytes_reference = packet.build_bytes_vec().unwrap();

    let buffer: arrayvec::ArrayVec<u8, 512> = arrayvec::ArrayVec::new();
    let mut message: DnsMessage<0, 0, _> = DnsMessage::new(buffer).unwrap();
    message.header_mut().unwrap().set_id(1);
    message.header_mut().unwrap().set_opcode(DnsHeaderOpcode::Query);
    message.header_mut().unwrap().set_kind(DnsHeaderKind::Query);
    message.header_mut().unwrap().set_authoritative_answer(false);
    message.header_mut().unwrap().set_truncated(false);
    message.header_mut().unwrap().set_recursion_desired(false);
    message.header_mut().unwrap().set_recursion_available(false);
    message.header_mut().unwrap().set_response_code(DnsHeaderResponseCode::NoError);
    let mut questions = message.questions();
    questions.append(DnsQuestion {
        name: dns_name!(b"esp32.local"),
        qtype: DnsQType::AAAA,
        qclass: DnsQClass::IN,
    }).unwrap();
    questions.append(DnsQuestion {
        name: dns_name!(b"_srv._udp.local"),
        qtype: DnsQType::TXT,
        qclass: DnsQClass::IN,
    }).unwrap();
    let message = questions.complete().unwrap();
    let mut answers = message.answers();
    answers.append(DnsAnswer {
        name: dns_name!(b"esp32.local"),
        rdata: DnsAType::A(A {
            address: [1, 2, 3, 4],
        }),
        cache_flush: false,
        aclass: DnsAClass::IN,
        ttl: 0,
    }).unwrap();
    answers.append(DnsAnswer {
        name: dns_name!(b"_srv._udp.local"),
        rdata: DnsAType::Txt(dns_txt!(
            b"Hello, world!",
            b"This is a test",
        )),
        cache_flush: false,
        aclass: DnsAClass::IN,
        ttl: 0,
    }).unwrap();
    let message = answers.complete().unwrap();
    let buffer = message.abort().unwrap();

    assert_eq!(bytes_reference.as_slice(), buffer.as_slice());
}

#[cfg(feature = "arrayvec")]
#[test]
fn comparison_mixed_compressed() {
    use simple_dns::{CLASS, Name, Packet, Question, ResourceRecord, TYPE};
    use simple_dns::rdata::RData;
    use flex_dns::{dns_name, dns_txt, DnsMessage};
    use flex_dns::answer::{DnsAClass, DnsAnswer};
    use flex_dns::header::{DnsHeaderKind, DnsHeaderOpcode, DnsHeaderResponseCode};
    use flex_dns::question::{DnsQClass, DnsQType, DnsQuestion};
    use flex_dns::rdata::{A, DnsAType};

    let mut packet = Packet::new_query(1);
    packet.questions.push(Question::new(
        Name::new_unchecked("esp32.local"),
        TYPE::AAAA.into(),
        CLASS::IN.into(),
        false,
    ));
    packet.questions.push(Question::new(
        Name::new_unchecked("_srv._udp.local"),
        TYPE::TXT.into(),
        CLASS::IN.into(),
        false,
    ));
    packet.answers.push(ResourceRecord::new(
        Name::new_unchecked("esp32.local"),
        CLASS::IN.into(),
        0,
        RData::A(simple_dns::rdata::A {
            address: 0x01020304
        }),
    ));
    packet.answers.push(ResourceRecord::new(
        Name::new_unchecked("_srv._udp.local"),
        CLASS::IN.into(),
        0,
        RData::TXT(simple_dns::rdata::TXT::new()
            .with_string("Hello, world!")
            .unwrap()
            .with_string("This is a test")
            .unwrap()
        ),
    ));
    let bytes_reference = packet.build_bytes_vec_compressed().unwrap();

    let buffer: arrayvec::ArrayVec<u8, 512> = arrayvec::ArrayVec::new();
    let mut message: DnsMessage<16, 0, _> = DnsMessage::new(buffer).unwrap();
    message.header_mut().unwrap().set_id(1);
    message.header_mut().unwrap().set_opcode(DnsHeaderOpcode::Query);
    message.header_mut().unwrap().set_kind(DnsHeaderKind::Query);
    message.header_mut().unwrap().set_authoritative_answer(false);
    message.header_mut().unwrap().set_truncated(false);
    message.header_mut().unwrap().set_recursion_desired(false);
    message.header_mut().unwrap().set_recursion_available(false);
    message.header_mut().unwrap().set_response_code(DnsHeaderResponseCode::NoError);
    let mut questions = message.questions();
    questions.append(DnsQuestion {
        name: dns_name!(b"esp32.local"),
        qtype: DnsQType::AAAA,
        qclass: DnsQClass::IN,
    }).unwrap();
    questions.append(DnsQuestion {
        name: dns_name!(b"_srv._udp.local"),
        qtype: DnsQType::TXT,
        qclass: DnsQClass::IN,
    }).unwrap();
    let message = questions.complete().unwrap();
    let mut answers = message.answers();
    answers.append(DnsAnswer {
        name: dns_name!(b"esp32.local"),
        rdata: DnsAType::A(A {
            address: [1, 2, 3, 4],
        }),
        cache_flush: false,
        aclass: DnsAClass::IN,
        ttl: 0,
    }).unwrap();
    answers.append(DnsAnswer {
        name: dns_name!(b"_srv._udp.local"),
        rdata: DnsAType::Txt(dns_txt!(
            b"Hello, world!",
            b"This is a test",
        )),
        cache_flush: false,
        aclass: DnsAClass::IN,
        ttl: 0,
    }).unwrap();
    let message = answers.complete().unwrap();
    let buffer = message.abort().unwrap();

    assert_eq!(bytes_reference.as_slice(), buffer.as_slice());
}

#[cfg(feature = "arrayvec")]
#[test]
fn test_complex() {
    use simple_dns::{CLASS, Name, Packet, ResourceRecord};
    use simple_dns::rdata::RData;
    use flex_dns::{dns_name, dns_txt, DnsMessage};
    use flex_dns::answer::{DnsAClass, DnsAnswer};
    use flex_dns::header::{DnsHeaderKind, DnsHeaderOpcode, DnsHeaderResponseCode};
    use flex_dns::rdata::{A, DnsAType, Ptr, Srv};

    let mut packet = Packet::new_query(1);
    packet.answers.push(ResourceRecord::new(
        Name::new_unchecked("_hap._tcp.local"),
        CLASS::IN.into(),
        120,
        RData::PTR(simple_dns::rdata::PTR(Name::new_unchecked("esp32.local"))),
    ));
    packet.answers.push(ResourceRecord::new(
        Name::new_unchecked("esp32.local"),
        CLASS::IN.into(),
        120,
        RData::SRV(simple_dns::rdata::SRV {
            priority: 0,
            weight: 0,
            port: 32000,
            target: Name::new_unchecked("esp32.local"),
        }),
    ));
    packet.answers.push(ResourceRecord::new(
        Name::new_unchecked("esp32.local"),
        CLASS::IN.into(),
        120,
        RData::TXT(simple_dns::rdata::TXT::new()
            .with_string("c#=2").unwrap()
            .with_string("ff=0").unwrap()
            .with_string("id=0a:14:1e:28:32:3c").unwrap()
            .with_string("md=esp32").unwrap()
            .with_string("pv=1.0").unwrap()
            .with_string("s#=1").unwrap()
            .with_string("sf=0").unwrap()
            .with_string("ci=10").unwrap()
        ),
    ));
    packet.answers.push(ResourceRecord::new(
        Name::new_unchecked("esp32.local"),
        CLASS::IN.into(),
        120,
        RData::A(simple_dns::rdata::A {
            address: 0x01020304,
        }),
    ));
    let bytes_reference = packet.build_bytes_vec().unwrap();

    let buffer: arrayvec::ArrayVec<u8, 512> = arrayvec::ArrayVec::new();
    let mut message: DnsMessage<0, 0, _> = DnsMessage::new(buffer).unwrap();
    message.header_mut().unwrap().set_id(1);
    message.header_mut().unwrap().set_opcode(DnsHeaderOpcode::Query);
    message.header_mut().unwrap().set_kind(DnsHeaderKind::Query);
    message.header_mut().unwrap().set_authoritative_answer(false);
    message.header_mut().unwrap().set_truncated(false);
    message.header_mut().unwrap().set_recursion_desired(false);
    message.header_mut().unwrap().set_recursion_available(false);
    message.header_mut().unwrap().set_response_code(DnsHeaderResponseCode::NoError);
    let questions = message.questions();
    let message = questions.complete().unwrap();
    let mut answers = message.answers();
    answers.append(DnsAnswer {
        name: dns_name!(b"_hap._tcp.local"),
        rdata: DnsAType::Ptr(Ptr {
            name: dns_name!(b"esp32.local"),
        }),
        cache_flush: false,
        aclass: DnsAClass::IN,
        ttl: 120,
    }).unwrap();
    answers.append(DnsAnswer {
        name: dns_name!(b"esp32.local"),
        rdata: DnsAType::Srv(Srv {
            priority: 0,
            weight: 0,
            port: 32000,
            target: dns_name!(b"esp32.local"),
        }),
        cache_flush: false,
        aclass: DnsAClass::IN,
        ttl: 120,
    }).unwrap();
    answers.append(DnsAnswer {
        name: dns_name!(b"esp32.local"),
        rdata: DnsAType::Txt(dns_txt!(
            b"c#=2",
            b"ff=0",
            b"id=0a:14:1e:28:32:3c",
            b"md=esp32",
            b"pv=1.0",
            b"s#=1",
            b"sf=0",
            b"ci=10",
        )),
        cache_flush: false,
        aclass: DnsAClass::IN,
        ttl: 120,
    }).unwrap();
    answers.append(DnsAnswer {
        name: dns_name!(b"esp32.local"),
        rdata: DnsAType::A(A {
            address: [1, 2, 3, 4],
        }),
        cache_flush: false,
        aclass: DnsAClass::IN,
        ttl: 120,
    }).unwrap();
    let message = answers.complete().unwrap();
    let buffer = message.abort().unwrap();

    assert_eq!(bytes_reference.as_slice(), buffer.as_slice());
}