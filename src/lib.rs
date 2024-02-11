use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    multi::many0,
    number::complete::{le_u16, le_u64, u8},
    IResult,
};

#[derive(Debug)]
pub struct Header {
    pub version: u8,
    pub timestamp: u64,
}

#[derive(Debug)]
pub struct MessageHeader {
    pub msg_size: u16,
    pub msg_type: u8,
}

#[derive(Debug)]
pub struct MessageFlagBits {
    pub header: MessageHeader,
    pub compat_flags: [u8; 8],
    pub incompat_flags: [u8; 8],
    pub appended_offsets: [u8; 3],
}

#[derive(Debug)]
pub struct MessageFormat {
    pub header: MessageHeader,
    pub format: String,
}

#[derive(Debug)]
pub struct MessageInfo {
    pub header: MessageHeader,
    pub key_len: u8,
    pub key: String,
    pub value: Vec<u8>,
}

#[derive(Debug)]
pub struct MessageInfoMultiple {
    pub header: MessageHeader,
    pub is_continued: u8,
    pub key_len: u8,
    pub key: String,
    pub value: Vec<u8>,
}

#[derive(Debug)]
pub struct MessageParameter {
    pub header: MessageHeader,
    pub key_len: u8,
    pub key: String,
    pub value: Vec<u8>,
}

#[derive(Debug)]
pub struct MessageParameterDefault {
    pub header: MessageHeader,
    pub default_types: u8,
    pub key_len: u8,
    pub key: String,
    pub value: Vec<u8>,
}

#[derive(Debug)]
pub struct MessageAddLogged {
    pub header: MessageHeader,
    pub multi_id: u8,
    pub msg_id: u16,
    pub message_name: String,
}

#[derive(Debug)]
pub struct MessageRemoveLogged {
    pub header: MessageHeader,
    pub msg_id: u16,
}

#[derive(Debug)]
pub struct MessageData {
    pub header: MessageHeader,
    pub msg_id: u16,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub struct MessageLogging {
    pub header: MessageHeader,
    pub log_level: u8,
    pub timestamp: u64,
    pub message: String,
}

#[derive(Debug)]
pub struct MessageLoggingTagged {
    pub header: MessageHeader,
    pub log_level: u8,
    pub tag: u16,
    pub timestamp: u64,
    pub message: String,
}

#[derive(Debug)]
pub struct MessageSync {
    pub header: MessageHeader,
    pub sync_magic: u8,
}

#[derive(Debug)]
pub struct MessageDropout {
    pub header: MessageHeader,
    pub duration: u16,
}

#[derive(Debug)]
pub enum Message {
    Format(MessageFormat),
    Info(MessageInfo),
    InfoMultiple(MessageInfoMultiple),
    Parameter(MessageParameter),
    ParameterDefault(MessageParameterDefault),
    AddLogged(MessageAddLogged),
    RemoveLogged(MessageRemoveLogged),
    Data(MessageData),
    Logging(MessageLogging),
    LoggingTagged(MessageLoggingTagged),
    Sync(MessageSync),
    Dropout(MessageDropout),
}

#[derive(Debug)]
pub struct Ulog {
    pub header: Header,
    pub message_flag_bits: MessageFlagBits,
    pub messages: Vec<Message>,
}

pub fn header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, _magic_number) = tag([0x55, 0x4c, 0x6f, 0x67, 0x01, 0x12, 0x35])(input)?;
    let (input, version) = u8(input)?;
    let (input, timestamp) = le_u64(input)?;
    Ok((input, Header { version, timestamp }))
}

pub fn message_header(input: &[u8], msg_type: u8) -> IResult<&[u8], MessageHeader> {
    let (input, msg_size) = le_u16(input)?;
    let (input, msg_type) = tag([msg_type])(input)?;
    Ok((
        input,
        MessageHeader {
            msg_size,
            msg_type: msg_type[0],
        },
    ))
}

pub fn message_flag_bits(input: &[u8]) -> IResult<&[u8], MessageFlagBits> {
    let (input, header) = message_header(input, b'B')?;
    let (input, message_input) = take(header.msg_size)(input)?;
    let (message_input, compat_flags) = take(8usize)(message_input)?;
    let (message_input, incompat_flags) = take(8usize)(message_input)?;
    let (_message_input, appended_offsets) = take(3usize)(message_input)?;
    Ok((
        input,
        MessageFlagBits {
            header,
            compat_flags: compat_flags.try_into().unwrap(),
            incompat_flags: incompat_flags.try_into().unwrap(),
            appended_offsets: appended_offsets.try_into().unwrap(),
        },
    ))
}

pub fn message_format(input: &[u8]) -> IResult<&[u8], Message> {
    let (input, header) = message_header(input, b'F')?;
    let (input, format) = take(header.msg_size)(input)?;
    Ok((
        input,
        Message::Format(MessageFormat {
            header,
            format: String::from_utf8(format.to_vec()).unwrap(),
        }),
    ))
}

pub fn message_info(input: &[u8]) -> IResult<&[u8], Message> {
    let (input, header) = message_header(input, b'I')?;
    let (input, key_len) = u8(input)?;
    let (input, key) = take(key_len)(input)?;
    let (input, value) = take(header.msg_size - 1 - key_len as u16)(input)?;
    Ok((
        input,
        Message::Info(MessageInfo {
            header,
            key_len,
            key: String::from_utf8(key.to_vec()).unwrap(),
            value: value.to_vec(),
        }),
    ))
}

pub fn message_info_multiple(input: &[u8]) -> IResult<&[u8], Message> {
    let (input, header) = message_header(input, b'M')?;
    let (input, is_continued) = u8(input)?;
    let (input, key_len) = u8(input)?;
    let (input, key) = take(key_len)(input)?;
    let (input, value) = take(header.msg_size - 2 - key_len as u16)(input)?;
    Ok((
        input,
        Message::InfoMultiple(MessageInfoMultiple {
            header,
            is_continued,
            key_len,
            key: String::from_utf8(key.to_vec()).unwrap(),
            value: value.to_vec(),
        }),
    ))
}

pub fn message_parameter(input: &[u8]) -> IResult<&[u8], Message> {
    let (input, header) = message_header(input, b'P')?;
    let (input, key_len) = u8(input)?;
    let (input, key) = take(key_len)(input)?;
    let (input, value) = take(header.msg_size - 1 - key_len as u16)(input)?;
    Ok((
        input,
        Message::Parameter(MessageParameter {
            header,
            key_len,
            key: String::from_utf8(key.to_vec()).unwrap(),
            value: value.to_vec(),
        }),
    ))
}

pub fn message_parameter_default(input: &[u8]) -> IResult<&[u8], Message> {
    let (input, header) = message_header(input, b'Q')?;
    let (input, default_types) = u8(input)?;
    let (input, key_len) = u8(input)?;
    let (input, key) = take(key_len)(input)?;
    let (input, value) = take(header.msg_size - 2 - key_len as u16)(input)?;
    Ok((
        input,
        Message::ParameterDefault(MessageParameterDefault {
            header,
            default_types,
            key_len,
            key: String::from_utf8(key.to_vec()).unwrap(),
            value: value.to_vec(),
        }),
    ))
}

pub fn message_add_logged(input: &[u8]) -> IResult<&[u8], Message> {
    let (input, header) = message_header(input, b'A')?;
    let (input, multi_id) = u8(input)?;
    let (input, msg_id) = le_u16(input)?;
    let (input, message_name) = take(header.msg_size - 3)(input)?;
    Ok((
        input,
        Message::AddLogged(MessageAddLogged {
            header,
            multi_id,
            msg_id,
            message_name: String::from_utf8(message_name.to_vec()).unwrap(),
        }),
    ))
}

pub fn message_remove_logged(input: &[u8]) -> IResult<&[u8], Message> {
    let (input, header) = message_header(input, b'R')?;
    let (input, msg_id) = le_u16(input)?;
    Ok((
        input,
        Message::RemoveLogged(MessageRemoveLogged { header, msg_id }),
    ))
}

pub fn message_data(input: &[u8]) -> IResult<&[u8], Message> {
    let (input, header) = message_header(input, b'D')?;
    let (input, msg_id) = le_u16(input)?;
    let (input, data) = take(header.msg_size - 2)(input)?;
    Ok((
        input,
        Message::Data(MessageData {
            header,
            msg_id,
            data: data.to_vec(),
        }),
    ))
}

pub fn message_logging(input: &[u8]) -> IResult<&[u8], Message> {
    let (input, header) = message_header(input, b'L')?;
    let (input, log_level) = u8(input)?;
    let (input, timestamp) = le_u64(input)?;
    let (input, message) = take(header.msg_size - 9)(input)?;
    Ok((
        input,
        Message::Logging(MessageLogging {
            header,
            log_level,
            timestamp,
            message: String::from_utf8(message.to_vec()).unwrap(),
        }),
    ))
}

pub fn message_logging_tagged(input: &[u8]) -> IResult<&[u8], Message> {
    let (input, header) = message_header(input, b'C')?;
    let (input, log_level) = u8(input)?;
    let (input, tag) = le_u16(input)?;
    let (input, timestamp) = le_u64(input)?;
    let (input, message) = take(header.msg_size - 11)(input)?;
    Ok((
        input,
        Message::LoggingTagged(MessageLoggingTagged {
            header,
            log_level,
            tag,
            timestamp,
            message: String::from_utf8(message.to_vec()).unwrap(),
        }),
    ))
}

pub fn message_sync(input: &[u8]) -> IResult<&[u8], Message> {
    let (input, header) = message_header(input, b'S')?;
    let (input, sync_magic) = u8(input)?;
    Ok((input, Message::Sync(MessageSync { header, sync_magic })))
}

pub fn message_dropout(input: &[u8]) -> IResult<&[u8], Message> {
    let (input, header) = message_header(input, b'O')?;
    let (input, duration) = le_u16(input)?;
    Ok((input, Message::Dropout(MessageDropout { header, duration })))
}

pub fn message(input: &[u8]) -> IResult<&[u8], Message> {
    let (input, message) = alt((
        message_format,
        message_info,
        message_info_multiple,
        message_parameter,
        message_parameter_default,
        message_add_logged,
        message_remove_logged,
        message_data,
        message_logging,
        message_logging_tagged,
        message_sync,
        message_dropout,
    ))(input)?;
    Ok((input, message))
}

pub fn ulog(input: &[u8]) -> IResult<&[u8], Ulog> {
    let (input, header) = header(input)?;
    let (input, message_flag_bits) = message_flag_bits(input)?;
    let (_, messages) = many0(message)(input)?;

    Ok((
        &[],
        Ulog {
            header,
            message_flag_bits,
            messages,
        },
    ))
}

pub fn parse_ulog(input: &[u8]) -> Option<Ulog> {
    let (_, ulog) = ulog(input).ok()?;
    Some(ulog)
}
