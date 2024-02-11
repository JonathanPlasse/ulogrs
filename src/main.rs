use nom::{
    bytes::complete::{tag, take},
    number::complete::{le_u16, le_u64, u8},
    IResult,
};

#[derive(Debug)]
pub struct Header {
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
    pub value: String,
}

#[derive(Debug)]
pub struct MessageInfoMultiple {
    pub header: MessageHeader,
    pub is_continued: u8,
    pub key_len: u8,
    pub key: String,
    pub value: String,
}

#[derive(Debug)]
pub struct MessageParameter {
    pub header: MessageHeader,
    pub key_len: u8,
    pub key: String,
    pub value: String,
}

#[derive(Debug)]
pub struct MessageParameterDefault {
    pub header: MessageHeader,
    pub default_types: u8,
    pub key_len: u8,
    pub key: String,
    pub value: String,
}

fn header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, _magic_number) = tag([0x55, 0x4c, 0x6f, 0x67, 0x01, 0x12, 0x35])(input)?;
    let (input, _version) = tag([0x01])(input)?;
    let (input, timestamp) = le_u64(input)?;
    Ok((input, Header { timestamp }))
}

fn message_header(input: &[u8], msg_type: u8) -> IResult<&[u8], MessageHeader> {
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

fn message_flag_bits(input: &[u8]) -> IResult<&[u8], MessageFlagBits> {
    let (input, header) = message_header(input, 'B' as u8)?;
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

fn message_format(input: &[u8]) -> IResult<&[u8], MessageFormat> {
    let (input, header) = message_header(input, 'F' as u8)?;
    let (input, format) = take(header.msg_size)(input)?;
    Ok((
        input,
        MessageFormat {
            header,
            format: String::from_utf8(format.to_vec()).unwrap(),
        },
    ))
}

fn message_info(input: &[u8]) -> IResult<&[u8], MessageInfo> {
    let (input, header) = message_header(input, 'I' as u8)?;
    let (input, key_len) = u8(input)?;
    let (input, key) = take(key_len)(input)?;
    let (input, value) = take(header.msg_size - 1 - key_len as u16)(input)?;
    Ok((
        input,
        MessageInfo {
            header,
            key_len,
            key: String::from_utf8(key.to_vec()).unwrap(),
            value: String::from_utf8(value.to_vec()).unwrap(),
        },
    ))
}

fn message_info_multiple(input: &[u8]) -> IResult<&[u8], MessageInfoMultiple> {
    let (input, header) = message_header(input, 'M' as u8)?;
    let (input, is_continued) = u8(input)?;
    let (input, key_len) = u8(input)?;
    let (input, key) = take(key_len)(input)?;
    let (input, value) = take(header.msg_size - 2 - key_len as u16)(input)?;
    Ok((
        input,
        MessageInfoMultiple {
            header,
            is_continued,
            key_len,
            key: String::from_utf8(key.to_vec()).unwrap(),
            value: String::from_utf8(value.to_vec()).unwrap(),
        },
    ))
}

fn message_parameter(input: &[u8]) -> IResult<&[u8], MessageParameter> {
    let (input, header) = message_header(input, 'P' as u8)?;
    let (input, key_len) = u8(input)?;
    let (input, key) = take(key_len)(input)?;
    let (input, value) = take(header.msg_size - 1 - key_len as u16)(input)?;
    Ok((
        input,
        MessageParameter {
            header,
            key_len,
            key: String::from_utf8(key.to_vec()).unwrap(),
            value: String::from_utf8(value.to_vec()).unwrap(),
        },
    ))
}

fn message_parameter_default(input: &[u8]) -> IResult<&[u8], MessageParameterDefault> {
    let (input, header) = message_header(input, 'D' as u8)?;
    let (input, default_types) = u8(input)?;
    let (input, key_len) = u8(input)?;
    let (input, key) = take(key_len)(input)?;
    let (input, value) = take(header.msg_size - 2 - key_len as u16)(input)?;
    Ok((
        input,
        MessageParameterDefault {
            header,
            default_types,
            key_len,
            key: String::from_utf8(key.to_vec()).unwrap(),
            value: String::from_utf8(value.to_vec()).unwrap(),
        },
    ))
}

fn main() {
    let input = std::fs::read("/home/jonathan/Downloads/1st_3_logs/10_47_33.ulg").unwrap();
    let (input, header) = header(&input).unwrap();
    println!("{:?}", header);
    let (input, message_flag_bits) = message_flag_bits(input).unwrap();
    println!("{:?}", message_flag_bits);
}
