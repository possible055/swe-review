use flate2::Compression;
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use std::io::{Read, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireType {
    Varint,
    Fixed64,
    LengthDelimited,
    Fixed32,
    #[allow(dead_code)]
    Unknown(u64),
}

#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue<'a> {
    Varint(u64),
    Fixed64([u8; 8]),
    Bytes(&'a [u8]),
    Fixed32([u8; 4]),
}

#[derive(Debug, Clone, PartialEq)]
pub struct Field<'a> {
    pub number: u64,
    pub wire_type: WireType,
    pub value: FieldValue<'a>,
}

#[derive(Default, Debug, Clone)]
pub struct ProtobufEncoder {
    chunks: Vec<Vec<u8>>,
}

impl ProtobufEncoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn varint(mut value: u64) -> Vec<u8> {
        let mut bytes = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            bytes.push(byte);
            if value == 0 {
                break;
            }
        }
        bytes
    }

    pub fn write_varint(&mut self, field: u64, value: u64) -> &mut Self {
        self.chunks.push(Self::tag(field, 0));
        self.chunks.push(Self::varint(value));
        self
    }

    pub fn write_fixed64_f64(&mut self, field: u64, value: f64) -> &mut Self {
        self.chunks.push(Self::tag(field, 1));
        self.chunks.push(value.to_le_bytes().to_vec());
        self
    }

    pub fn write_string(&mut self, field: u64, value: &str) -> &mut Self {
        self.write_bytes(field, value.as_bytes())
    }

    pub fn write_bytes(&mut self, field: u64, value: &[u8]) -> &mut Self {
        self.chunks.push(Self::tag(field, 2));
        self.chunks.push(Self::varint(value.len() as u64));
        self.chunks.push(value.to_vec());
        self
    }

    pub fn write_message(&mut self, field: u64, sub: &ProtobufEncoder) -> &mut Self {
        self.write_bytes(field, &sub.to_bytes())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.chunks.concat()
    }

    fn tag(field: u64, wire: u64) -> Vec<u8> {
        Self::varint((field << 3) | wire)
    }
}

pub fn iter_fields(data: &[u8]) -> Vec<Field<'_>> {
    let mut fields = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let Some((tag, next)) = decode_varint_checked(data, offset) else {
            break;
        };
        offset = next;
        let number = tag >> 3;
        let wire = tag & 0x7;
        let Some(field) = read_field(data, &mut offset, number, wire) else {
            break;
        };
        fields.push(field);
    }
    fields
}

pub fn extract_strings(data: &[u8]) -> Vec<String> {
    iter_fields(data)
        .into_iter()
        .filter_map(|field| match field.value {
            FieldValue::Bytes(bytes) => std::str::from_utf8(bytes).ok().map(ToOwned::to_owned),
            _ => None,
        })
        .collect()
}

pub fn gzip_decompress(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(data);
    let mut out = Vec::new();
    decoder.read_to_end(&mut out)?;
    Ok(out)
}

pub fn gzip_compress(data: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    encoder.finish()
}

fn read_field<'a>(data: &'a [u8], offset: &mut usize, number: u64, wire: u64) -> Option<Field<'a>> {
    match wire {
        0 => {
            let (value, next) = decode_varint_checked(data, *offset)?;
            *offset = next;
            Some(Field {
                number,
                wire_type: WireType::Varint,
                value: FieldValue::Varint(value),
            })
        }
        1 => {
            let end = offset.checked_add(8)?;
            let bytes = data.get(*offset..end)?;
            *offset = end;
            Some(Field {
                number,
                wire_type: WireType::Fixed64,
                value: FieldValue::Fixed64(bytes.try_into().ok()?),
            })
        }
        2 => {
            let (length, next) = decode_varint_checked(data, *offset)?;
            let start = next;
            let end = start.checked_add(length as usize)?;
            let bytes = data.get(start..end)?;
            *offset = end;
            Some(Field {
                number,
                wire_type: WireType::LengthDelimited,
                value: FieldValue::Bytes(bytes),
            })
        }
        5 => {
            let end = offset.checked_add(4)?;
            let bytes = data.get(*offset..end)?;
            *offset = end;
            Some(Field {
                number,
                wire_type: WireType::Fixed32,
                value: FieldValue::Fixed32(bytes.try_into().ok()?),
            })
        }
        _ => None,
    }
}

fn decode_varint_checked(data: &[u8], mut offset: usize) -> Option<(u64, usize)> {
    let mut value = 0_u64;
    let mut shift = 0_u32;
    while offset < data.len() && shift < 64 {
        let byte = data[offset];
        offset += 1;
        value |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((value, offset));
        }
        shift += 7;
    }
    None
}

pub fn field_string(field: &Field<'_>) -> Option<String> {
    match field.value {
        FieldValue::Bytes(bytes) => std::str::from_utf8(bytes).ok().map(ToOwned::to_owned),
        _ => None,
    }
}

pub fn field_bytes<'a>(field: &Field<'a>) -> Option<&'a [u8]> {
    match field.value {
        FieldValue::Bytes(bytes) => Some(bytes),
        _ => None,
    }
}

pub fn field_varint(field: &Field<'_>) -> Option<u64> {
    match field.value {
        FieldValue::Varint(value) => Some(value),
        _ => None,
    }
}

#[allow(dead_code)]
pub fn field_fixed64_f64(field: &Field<'_>) -> Option<f64> {
    match field.value {
        FieldValue::Fixed64(bytes) => Some(f64::from_le_bytes(bytes)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protobuf_encoder_writes_strings_and_messages() {
        let mut inner = ProtobufEncoder::new();
        inner.write_string(1, "ok");

        let mut outer = ProtobufEncoder::new();
        outer.write_message(2, &inner);

        assert_eq!(outer.to_bytes(), b"\x12\x04\x0a\x02ok");
    }

    #[test]
    fn protobuf_encoder_writes_fixed64_f64() {
        let mut encoder = ProtobufEncoder::new();
        encoder.write_fixed64_f64(5, 0.5);

        assert_eq!(encoder.to_bytes(), [0x29, 0, 0, 0, 0, 0, 0, 0xe0, 0x3f]);
    }

    #[test]
    fn iter_fields_reads_supported_wire_types() {
        let mut data = Vec::new();
        data.extend(ProtobufEncoder::varint(8));
        data.extend(ProtobufEncoder::varint(150));
        data.extend([0x11, 1, 2, 3, 4, 5, 6, 7, 8]);
        data.extend([0x1a, 0x02, b'o', b'k']);

        let fields = iter_fields(&data);
        assert_eq!(fields.len(), 3);
        assert_eq!(field_varint(&fields[0]), Some(150));
        assert_eq!(
            field_fixed64_f64(&fields[1]),
            Some(f64::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 8]))
        );
        assert_eq!(field_string(&fields[2]), Some("ok".to_string()));
    }
}
