use forge_types::{ForgeError, Result};
use rmp::Marker;
use std::io::{Cursor, Read};

/// Extremely fast, zero-allocation MessagePack field extractor.
/// Scans the binary payload, looking for the target map key, and returns
/// the raw bytes of the associated value.
pub fn extract_field_raw<'a>(doc: &'a [u8], field: &str) -> Result<Option<&'a [u8]>> {
    let mut cursor = std::io::Cursor::new(doc);

    let marker = rmp::decode::read_marker(&mut cursor)
        .map_err(|e| ForgeError::Serialization(format!("failed to read marker: {:?}", e)))?;

    let len = match marker {
        Marker::FixMap(len) => len as u32,
        Marker::Map16 => read_data_u16(&mut cursor)
            .map_err(|_| ForgeError::Serialization("invalid map16".into()))?
            as u32,
        Marker::Map32 => read_data_u32(&mut cursor)
            .map_err(|_| ForgeError::Serialization("invalid map32".into()))?,
        _ => return Ok(None), // Not a map, can't extract fields
    };

    let target_bytes = field.as_bytes();

    for _ in 0..len {
        // Read key
        let key_start = cursor.position() as usize;
        skip_value(&mut cursor)?;
        let key_end = cursor.position() as usize;

        let key_slice = &doc[key_start..key_end];
        let mut key_cursor = std::io::Cursor::new(key_slice);

        let mut is_match = false;
        if let Ok(str_len) = rmp::decode::read_str_len(&mut key_cursor) {
            let str_start = key_start + key_cursor.position() as usize;
            let str_end = str_start + str_len as usize;
            if str_end <= doc.len() && &doc[str_start..str_end] == target_bytes {
                is_match = true;
            }
        }

        // Read value bounds
        let val_start = cursor.position() as usize;
        skip_value(&mut cursor)?;
        let val_end = cursor.position() as usize;

        if is_match {
            return Ok(Some(&doc[val_start..val_end]));
        }
    }

    Ok(None)
}

fn read_data_u8(cursor: &mut Cursor<&[u8]>) -> std::result::Result<u8, std::io::Error> {
    let mut buf = [0u8; 1];
    cursor.read_exact(&mut buf)?;
    Ok(buf[0])
}

fn read_data_u16(cursor: &mut Cursor<&[u8]>) -> std::result::Result<u16, std::io::Error> {
    let mut buf = [0u8; 2];
    cursor.read_exact(&mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

fn read_data_u32(cursor: &mut Cursor<&[u8]>) -> std::result::Result<u32, std::io::Error> {
    let mut buf = [0u8; 4];
    cursor.read_exact(&mut buf)?;
    Ok(u32::from_be_bytes(buf))
}

/// Recursively skips a single MessagePack value in the cursor.
fn skip_value(cursor: &mut Cursor<&[u8]>) -> Result<()> {
    let marker = rmp::decode::read_marker(cursor)
        .map_err(|_| ForgeError::Serialization("EOF during skip".into()))?;

    match marker {
        Marker::FixPos(_) | Marker::FixNeg(_) | Marker::Null | Marker::True | Marker::False => {
            Ok(())
        }
        Marker::U8 | Marker::I8 => {
            cursor.set_position(cursor.position() + 1);
            Ok(())
        }
        Marker::U16 | Marker::I16 => {
            cursor.set_position(cursor.position() + 2);
            Ok(())
        }
        Marker::U32 | Marker::I32 | Marker::F32 => {
            cursor.set_position(cursor.position() + 4);
            Ok(())
        }
        Marker::U64 | Marker::I64 | Marker::F64 => {
            cursor.set_position(cursor.position() + 8);
            Ok(())
        }
        Marker::FixStr(len) => {
            cursor.set_position(cursor.position() + len as u64);
            Ok(())
        }
        Marker::Str8 | Marker::Bin8 => {
            let len = read_data_u8(cursor).map_err(|_| ForgeError::Serialization("EOF".into()))?;
            cursor.set_position(cursor.position() + len as u64);
            Ok(())
        }
        Marker::Str16 | Marker::Bin16 => {
            let len = read_data_u16(cursor).map_err(|_| ForgeError::Serialization("EOF".into()))?;
            cursor.set_position(cursor.position() + len as u64);
            Ok(())
        }
        Marker::Str32 | Marker::Bin32 => {
            let len = read_data_u32(cursor).map_err(|_| ForgeError::Serialization("EOF".into()))?;
            cursor.set_position(cursor.position() + len as u64);
            Ok(())
        }
        Marker::FixArray(len) => {
            for _ in 0..len {
                skip_value(cursor)?;
            }
            Ok(())
        }
        Marker::Array16 => {
            let len = read_data_u16(cursor).map_err(|_| ForgeError::Serialization("EOF".into()))?;
            for _ in 0..len {
                skip_value(cursor)?;
            }
            Ok(())
        }
        Marker::Array32 => {
            let len = read_data_u32(cursor).map_err(|_| ForgeError::Serialization("EOF".into()))?;
            for _ in 0..len {
                skip_value(cursor)?;
            }
            Ok(())
        }
        Marker::FixMap(len) => {
            for _ in 0..len * 2 {
                skip_value(cursor)?;
            }
            Ok(())
        }
        Marker::Map16 => {
            let len = read_data_u16(cursor).map_err(|_| ForgeError::Serialization("EOF".into()))?;
            for _ in 0..len * 2 {
                skip_value(cursor)?;
            }
            Ok(())
        }
        Marker::Map32 => {
            let len = read_data_u32(cursor).map_err(|_| ForgeError::Serialization("EOF".into()))?;
            for _ in 0..len * 2 {
                skip_value(cursor)?;
            }
            Ok(())
        }
        Marker::FixExt1 => {
            cursor.set_position(cursor.position() + 2);
            Ok(())
        }
        Marker::FixExt2 => {
            cursor.set_position(cursor.position() + 3);
            Ok(())
        }
        Marker::FixExt4 => {
            cursor.set_position(cursor.position() + 5);
            Ok(())
        }
        Marker::FixExt8 => {
            cursor.set_position(cursor.position() + 9);
            Ok(())
        }
        Marker::FixExt16 => {
            cursor.set_position(cursor.position() + 17);
            Ok(())
        }
        Marker::Ext8 => {
            let len = read_data_u8(cursor).map_err(|_| ForgeError::Serialization("EOF".into()))?;
            cursor.set_position(cursor.position() + 1 + len as u64);
            Ok(())
        }
        Marker::Ext16 => {
            let len = read_data_u16(cursor).map_err(|_| ForgeError::Serialization("EOF".into()))?;
            cursor.set_position(cursor.position() + 1 + len as u64);
            Ok(())
        }
        Marker::Ext32 => {
            let len = read_data_u32(cursor).map_err(|_| ForgeError::Serialization("EOF".into()))?;
            cursor.set_position(cursor.position() + 1 + len as u64);
            Ok(())
        }
        Marker::Reserved => Err(ForgeError::Serialization("Reserved marker".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extracts_field_from_msgpack() {
        let doc = json!({
            "id": "123",
            "active": true,
            "nested": [1, 2, 3],
            "target": "found_me"
        });

        let bytes = rmp_serde::to_vec_named(&doc).unwrap();

        let extracted = extract_field_raw(&bytes, "target")
            .unwrap()
            .expect("should find target");
        let decoded: String = rmp_serde::from_slice(extracted).unwrap();

        assert_eq!(decoded, "found_me");
    }

    #[test]
    fn returns_none_if_missing() {
        let doc = json!({
            "id": "123",
            "active": true
        });

        let bytes = rmp_serde::to_vec_named(&doc).unwrap();

        let extracted = extract_field_raw(&bytes, "missing").unwrap();
        assert!(extracted.is_none());
    }

    #[test]
    fn ignores_nested_fields_with_same_name() {
        let doc = json!({
            "id": "123",
            "nested": {
                "target": "wrong"
            },
            "target": "right"
        });

        let bytes = rmp_serde::to_vec_named(&doc).unwrap();

        let extracted = extract_field_raw(&bytes, "target")
            .unwrap()
            .expect("should find target");
        let decoded: String = rmp_serde::from_slice(extracted).unwrap();

        assert_eq!(decoded, "right"); // Top level only
    }
}
