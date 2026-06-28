use anyhow::{Result, anyhow};

// wrap  payload to format: 1byte type, 2byte length, payload
pub fn pack_msg(typ: u8, payload: &[u8]) -> Result<Vec<u8>> {
 // yea max u16 is 65535
 if payload.len() > 65535 {
        return Err(anyhow!("payload too large"));
    }

// alocate: type1 + len2 + payload
// TODO: using Vec::with_capacity to short the code later 
    let mut out = vec![typ];

// convert lenth payload to byte order
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

// unpack packet to  type and payload
pub fn unpack_msg(data: &[u8]) -> Result<(u8, Vec<u8>)> {
 // 1byte type + 2byte length
   if data.len() < 3 {
        return Err(anyhow!("too short"));
    }
    let typ = data[0];

//  get all information from byte1 and 2
    let len = u16::from_be_bytes([data[1], data[2]]) as usize;
    if data.len() < 3 + len {
// TODO: change return &[u8]
        return Err(anyhow!("incomplete"));
    }

// TODO: change return &[u8]
    Ok((typ, data[3..3 + len].to_vec()))
}