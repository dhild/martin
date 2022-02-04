use byteorder::{BigEndian, WriteBytesExt};
use names::Name;
use names::write_name;
use rr::{Class, Type, ResourceRecord};
use std::io;
use std::io::{Cursor, Write};

fn write_data(name: &Name,
              rtype: Type,
              rclass: Class,
              ttl: i32,
              data: &[u8],
              cursor: &mut Write)
              -> io::Result<()> {
    write_name(name, cursor)?;
    cursor.write_u16::<BigEndian>(rtype.into())?;
    cursor.write_u16::<BigEndian>(rclass.into())?;
    cursor.write_i32::<BigEndian>(ttl)?;
    cursor.write_u16::<BigEndian>(data.len() as u16)?;
    cursor.write_all(data)?;
    Ok(())
}

pub fn write_rr<T>(rr: &ResourceRecord, cursor: &mut Cursor<T>) -> io::Result<()>
    where Cursor<T>: Write
{
    match *rr {
        ResourceRecord::OPT { payload_size, extended_rcode, version, dnssec_ok, ref data } => {
            cursor.write_u8(0)?;
            cursor.write_u16::<BigEndian>(Type::OPT.into())?;
            cursor.write_u16::<BigEndian>(payload_size)?;
            cursor.write_u8(extended_rcode)?;
            cursor.write_u8(version)?;
            let flags = if dnssec_ok { 0b1000_0000_0000_0000 } else { 0 };
            cursor.write_u16::<BigEndian>(flags)?;
            cursor.write_u16::<BigEndian>(data.len() as u16)?;
            cursor.write_all(data)
        }
        ResourceRecord::A { ref name, class, ttl, ref addr } => {
            write_data(name, Type::A, class, ttl, &addr.octets(), cursor)
        }
        ResourceRecord::AAAA { ref name, class, ttl, ref addr } => {
            write_data(name, Type::AAAA, class, ttl, &addr.octets(), cursor)
        }
        ResourceRecord::CNAME { ref name, class, ttl, ref cname } => {
            write_name(name, cursor)?;
            cursor.write_u16::<BigEndian>(Type::CNAME.into())?;
            cursor.write_u16::<BigEndian>(class.into())?;
            cursor.write_i32::<BigEndian>(ttl)?;

            let start = cursor.position();
            cursor.write_u16::<BigEndian>(0)?;
            write_name(cname, cursor)?;
            let end = cursor.position();
            cursor.set_position(start);
            cursor.write_u16::<BigEndian>((end - start) as u16)?;
            cursor.set_position(end);
            Ok(())
        }
        ResourceRecord::SOA { ref name,
                              class,
                              ttl,
                              ref mname,
                              ref rname,
                              serial,
                              refresh,
                              retry,
                              expire,
                              minimum } => {
            write_name(name, cursor)?;
            cursor.write_u16::<BigEndian>(Type::SOA.into())?;
            cursor.write_u16::<BigEndian>(class.into())?;
            cursor.write_i32::<BigEndian>(ttl)?;

            let start = cursor.position();
            cursor.write_u16::<BigEndian>(0)?;

            write_name(mname, cursor)?;
            write_name(rname, cursor)?;
            cursor.write_u32::<BigEndian>(serial)?;
            cursor.write_u32::<BigEndian>(refresh)?;
            cursor.write_u32::<BigEndian>(retry)?;
            cursor.write_u32::<BigEndian>(expire)?;
            cursor.write_u32::<BigEndian>(minimum)?;

            let end = cursor.position();
            cursor.set_position(start);
            cursor.write_u16::<BigEndian>((end - start) as u16)?;
            cursor.set_position(end);
            Ok(())
        }
        ResourceRecord::PTR { ref name, class, ttl, .. } => {
            write_data(name, Type::PTR, class, ttl, &[], cursor)
        }
        ResourceRecord::MX { ref name, class, ttl, preference, ref exchange } => {
            write_name(name, cursor)?;
            cursor.write_u16::<BigEndian>(Type::MX.into())?;
            cursor.write_u16::<BigEndian>(class.into())?;
            cursor.write_i32::<BigEndian>(ttl)?;

            let start = cursor.position();
            cursor.write_u16::<BigEndian>(0)?;

            cursor.write_u16::<BigEndian>(preference)?;
            write_name(exchange, cursor)?;

            let end = cursor.position();
            cursor.set_position(start);
            cursor.write_u16::<BigEndian>((end - start) as u16)?;
            cursor.set_position(end);
            Ok(())
        }
        ResourceRecord::NS { ref name, class, ttl, ref ns_name } => {
            write_name(name, cursor)?;
            cursor.write_u16::<BigEndian>(Type::NS.into())?;
            cursor.write_u16::<BigEndian>(class.into())?;
            cursor.write_i32::<BigEndian>(ttl)?;

            let start = cursor.position();
            cursor.write_u16::<BigEndian>(0)?;

            write_name(ns_name, cursor)?;

            let end = cursor.position();
            cursor.set_position(start);
            cursor.write_u16::<BigEndian>((end - start) as u16)?;
            cursor.set_position(end);
            Ok(())
        }
        ResourceRecord::TXT { ref name, class, ttl, .. } => {
            write_data(name, Type::TXT, class, ttl, &[], cursor)
        }
        ResourceRecord::Unknown { ref name, rtype, class, ttl, ref data } => {
            write_data(name, rtype, class, ttl, data, cursor)
        }
    }
}
