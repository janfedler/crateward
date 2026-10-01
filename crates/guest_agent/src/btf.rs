//! Finds member offsets of kernel structures in the kernel's BTF.
//!
//! The eBPF programs read a few fields of kernel structures (ADR 0007). The
//! agent looks their offsets up in `/sys/kernel/btf/vmlinux` at load time,
//! so the programs follow the running kernel. Only the parts of the format
//! needed for that are decoded: type records are walked to know where each
//! one ends, and struct and union members are read. Layout per the kernel's
//! `Documentation/bpf/btf.rst` and `include/uapi/linux/btf.h`.

use std::collections::HashMap;
use std::io;

const MAGIC: u16 = 0xeb9f;

/// Where the kernel exposes its BTF.
const KERNEL_BTF: &str = "/sys/kernel/btf/vmlinux";

const KIND_INT: u32 = 1;
const KIND_PTR: u32 = 2;
const KIND_ARRAY: u32 = 3;
const KIND_STRUCT: u32 = 4;
const KIND_UNION: u32 = 5;
const KIND_ENUM: u32 = 6;
const KIND_FWD: u32 = 7;
const KIND_TYPEDEF: u32 = 8;
const KIND_VOLATILE: u32 = 9;
const KIND_CONST: u32 = 10;
const KIND_RESTRICT: u32 = 11;
const KIND_FUNC: u32 = 12;
const KIND_FUNC_PROTO: u32 = 13;
const KIND_VAR: u32 = 14;
const KIND_DATASEC: u32 = 15;
const KIND_FLOAT: u32 = 16;
const KIND_DECL_TAG: u32 = 17;
const KIND_TYPE_TAG: u32 = 18;
const KIND_ENUM64: u32 = 19;

/// Nesting limit when following anonymous members and type modifiers.
const MAX_DEPTH: usize = 16;

#[derive(Debug, Clone, Copy)]
struct Member {
    name: u32,
    ty: u32,
    /// Offset in bits from the start of the enclosing type.
    bits: u32,
}

#[derive(Debug, Clone)]
struct Type {
    kind: u32,
    name: u32,
    /// The referenced type, for modifiers and typedefs.
    target: u32,
    members: Vec<Member>,
}

/// Why the kernel's BTF could not be used.
#[derive(Debug, thiserror::Error)]
pub enum BtfError {
    /// The kernel's BTF file cannot be read.
    #[error("{}: {}", KERNEL_BTF, .0)]
    Read(io::Error),
    /// The data does not start with the magic of little endian BTF.
    #[error("not little endian BTF")]
    NotBtf,
    /// The data ends before a field does, at this byte.
    #[error("BTF ends at byte {0}")]
    Truncated(usize),
    /// A section lies outside the data.
    #[error("BTF section out of bounds")]
    SectionOutOfBounds,
    /// A type record has a kind this decoder does not know.
    #[error("unknown BTF kind {0}")]
    UnknownKind(u32),
    /// The type section ends inside a type record.
    #[error("BTF type section ends inside a type")]
    RaggedTypes,
    /// The kernel has no struct of this name.
    #[error("no struct {0} in the kernel BTF")]
    NoStruct(String),
    /// The struct (first) has no member of this name (second).
    #[error("no member {1} in struct {0}")]
    NoMember(String, String),
    /// The member (second) of the struct (first) is a bitfield that does
    /// not start on a byte.
    #[error("{0}.{1} is not byte aligned")]
    Unaligned(String, String),
}

/// Parsed BTF: types by ID and the string table.
#[derive(Debug)]
pub struct Btf {
    types: Vec<Type>,
    strings: Vec<u8>,
    structs: HashMap<String, u32>,
}

fn u32_at(data: &[u8], at: usize) -> Result<u32, BtfError> {
    data.get(at..at + 4)
        .and_then(|b| b.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or(BtfError::Truncated(at))
}

fn usize_of(value: u32) -> usize {
    usize::try_from(value).unwrap_or(usize::MAX)
}

/// The type section and the string section, checked against the data.
fn sections(data: &[u8]) -> Result<(&[u8], &[u8]), BtfError> {
    if !data.starts_with(&MAGIC.to_le_bytes()) {
        return Err(BtfError::NotBtf);
    }
    let header_len = usize_of(u32_at(data, 4)?);
    let (type_off, type_len) = (usize_of(u32_at(data, 8)?), usize_of(u32_at(data, 12)?));
    let (str_off, str_len) = (usize_of(u32_at(data, 16)?), usize_of(u32_at(data, 20)?));
    let section = |off: usize, len: usize| -> Option<&[u8]> {
        let start = header_len.checked_add(off)?;
        data.get(start..start.checked_add(len)?)
    };
    let types = section(type_off, type_len).ok_or(BtfError::SectionOutOfBounds)?;
    let strings = section(str_off, str_len).ok_or(BtfError::SectionOutOfBounds)?;
    Ok((types, strings))
}

/// Every type record of the section. ID 0 is `void`, the first record is 1.
fn read_types(data: &[u8]) -> Result<Vec<Type>, BtfError> {
    let void = Type {
        kind: 0,
        name: 0,
        target: 0,
        members: Vec::new(),
    };
    let mut types = vec![void];
    let mut at = 0;
    while at < data.len() {
        let (ty, next) = read_type(data, at)?;
        types.push(ty);
        at = next;
    }
    if at != data.len() {
        return Err(BtfError::RaggedTypes);
    }
    Ok(types)
}

/// The record at `at` and the offset of the next one.
fn read_type(data: &[u8], at: usize) -> Result<(Type, usize), BtfError> {
    let name = u32_at(data, at)?;
    let info = u32_at(data, at + 4)?;
    let target = u32_at(data, at + 8)?;
    let at = at + 12;
    let count = usize_of(info & 0xffff);
    let kind = (info >> 24) & 0x1f;
    let extra = extra_len(kind, count)?;
    let mut members = Vec::new();
    if matches!(kind, KIND_STRUCT | KIND_UNION) {
        let kind_flag = info >> 31 == 1;
        for i in 0..count {
            members.push(read_member(data, at + i * 12, kind_flag)?);
        }
    }
    let ty = Type {
        kind,
        name,
        target,
        members,
    };
    Ok((ty, at + extra))
}

/// The bytes a record of this kind has after its 12 byte head; `count` is
/// the member or value count of the info word.
fn extra_len(kind: u32, count: usize) -> Result<usize, BtfError> {
    Ok(match kind {
        KIND_PTR | KIND_FWD | KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT
        | KIND_FUNC | KIND_FLOAT | KIND_TYPE_TAG => 0,
        KIND_INT | KIND_VAR | KIND_DECL_TAG => 4,
        KIND_ARRAY => 12,
        KIND_ENUM | KIND_FUNC_PROTO => count * 8,
        KIND_DATASEC | KIND_ENUM64 | KIND_STRUCT | KIND_UNION => count * 12,
        other => return Err(BtfError::UnknownKind(other)),
    })
}

fn read_member(data: &[u8], at: usize, kind_flag: bool) -> Result<Member, BtfError> {
    let offset = u32_at(data, at + 8)?;
    Ok(Member {
        name: u32_at(data, at)?,
        ty: u32_at(data, at + 4)?,
        // With `kind_flag`, the top 8 bits hold the bitfield size.
        bits: if kind_flag {
            offset & 0x00ff_ffff
        } else {
            offset
        },
    })
}

impl Btf {
    /// Parses raw BTF as the kernel exposes it (little endian).
    ///
    /// # Errors
    ///
    /// Fails on a bad magic, truncated data or an unknown type kind.
    pub fn parse(data: &[u8]) -> Result<Self, BtfError> {
        let (type_data, strings) = sections(data)?;
        let mut btf = Self {
            types: read_types(type_data)?,
            strings: strings.to_vec(),
            structs: HashMap::new(),
        };
        btf.structs = btf.struct_index();
        Ok(btf)
    }

    /// The ID of the first struct of each name. Unions and structs without a
    /// name are left out.
    fn struct_index(&self) -> HashMap<String, u32> {
        let mut structs = HashMap::new();
        for (id, ty) in self.types.iter().enumerate() {
            if ty.kind == KIND_STRUCT
                && let Some(name) = self.name(ty.name)
                && !name.is_empty()
                && let Ok(id) = u32::try_from(id)
            {
                structs.entry(name.to_owned()).or_insert(id);
            }
        }
        structs
    }

    /// Reads and parses the running kernel's BTF.
    ///
    /// # Errors
    ///
    /// Fails if the file cannot be read or parsed.
    pub fn from_kernel() -> Result<Self, BtfError> {
        Self::parse(&std::fs::read(KERNEL_BTF).map_err(BtfError::Read)?)
    }

    fn name(&self, offset: u32) -> Option<&str> {
        let rest = self.strings.get(usize_of(offset)..)?;
        let end = rest.iter().position(|&b| b == 0)?;
        std::str::from_utf8(rest.get(..end)?).ok()
    }

    fn get(&self, id: u32) -> Option<&Type> {
        self.types.get(usize_of(id))
    }

    /// Follows typedefs and modifiers to the underlying type.
    fn resolve(&self, mut id: u32) -> Option<&Type> {
        for _ in 0..MAX_DEPTH {
            let ty = self.get(id)?;
            match ty.kind {
                KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_TYPE_TAG => {
                    id = ty.target;
                }
                _ => return Some(ty),
            }
        }
        None
    }

    /// Bit offset of `member` in `ty`, looking inside anonymous struct and
    /// union members.
    fn find(&self, ty: &Type, member: &str, depth: usize) -> Option<u32> {
        if depth > MAX_DEPTH {
            return None;
        }
        for m in &ty.members {
            match self.name(m.name) {
                Some(name) if name == member => return Some(m.bits),
                Some("") => {
                    let inner = self.resolve(m.ty)?;
                    if matches!(inner.kind, KIND_STRUCT | KIND_UNION)
                        && let Some(bits) = self.find(inner, member, depth + 1)
                    {
                        return m.bits.checked_add(bits);
                    }
                }
                _ => {}
            }
        }
        None
    }

    /// Byte offset of `member` in `struct name`.
    ///
    /// # Errors
    ///
    /// Fails if the struct or member does not exist or the member is a
    /// bitfield that does not start on a byte.
    pub fn offset(&self, name: &str, member: &str) -> Result<u32, BtfError> {
        let ty = self
            .structs
            .get(name)
            .and_then(|&id| self.get(id))
            .ok_or_else(|| BtfError::NoStruct(name.into()))?;
        let bits = self
            .find(ty, member, 0)
            .ok_or_else(|| BtfError::NoMember(name.into(), member.into()))?;
        if bits % 8 == 0 {
            Ok(bits / 8)
        } else {
            Err(BtfError::Unaligned(name.into(), member.into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(values: &[u32]) -> Vec<u8> {
        values.iter().flat_map(|v| v.to_le_bytes()).collect()
    }

    /// Wraps type records and strings into BTF with a 24 byte header.
    fn blob(types: &[u8], strings: &[u8]) -> Vec<u8> {
        let len = |bytes: &[u8]| u32::try_from(bytes.len()).unwrap();
        let header = [
            u32::from(MAGIC) | (1 << 16),
            24,
            0,
            len(types),
            len(types),
            len(strings),
        ];
        let mut data = words(&header);
        data.extend_from_slice(types);
        data.extend_from_slice(strings);
        data
    }

    /// Type records, each given as its words, as bytes.
    fn records(list: &[&[u32]]) -> Vec<u8> {
        words(&list.concat())
    }

    /// One type record with an empty name and a zero size or target.
    fn record(info: u32, extra: &[u32]) -> Vec<u32> {
        [&[0, info, 0][..], extra].concat()
    }

    /// Builds BTF with an anonymous struct inside a named one:
    ///
    /// ```c
    /// struct outer { int a; struct { int pad; long b; }; int c : 4; };
    /// ```
    fn sample() -> Vec<u8> {
        let strings = b"\0int\0long\0outer\0a\0pad\0b\0c\0".to_vec();
        let (int, long, outer, a, pad, b, c) = (1_u32, 5, 10, 16, 18, 22, 24);
        let mut types = Vec::new();
        let mut push = |values: &[u32]| {
            for v in values {
                types.extend_from_slice(&v.to_le_bytes());
            }
        };
        // 1: int
        push(&[int, KIND_INT << 24, 4, 32]);
        // 2: long
        push(&[long, KIND_INT << 24, 8, 64]);
        // 3: anonymous struct { int pad; long b; }
        push(&[0, (KIND_STRUCT << 24) | 2, 16]);
        push(&[pad, 1, 0, b, 2, 64]);
        // 4: const of 3, to check that modifiers are followed
        push(&[0, KIND_CONST << 24, 3]);
        // 5: struct outer, with a bitfield (kind_flag set)
        push(&[outer, (1 << 31) | (KIND_STRUCT << 24) | 3, 32]);
        push(&[a, 1, 0, 0, 4, 64, c, 1, (4 << 24) | 196]);
        blob(&types, &strings)
    }

    #[test]
    fn finds_members_inside_anonymous_structs() {
        let btf = Btf::parse(&sample()).unwrap();
        assert_eq!(btf.offset("outer", "a").unwrap(), 0);
        assert_eq!(btf.offset("outer", "pad").unwrap(), 8);
        assert_eq!(btf.offset("outer", "b").unwrap(), 16);
        assert!(matches!(
            btf.offset("outer", "c"),
            Err(BtfError::Unaligned(..))
        ));
        assert!(matches!(
            btf.offset("outer", "missing"),
            Err(BtfError::NoMember(..))
        ));
        assert!(matches!(
            btf.offset("inner", "a"),
            Err(BtfError::NoStruct(_))
        ));
    }

    #[test]
    fn rejects_truncated_or_foreign_data() {
        let data = sample();
        assert!(matches!(
            Btf::parse(&data[..data.len() - 30]),
            Err(BtfError::SectionOutOfBounds)
        ));
        assert!(matches!(Btf::parse(&data[1..]), Err(BtfError::NotBtf)));
        assert!(matches!(Btf::parse(&[]), Err(BtfError::NotBtf)));
        assert!(matches!(
            Btf::parse(&MAGIC.to_le_bytes()),
            Err(BtfError::Truncated(4))
        ));
    }

    #[test]
    fn rejects_a_type_of_an_unknown_kind() {
        let mut data = sample();
        // The kind is in the top byte of the info word of the first type.
        data[24 + 7] = 0x1f;
        assert!(matches!(
            Btf::parse(&data),
            Err(BtfError::UnknownKind(0x1f))
        ));
    }

    #[test]
    fn every_kind_has_its_own_record_size() {
        // (kind, member or value count, words after the 12 byte record head)
        let kinds = [
            (KIND_INT, 0, 1),
            (KIND_PTR, 0, 0),
            (KIND_ARRAY, 0, 3),
            (KIND_STRUCT, 1, 3),
            (KIND_UNION, 1, 3),
            (KIND_ENUM, 2, 4),
            (KIND_FWD, 0, 0),
            (KIND_TYPEDEF, 0, 0),
            (KIND_VOLATILE, 0, 0),
            (KIND_CONST, 0, 0),
            (KIND_RESTRICT, 0, 0),
            (KIND_FUNC, 0, 0),
            (KIND_FUNC_PROTO, 2, 4),
            (KIND_VAR, 0, 1),
            (KIND_DATASEC, 2, 6),
            (KIND_FLOAT, 0, 0),
            (KIND_DECL_TAG, 0, 1),
            (KIND_TYPE_TAG, 0, 0),
            (KIND_ENUM64, 2, 6),
        ];
        let mut types = Vec::new();
        for (kind, count, extra) in kinds {
            types.extend(record((kind << 24) | count, &vec![0; extra]));
        }
        // struct after { int x; }, found only if every record before it
        // ended where the decoder thinks it does.
        types.extend([1, (KIND_STRUCT << 24) | 1, 8, 7, 1, 32]);
        let btf = Btf::parse(&blob(&words(&types), b"\0after\0x\0")).unwrap();
        let seen: Vec<u32> = btf.types.iter().map(|t| t.kind).collect();
        let mut expected = vec![0];
        expected.extend(1..=19);
        expected.push(KIND_STRUCT);
        assert_eq!(seen, expected);
        assert_eq!(btf.structs["after"], 20);
        assert_eq!(btf.offset("after", "x").unwrap(), 4);
    }

    #[test]
    fn a_type_cut_off_inside_a_record_is_an_error() {
        let strings = b"\0";
        // An int without its extra word: the section ends inside the type.
        let int = words(&record(KIND_INT << 24, &[]));
        assert!(matches!(
            Btf::parse(&blob(&int, strings)),
            Err(BtfError::RaggedTypes)
        ));
        // A record head that stops after the info word.
        let head = words(&[0, KIND_PTR << 24]);
        assert!(matches!(
            Btf::parse(&blob(&head, strings)),
            Err(BtfError::Truncated(8))
        ));
        // A struct that has two members according to its info word, and one.
        let cut = words(&[0, (KIND_STRUCT << 24) | 2, 8, 0, 1, 0]);
        assert!(matches!(
            Btf::parse(&blob(&cut, strings)),
            Err(BtfError::Truncated(32))
        ));
    }

    #[test]
    fn a_cut_header_reports_where_it_ends() {
        let data = sample();
        for len in [4, 8, 12, 16, 20] {
            assert!(
                matches!(Btf::parse(&data[..len]), Err(BtfError::Truncated(at)) if at == len),
                "{len}"
            );
        }
    }

    #[test]
    fn the_sections_are_checked_before_the_types() {
        let mut data = sample();
        data[24 + 7] = 0x1f;
        data.truncate(data.len() - 10);
        assert!(matches!(
            Btf::parse(&data),
            Err(BtfError::SectionOutOfBounds)
        ));
    }

    #[test]
    fn sections_start_after_the_header_length() {
        let mut data = sample();
        data[4..8].copy_from_slice(&32_u32.to_le_bytes());
        data.splice(24..24, [0xaa; 8]);
        let btf = Btf::parse(&data).unwrap();
        assert_eq!(btf.offset("outer", "b").unwrap(), 16);
    }

    #[test]
    fn a_struct_name_maps_to_its_first_struct() {
        // int 1, dup 5, x 9, y 11, z 13, un 15, u 18
        let strings = b"\0int\0dup\0x\0y\0z\0un\0u\0";
        let types = records(&[
            // 1: int
            &[1, KIND_INT << 24, 4, 32],
            // 2 and 3: struct dup, with x or y
            &[5, (KIND_STRUCT << 24) | 1, 4, 9, 1, 8],
            &[5, (KIND_STRUCT << 24) | 1, 4, 11, 1, 16],
            // 4: struct without a name
            &[0, (KIND_STRUCT << 24) | 1, 4, 13, 1, 0],
            // 5: struct whose name lies outside the strings
            &[999, (KIND_STRUCT << 24) | 1, 4, 13, 1, 0],
            // 6: union un, which is not a struct
            &[15, (KIND_UNION << 24) | 1, 4, 18, 1, 0],
        ]);
        let btf = Btf::parse(&blob(&types, strings)).unwrap();
        assert_eq!(btf.structs.len(), 1);
        assert_eq!(btf.structs["dup"], 2);
        assert_eq!(btf.offset("dup", "x").unwrap(), 1);
        assert!(matches!(
            btf.offset("dup", "y"),
            Err(BtfError::NoMember(..))
        ));
        assert!(matches!(btf.offset("", "z"), Err(BtfError::NoStruct(_))));
        assert!(matches!(btf.offset("un", "u"), Err(BtfError::NoStruct(_))));
    }

    #[test]
    fn the_kind_flag_decides_whether_the_top_bits_are_a_bitfield_size() {
        // int 1, plain 5, flagged 11, m 19
        let strings = b"\0int\0plain\0flagged\0m\0";
        let types = records(&[
            &[1, KIND_INT << 24, 4, 32],
            // 2: no kind_flag, so all 32 bits are the offset
            &[5, (KIND_STRUCT << 24) | 1, 4, 19, 1, (1 << 24) | 8],
            // 3: kind_flag, so the top 8 bits are the bitfield size
            &[
                11,
                (1 << 31) | (KIND_STRUCT << 24) | 1,
                4,
                19,
                1,
                (3 << 24) | 40,
            ],
        ]);
        let btf = Btf::parse(&blob(&types, strings)).unwrap();
        assert_eq!(btf.offset("plain", "m").unwrap(), 2_097_153);
        assert_eq!(btf.offset("flagged", "m").unwrap(), 5);
    }

    #[test]
    fn finds_members_inside_anonymous_unions() {
        // int 1, holder 5, pad 12, a 16, b 18
        let strings = b"\0int\0holder\0pad\0a\0b\0";
        let types = records(&[
            &[1, KIND_INT << 24, 4, 32],
            // 2: union { int a; int b; }
            &[0, (KIND_UNION << 24) | 2, 4, 16, 1, 0, 18, 1, 0],
            // 3: struct holder { int pad; <the union>; }
            &[5, (KIND_STRUCT << 24) | 2, 8, 12, 1, 0, 0, 2, 32],
        ]);
        let btf = Btf::parse(&blob(&types, strings)).unwrap();
        assert_eq!(btf.offset("holder", "pad").unwrap(), 0);
        assert_eq!(btf.offset("holder", "a").unwrap(), 4);
        assert_eq!(btf.offset("holder", "b").unwrap(), 4);
    }

    #[test]
    fn unused_bits_of_the_info_word_are_ignored() {
        // Bits 29 and 30 sit next to the kind, bits 16 to 23 next to the count.
        let junk = (3 << 29) | (0x7f << 16);
        let types = records(&[&[1, junk | (KIND_STRUCT << 24) | 1, 4, 3, 1, 8]]);
        let btf = Btf::parse(&blob(&types, b"\0s\0m\0")).unwrap();
        assert_eq!(btf.types[1].kind, KIND_STRUCT);
        assert_eq!(btf.offset("s", "m").unwrap(), 1);
    }

    /// The host kernel's BTF, when readable, has every member the eBPF
    /// programs use.
    #[test]
    fn host_kernel_has_the_traced_members() {
        let Ok(btf) = Btf::from_kernel() else {
            eprintln!("skipping: no readable kernel BTF on this host");
            return;
        };
        for (name, member) in crate::trace::OFFSETS.iter().map(|o| (o.1, o.2)) {
            btf.offset(name, member).unwrap();
        }
        assert_eq!(btf.offset("sockaddr", "sa_family").unwrap(), 0);
    }
}
