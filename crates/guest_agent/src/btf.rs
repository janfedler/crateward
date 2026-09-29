//! Finds member offsets of kernel structures in the kernel's BTF.
//!
//! The eBPF programs read a few fields of kernel structures (ADR 0006). The
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

impl Btf {
    /// Parses raw BTF as the kernel exposes it (little endian).
    ///
    /// # Errors
    ///
    /// Fails on a bad magic, truncated data or an unknown type kind.
    pub fn parse(data: &[u8]) -> Result<Self, BtfError> {
        let magic = data
            .get(..2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_le_bytes);
        if magic != Some(MAGIC) {
            return Err(BtfError::NotBtf);
        }
        let header_len = usize_of(u32_at(data, 4)?);
        let type_off = usize_of(u32_at(data, 8)?);
        let type_len = usize_of(u32_at(data, 12)?);
        let str_off = usize_of(u32_at(data, 16)?);
        let str_len = usize_of(u32_at(data, 20)?);
        let section = |off: usize, len: usize| {
            header_len
                .checked_add(off)
                .and_then(|start| Some((start, start.checked_add(len)?)))
                .and_then(|(start, end)| data.get(start..end))
                .ok_or(BtfError::SectionOutOfBounds)
        };
        let type_data = section(type_off, type_len)?;
        let strings = section(str_off, str_len)?.to_vec();

        // Type ID 0 is `void`.
        let mut types = vec![Type {
            kind: 0,
            name: 0,
            target: 0,
            members: Vec::new(),
        }];
        let mut at = 0;
        while at < type_data.len() {
            let name = u32_at(type_data, at)?;
            let info = u32_at(type_data, at + 4)?;
            let size_or_type = u32_at(type_data, at + 8)?;
            at += 12;
            let vlen = usize_of(info & 0xffff);
            let kind = (info >> 24) & 0x1f;
            let kind_flag = info >> 31 == 1;
            let mut members = Vec::new();
            let extra = match kind {
                KIND_PTR | KIND_FWD | KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT
                | KIND_FUNC | KIND_FLOAT | KIND_TYPE_TAG => 0,
                KIND_INT | KIND_VAR | KIND_DECL_TAG => 4,
                KIND_ARRAY => 12,
                KIND_ENUM | KIND_FUNC_PROTO => vlen * 8,
                KIND_DATASEC | KIND_ENUM64 => vlen * 12,
                KIND_STRUCT | KIND_UNION => {
                    for i in 0..vlen {
                        let base = at + i * 12;
                        let offset = u32_at(type_data, base + 8)?;
                        members.push(Member {
                            name: u32_at(type_data, base)?,
                            ty: u32_at(type_data, base + 4)?,
                            // With `kind_flag`, the top 8 bits hold the
                            // bitfield size.
                            bits: if kind_flag {
                                offset & 0x00ff_ffff
                            } else {
                                offset
                            },
                        });
                    }
                    vlen * 12
                }
                other => return Err(BtfError::UnknownKind(other)),
            };
            at += extra;
            types.push(Type {
                kind,
                name,
                target: size_or_type,
                members,
            });
        }
        if at != type_data.len() {
            return Err(BtfError::RaggedTypes);
        }
        let mut btf = Self {
            types,
            strings,
            structs: HashMap::new(),
        };
        let mut structs = HashMap::new();
        for (id, ty) in btf.types.iter().enumerate() {
            if ty.kind == KIND_STRUCT
                && let Some(name) = btf.name(ty.name)
                && !name.is_empty()
                && let Ok(id) = u32::try_from(id)
            {
                structs.entry(name.to_owned()).or_insert(id);
            }
        }
        btf.structs = structs;
        Ok(btf)
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
        let mut data = Vec::new();
        for v in [
            u32::from(MAGIC) | (1 << 16),
            24,
            0,
            u32::try_from(types.len()).unwrap(),
            u32::try_from(types.len()).unwrap(),
            u32::try_from(strings.len()).unwrap(),
        ] {
            data.extend_from_slice(&v.to_le_bytes());
        }
        data.extend_from_slice(&types);
        data.extend_from_slice(&strings);
        data
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
