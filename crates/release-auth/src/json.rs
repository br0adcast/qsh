//! Reject duplicate decoded member names and excessive nesting before typed decoding.
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use std::{collections::BTreeSet, fmt};

struct Bounded {
    depth: usize,
}
impl<'de> DeserializeSeed<'de> for Bounded {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}
impl<'de> Visitor<'de> for Bounded {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("bounded JSON without duplicate members")
    }
    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E: de::Error>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E: de::Error>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E: de::Error>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E: de::Error>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<(), A::Error> {
        if self.depth >= 32 {
            return Err(de::Error::custom("JSON depth limit"));
        }
        while a
            .next_element_seed(Bounded {
                depth: self.depth + 1,
            })?
            .is_some()
        {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<(), A::Error> {
        if self.depth >= 32 {
            return Err(de::Error::custom("JSON depth limit"));
        }
        let mut names = BTreeSet::new();
        while let Some(name) = a.next_key::<String>()? {
            if !names.insert(name) {
                return Err(de::Error::custom("duplicate JSON member"));
            }
            a.next_value_seed(Bounded {
                depth: self.depth + 1,
            })?;
        }
        Ok(())
    }
}
pub(crate) fn parse(bytes: &[u8]) -> Result<serde_json::Value, &'static str> {
    let mut d = serde_json::Deserializer::from_slice(bytes);
    Bounded { depth: 0 }
        .deserialize(&mut d)
        .map_err(|_| "invalid bounded JSON")?;
    d.end().map_err(|_| "trailing JSON data")?;
    serde_json::from_slice(bytes).map_err(|_| "invalid JSON")
}
