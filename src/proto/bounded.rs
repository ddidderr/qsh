//! Allocation limits applied while serde visits untrusted request fields.
//!
//! Validating an ordinary `Vec<String>` after deserialization is too late:
//! thousands of empty strings already consume much more memory than their
//! wire representation. These private wrappers preserve the public request
//! types and postcard layout while checking lengths before allocating.

use std::{fmt, marker::PhantomData};

use serde::{
    de::{self, SeqAccess, Visitor},
    Deserialize, Deserializer,
};

use super::{MAX_ARGS, MAX_ENV, MAX_NAME_BYTES, MAX_VALUE_BYTES};

struct BoundedString<const LIMIT: usize>(String);

impl<'de, const LIMIT: usize> Deserialize<'de> for BoundedString<LIMIT> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct StringVisitor<const LIMIT: usize>;

        impl<const LIMIT: usize> Visitor<'_> for StringVisitor<LIMIT> {
            type Value = BoundedString<LIMIT>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a string of at most {LIMIT} bytes")
            }

            fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
                if value.len() > LIMIT {
                    return Err(E::custom("string exceeds protocol limit"));
                }
                Ok(BoundedString(value.to_owned()))
            }
        }

        // Postcard borrows the string from the frame for this visitor; the
        // owned copy is made only after the byte limit has been checked.
        deserializer.deserialize_str(StringVisitor::<LIMIT>)
    }
}

struct BoundedVec<T, const LIMIT: usize>(Vec<T>);

impl<'de, T: Deserialize<'de>, const LIMIT: usize> Deserialize<'de> for BoundedVec<T, LIMIT> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct VecVisitor<T, const LIMIT: usize>(PhantomData<T>);

        impl<'de, T: Deserialize<'de>, const LIMIT: usize> Visitor<'de> for VecVisitor<T, LIMIT> {
            type Value = BoundedVec<T, LIMIT>;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(formatter, "a sequence of at most {LIMIT} elements")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let capacity = seq.size_hint().unwrap_or(0);
                if capacity > LIMIT {
                    return Err(de::Error::custom("sequence exceeds protocol limit"));
                }
                let mut values = Vec::with_capacity(capacity);
                while let Some(value) = seq.next_element()? {
                    // Enforce the bound even for deserializers that omit or
                    // underestimate their hint. T is itself allocation-bounded.
                    if values.len() == LIMIT {
                        return Err(de::Error::custom("sequence exceeds protocol limit"));
                    }
                    values.push(value);
                }
                Ok(BoundedVec(values))
            }
        }

        deserializer.deserialize_seq(VecVisitor::<T, LIMIT>(PhantomData))
    }
}

pub(super) fn name<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    BoundedString::<MAX_NAME_BYTES>::deserialize(deserializer).map(|value| value.0)
}

pub(super) fn optional_name<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    Option::<BoundedString<MAX_NAME_BYTES>>::deserialize(deserializer)
        .map(|value| value.map(|name| name.0))
}

pub(super) fn command<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<String>>, D::Error> {
    type Arguments = BoundedVec<BoundedString<MAX_VALUE_BYTES>, MAX_ARGS>;
    Option::<Arguments>::deserialize(deserializer)
        .map(|value| value.map(|args| args.0.into_iter().map(|arg| arg.0).collect()))
}

pub(super) fn environment<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<(String, String)>, D::Error> {
    type Entry = (
        BoundedString<MAX_NAME_BYTES>,
        BoundedString<MAX_VALUE_BYTES>,
    );
    BoundedVec::<Entry, MAX_ENV>::deserialize(deserializer).map(|entries| {
        entries
            .0
            .into_iter()
            .map(|(name, value)| (name.0, value.0))
            .collect()
    })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use serde::de::value::{Error, SeqDeserializer};

    use super::*;

    #[test]
    fn oversized_hint_is_rejected_before_visiting_an_element() {
        let visits = Cell::new(0);
        let elements =
            std::iter::repeat_n("", MAX_ARGS + 1).inspect(|_| visits.set(visits.get() + 1));
        let decoder = SeqDeserializer::<_, Error>::new(elements);
        assert!(BoundedVec::<BoundedString<1>, MAX_ARGS>::deserialize(decoder).is_err());
        assert_eq!(visits.get(), 0);
    }

    #[test]
    fn absent_hint_does_not_disable_the_count_limit() {
        let elements = std::iter::repeat_n("", MAX_ARGS + 1).filter(|_| true);
        let decoder = SeqDeserializer::<_, Error>::new(elements);
        assert!(BoundedVec::<BoundedString<1>, MAX_ARGS>::deserialize(decoder).is_err());
    }
}
