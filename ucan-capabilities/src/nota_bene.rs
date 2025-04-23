use serde::{
    de::Deserializer,
    ser::{SerializeSeq, Serializer},
    Deserialize, Serialize,
};
use std::collections::BTreeMap;

/// A collection of UCAN Nota Bene information.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NotaBeneCollection<T>(Vec<BTreeMap<String, T>>);

impl<T> NotaBeneCollection<T> {
    /// Create a new empty set of Nota Bene information.
    pub fn new() -> Self {
        Self::default()
    }
    pub fn into_inner(self) -> Vec<BTreeMap<String, T>> {
        self.0
    }
}

impl<T> Default for NotaBeneCollection<T> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<T> Serialize for NotaBeneCollection<T>
where
    T: Serialize,
{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let seq = if self.0.is_empty() {
            let mut seq = serializer.serialize_seq(Some(1))?;
            // the ucan spec basically says that an empty NotaBeneCollection is not
            // allowed, so if this exists we just serialize an empty map
            seq.serialize_element(&BTreeMap::<String, T>::new())?;
            seq
        } else {
            let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
            for item in &self.0 {
                seq.serialize_element(item)?;
            }
            seq
        };
        seq.end()
    }
}

impl<'de, T> Deserialize<'de> for NotaBeneCollection<T>
where
    T: Deserialize<'de>,
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec: Vec<BTreeMap<String, T>> = Vec::deserialize(deserializer)?;
        if vec.is_empty() {
            // can't have an empty vec here
            Err(serde::de::Error::custom(
                "empty NotaBeneCollection is not allowed",
            ))
        } else if vec.len() == 1 && vec.first().map(|m| m.is_empty()).unwrap_or(false) {
            // if the only entry is an empty map, then we just return an empty vec
            Ok(Self::default())
        } else {
            Ok(Self(vec))
        }
    }
}

impl std::ops::DerefMut for NotaBeneCollection<String> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl std::ops::Deref for NotaBeneCollection<String> {
    type Target = Vec<BTreeMap<String, String>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> AsRef<[BTreeMap<String, T>]> for NotaBeneCollection<T> {
    fn as_ref(&self) -> &[BTreeMap<String, T>] {
        &self.0
    }
}

impl<T> IntoIterator for NotaBeneCollection<T> {
    type Item = BTreeMap<String, T>;
    type IntoIter = std::vec::IntoIter<BTreeMap<String, T>>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T> Extend<BTreeMap<String, T>> for NotaBeneCollection<T> {
    fn extend<I: IntoIterator<Item = BTreeMap<String, T>>>(&mut self, iter: I) {
        self.0.extend(iter);
    }
}

impl<T1, T2> From<Vec<BTreeMap<String, T1>>> for NotaBeneCollection<T2>
where
    T1: Into<T2>,
{
    fn from(iter: Vec<BTreeMap<String, T1>>) -> Self {
        Self(
            iter.into_iter()
                .map(|nb| nb.into_iter().map(|(s, v)| (s, v.into())).collect())
                .collect(),
        )
    }
}

pub fn try_convert<T1, T2>(
    nb1: NotaBeneCollection<T1>,
) -> Result<NotaBeneCollection<T2>, <T2 as TryFrom<T1>>::Error>
where
    T2: TryFrom<T1>,
{
    Ok(NotaBeneCollection(
        nb1.into_iter()
            .map(|nb| {
                nb.into_iter()
                    .map(|(s, v)| Ok((s, v.try_into()?)))
                    .collect::<Result<BTreeMap<String, T2>, <T2 as TryFrom<T1>>::Error>>()
            })
            .collect::<Result<Vec<BTreeMap<String, T2>>, <T2 as TryFrom<T1>>::Error>>()?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde() {
        let mut nb = NotaBeneCollection::<String>::new();
        assert_eq!(nb.len(), 0);
        assert_eq!(
            serde_json::from_str::<NotaBeneCollection<String>>(r#"[{}]"#).unwrap(),
            nb
        );
        assert_eq!(serde_json::to_string(&nb).unwrap(), r#"[{}]"#);

        nb.push(
            [("foo".to_string(), "bar".to_string())]
                .into_iter()
                .collect(),
        );
        assert_eq!(nb.len(), 1);
        assert_eq!(serde_json::to_string(&nb).unwrap(), r#"[{"foo":"bar"}]"#);
    }
}
