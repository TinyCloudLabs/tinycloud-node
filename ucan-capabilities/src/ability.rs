use nutype::nutype;
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Error as FmtError, Formatter};

#[nutype(validate(with = is_valid_ability))]
#[derive(*, Display, TryFrom, Into, Borrow, Serialize, Deserialize)]
pub struct Ability(String);

#[nutype(validate(with = is_valid))]
#[derive(*, Display, TryFrom, Into, Borrow, Serialize, Deserialize)]
pub struct AbilityNamespace(String);

#[nutype(validate(with = is_valid))]
#[derive(*, Display, TryFrom, Into, Borrow, Serialize, Deserialize)]
pub struct AbilityName(String);

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, PartialOrd, Ord)]
pub struct AbilityRef<'a>(&'a str);

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, PartialOrd, Ord)]
pub struct AbilityNamespaceRef<'a>(&'a str);

#[derive(Debug, PartialEq, Eq, Hash, Clone, Serialize, Deserialize, PartialOrd, Ord)]
pub struct AbilityNameRef<'a>(&'a str);

impl Ability {
    pub fn from_parts(namespace: AbilityNamespace, name: AbilityName) -> Self {
        // these are already validated, so this is safe
        Self::new([namespace.as_ref(), name.as_ref()].join("/")).unwrap()
    }
    pub fn get_ref(&self) -> AbilityRef {
        AbilityRef(self.as_ref())
    }
    pub fn into_parts(self) -> (AbilityNamespace, AbilityName) {
        let split = self.as_ref().split_once('/').unwrap();
        // these are already validated, so this is safe
        let namespace = AbilityNamespace::new(split.0.to_string()).unwrap();
        let name = AbilityName::new(split.1.to_string()).unwrap();

        (namespace, name)
    }
    pub fn namespace(&self) -> AbilityNamespaceRef {
        AbilityNamespaceRef(self.as_ref().split_once('/').unwrap().0)
    }
    pub fn name(&self) -> AbilityNameRef {
        AbilityNameRef(self.as_ref().split_once('/').unwrap().1)
    }
    pub fn len(&self) -> usize {
        self.as_ref().len()
    }
    pub fn is_empty(&self) -> bool {
        self.as_ref().is_empty()
    }
}

impl<'a> AbilityNamespaceRef<'a> {
    pub fn to_owned(&self) -> AbilityNamespace {
        AbilityNamespace::try_from(self.as_ref()).unwrap()
    }
}

impl<'a> AbilityNameRef<'a> {
    pub fn to_owned(&self) -> AbilityName {
        AbilityName::try_from(self.as_ref()).unwrap()
    }
}

impl<'a> AbilityRef<'a> {
    pub fn to_owned(&self) -> Ability {
        Ability::try_from(self.as_ref()).unwrap()
    }
    pub fn namespace(&self) -> AbilityNamespaceRef {
        AbilityNamespaceRef(self.0.split_once('/').unwrap().0)
    }

    pub fn name(&self) -> AbilityNameRef {
        AbilityNameRef(self.0.split_once('/').unwrap().1)
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'a> Display for AbilityRef<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        write!(f, "{}", &self.0)
    }
}

impl<'a> Display for AbilityNamespaceRef<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        write!(f, "{}", &self.0)
    }
}

impl<'a> Display for AbilityNameRef<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), FmtError> {
        write!(f, "{}", &self.0)
    }
}

impl AsRef<str> for AbilityRef<'_> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl AsRef<str> for AbilityNameRef<'_> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl AsRef<str> for AbilityNamespaceRef<'_> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

const ALLOWED_CHARS: &str = "-_.+*";

fn not_allowed(c: char) -> bool {
    !c.is_alphanumeric() && !ALLOWED_CHARS.contains(c)
}

fn is_valid(s: &str) -> bool {
    !s.is_empty() && !s.contains(not_allowed)
}

fn is_valid_ability(s: &str) -> bool {
    s.split_once('/')
        .map(|(namespace, name)| is_valid(namespace) && is_valid(name))
        .unwrap_or(false)
}

impl<'a> TryFrom<&'a str> for AbilityRef<'a> {
    type Error = <Ability as TryFrom<&'a str>>::Error;
    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        if is_valid_ability(s) {
            Ok(Self(s))
        } else {
            Err(Self::Error::Invalid)
        }
    }
}

impl<'a> TryFrom<&'a str> for AbilityNamespaceRef<'a> {
    type Error = <AbilityNamespace as TryFrom<&'a str>>::Error;
    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        if is_valid(s) {
            Ok(Self(s))
        } else {
            Err(Self::Error::Invalid)
        }
    }
}

impl<'a> TryFrom<&'a str> for AbilityNameRef<'a> {
    type Error = <AbilityName as TryFrom<&'a str>>::Error;
    fn try_from(s: &'a str) -> Result<Self, Self::Error> {
        if is_valid(s) {
            Ok(Self(s))
        } else {
            Err(Self::Error::Invalid)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn invalid_parts() {
        let invalids = [
            "https://example.com/",
            "-my-namespace:",
            "my-namespace-/",
            "my--namespace[]",
            "not a valid namespace",
            "",
        ];
        for s in invalids {
            s.parse::<AbilityNamespace>().unwrap_err();
            s.parse::<AbilityName>().unwrap_err();
        }
    }

    #[test]
    fn valid_parts() {
        let valids = ["my-namespace", "My-nAmespac3-2", "*"];
        for s in valids {
            s.parse::<AbilityNamespace>().unwrap();
            s.parse::<AbilityName>().unwrap();
        }
    }

    #[test]
    fn valid_abilities() {
        for s in [
            "credential/present",
            "kv/list",
            "some-ns/some-name",
            "msg/*",
        ] {
            let ab = s.parse::<Ability>().unwrap();
            let (ns, n) = s.split_once('/').unwrap();
            assert_eq!(ab.namespace().as_ref(), ns);
            assert_eq!(ab.name().as_ref(), n);

            let (namespace, name) = ab.clone().into_parts();
            assert_eq!(namespace.as_ref(), ns);
            assert_eq!(name.as_ref(), n);

            let ability = Ability::from_parts(namespace, name);
            assert_eq!(ability, ab);
            assert_eq!(ability.as_ref(), s);
        }
    }

    #[test]
    fn invalid_abilities() {
        for s in [
            "credential ns/present",
            "kv-list",
            "some:ns/some-name",
            "msg/wrong/str",
            "/",
            "//",
            "over/one/slash",
        ] {
            s.parse::<Ability>().unwrap_err();
        }
    }

    #[test]
    fn ordering() {
        let abilities: Vec<Ability> = [
            "a/b", "a/c", "aa/a", "b/a", "kv*/read", "kv/list", "kv/read", "kva/get",
        ]
        .into_iter()
        .map(|s| s.parse().unwrap())
        .collect();

        let mut sorted = abilities.clone();
        sorted.sort();

        assert_eq!(sorted, abilities);
    }

    #[test]
    fn serde() {
        use serde_json::{from_str, to_string};

        let ab_str = r#""credential/present""#;

        let ability: Ability = from_str(ab_str).unwrap();

        #[derive(Serialize, Deserialize, Debug, PartialEq)]
        struct Wrapper(Ability);

        let wrapped: Wrapper = from_str(ab_str).unwrap();

        assert_eq!(wrapped.0, ability);
        assert_eq!(to_string(&wrapped).unwrap(), ab_str);
    }
}
