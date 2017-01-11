//! Types and utilities for working with DNS names.

use std::error::Error;
use std::fmt;
use std::str::FromStr;

/// Representation of a domain name
///
/// Domain names consist of one or more labels, broken up by the character '.'.
#[derive(Debug,Hash,PartialEq,PartialOrd,Eq,Ord,Clone)]
pub struct Name {
    name: String,
}

fn first_label(name: &str) -> &str {
    match name.find('.') {
        Some(index) => &name[..index],
        None => name,
    }
}

impl Name {
    fn label(&self) -> &str {
        first_label(&self.name)
    }

    fn parent(&self) -> Option<Name> {
        match self.name.find('.') {
            Some(index) => Some(Name { name: String::from(&self.name[(index + 1)..]) }),
            None => {
                match self.name.len() {
                    0 => None,
                    _ => Some(Name { name: String::from("") }),
                }
            }
        }
    }
}

/// An error returned when parsing a domain name
#[derive(Debug,PartialEq,Clone,Copy)]
pub struct NameParseError(());

impl fmt::Display for NameParseError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(self.description())
    }
}

impl Error for NameParseError {
    fn description(&self) -> &str {
        "invalid domain name syntax"
    }
}


impl FromStr for Name {
    type Err = NameParseError;
    fn from_str(s: &str) -> Result<Name, NameParseError> {
        let name = String::from(s);
        Ok(Name { name: name })
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}.", self.name)
    }
}

#[cfg(test)]
mod tests {
    use super::Name;

    #[test]
    fn root_label_is_valid() {
        let name = "".parse::<Name>().unwrap();
        assert_eq!("", name.label());
    }

    #[test]
    fn root_parent_is_none() {
        let name = "".parse::<Name>().unwrap();
        assert_eq!(None, name.parent());
    }

    #[test]
    fn simple_label_is_valid() {
        let name = "raspberry".parse::<Name>().unwrap();
        assert_eq!("raspberry", name.label());
    }

    #[test]
    fn simple_parent_is_root() {
        let name = "raspberry".parse::<Name>().unwrap();
        let parent = name.parent().unwrap();
        assert_eq!("", parent.label());
    }

    #[test]
    fn multi_label_is_valid() {
        let name = "test.example.com".parse::<Name>().unwrap();
        assert_eq!("test", name.label());
    }

    #[test]
    fn multi_parent_is_valid() {
        let name = "test.example.com".parse::<Name>().unwrap();
        let parent1 = name.parent().unwrap();
        assert_eq!("example", parent1.label());
        let parent2 = parent1.parent().unwrap();
        assert_eq!("com", parent2.label());
        let parent3 = parent2.parent().unwrap();
        assert_eq!("", parent3.label());
    }
}
