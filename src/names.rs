use std::fmt;
use std::str::FromStr;

#[derive(Debug,Hash,PartialEq,PartialOrd,Eq,Ord,Clone)]
pub struct Name {
    name: String,
}

fn first_label(name: &str) -> &str {
    match name.find(".") {
        Some(index) => &name[..index],
        None => name,
    }
}

impl Name {
    fn label(&self) -> &str {
        first_label(&self.name)
    }

    fn parent(&self) -> Option<Name> {
        match self.name.find(".") {
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

#[derive(Debug,PartialEq)]
pub enum NameError {
    NameTooLong(usize, String),
    LabelTooLong(usize, String),
    EmptyNonRootLabel,
}

impl FromStr for Name {
    type Err = NameError;
    fn from_str(s: &str) -> Result<Name, NameError> {
        let name = String::from(s);
        if name.len() > 255 {
            return Err(NameError::NameTooLong(name.len(), name));
        }

        if name.len() > 0 {
            let mut name_part = s;
            loop {
                let label = first_label(&name_part);
                if label.len() > 63 {
                    return Err(NameError::LabelTooLong(label.len(), String::from(label)));
                }
                if label.len() == 0 {
                    return Err(NameError::EmptyNonRootLabel);
                }
                if label.len() == name_part.len() {
                    // Non-empty last element
                    break;
                }
                name_part = &name_part[(label.len() + 1)..];
            }
        }
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
    use super::{Name, NameError};

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

    #[test]
    fn long_name_is_invalid() {
        let raw_name = String::from_utf8(vec!['A' as u8; 256]).unwrap();
        let result = raw_name.parse::<Name>();
        assert_eq!(result.err(), Some(NameError::NameTooLong(256, raw_name)));
    }

    #[test]
    fn long_first_label_is_invalid() {
        let raw_name = String::from_utf8(vec!['A' as u8; 150]).unwrap();
        let result = raw_name.parse::<Name>();
        assert_eq!(result.err(), Some(NameError::LabelTooLong(150, raw_name)));
    }
}
