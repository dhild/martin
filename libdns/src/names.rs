use std::str::FromStr;

#[derive(Debug,Hash,PartialEq,PartialOrd,Eq,Ord,Clone)]
struct Name {
    name: String,
}

impl Name {
    fn label(&self) -> &str {
        if let Some(index) = self.name.find('.') {
            let (label, _) = self.name.split_at(index);
            label
        } else {
            self.name.as_ref()
        }
    }

    fn parent(&self) -> Option<Name> {
        if let Some(index) = self.name.find('.') {
            let (_, p) = self.name.split_at(index + 1);
            return Some(Name { name: String::from(p) });
        }
        if self.name.len() > 0 {
            return Some( Name { name: String::from("") });
        }
        None
    }
}

#[derive(Debug,PartialEq)]
enum NameError {
    NameTooLong(usize),
    LabelTooLong(usize)
}

impl FromStr for Name {
    type Err = NameError;
    fn from_str(s: &str) -> Result<Name, NameError> {
        let name = String::from(s);
        if name.len() > 255 {
            return Err(NameError::NameTooLong(name.len()));
        }
        let result = Name { name: name };
        let label_len = result.label().len();
        if label_len > 63 {
            return Err(NameError::LabelTooLong(label_len));
        }
        Ok(result)
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
        assert_eq!(result.err(), Some(NameError::NameTooLong(256)));
    }

    #[test]
    fn long_first_label_is_invalid() {
        let raw_name = String::from_utf8(vec!['A' as u8; 150]).unwrap();
        let result = raw_name.parse::<Name>();
        assert_eq!(result.err(), Some(NameError::LabelTooLong(150)));
    }
}
