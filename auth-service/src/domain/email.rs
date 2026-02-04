use validator::ValidateEmail;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Email(String);

#[derive(Debug, PartialEq)]
pub enum EmailParseError {
    EmptyEmail,
    InvalidFormat,
}

impl Email {
    pub fn parse(email: String) -> Result<Self, EmailParseError> {
        if email.is_empty() {
            return Err(EmailParseError::EmptyEmail);
        }

        if !email.validate_email() {
            return Err(EmailParseError::InvalidFormat);
        }

        Ok(Self(email))
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_email() {
        let email = "test@example.com".to_string();
        assert!(Email::parse(email).is_ok());
    }

    #[test]
    fn test_empty_email() {
        let email = "".to_string();
        assert_eq!(Email::parse(email), Err(EmailParseError::EmptyEmail));
    }

    #[test]
    fn test_email_missing_at_symbol() {
        let email = "testexample.com".to_string();
        assert_eq!(Email::parse(email), Err(EmailParseError::InvalidFormat));
    }

    #[test]
    fn test_email_missing_domain() {
        let email = "test@".to_string();
        assert_eq!(Email::parse(email), Err(EmailParseError::InvalidFormat));
    }

    #[test]
    fn test_email_missing_username() {
        let email = "@example.com".to_string();
        assert_eq!(Email::parse(email), Err(EmailParseError::InvalidFormat));
    }

    #[test]
    fn test_as_ref() {
        let email = Email::parse("test@example.com".to_string()).unwrap();
        assert_eq!(email.as_ref(), "test@example.com");
    }

    #[test]
    fn test_email_with_plus() {
        let email = "test+tag@example.com".to_string();
        assert!(Email::parse(email).is_ok());
    }

    #[test]
    fn test_email_with_subdomain() {
        let email = "test@mail.example.com".to_string();
        assert!(Email::parse(email).is_ok());
    }
}
