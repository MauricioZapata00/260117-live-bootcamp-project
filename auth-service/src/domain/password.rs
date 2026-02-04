#[derive(Debug, Clone, PartialEq)]
pub struct Password(String);

#[derive(Debug, PartialEq)]
pub enum PasswordParseError {
    EmptyPassword,
    TooShort,
}

impl Password {
    pub fn parse(password: String) -> Result<Self, PasswordParseError> {
        if password.is_empty() {
            return Err(PasswordParseError::EmptyPassword);
        }

        if password.len() < 8 {
            return Err(PasswordParseError::TooShort);
        }

        Ok(Self(password))
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_password() {
        let password = "password123".to_string();
        assert!(Password::parse(password).is_ok());
    }

    #[test]
    fn test_empty_password() {
        let password = "".to_string();
        assert_eq!(Password::parse(password), Err(PasswordParseError::EmptyPassword));
    }

    #[test]
    fn test_password_too_short() {
        let password = "pass".to_string();
        assert_eq!(Password::parse(password), Err(PasswordParseError::TooShort));
    }

    #[test]
    fn test_password_exactly_8_chars() {
        let password = "12345678".to_string();
        assert!(Password::parse(password).is_ok());
    }

    #[test]
    fn test_as_ref() {
        let password = Password::parse("password123".to_string()).unwrap();
        assert_eq!(password.as_ref(), "password123");
    }

    #[test]
    fn test_long_password() {
        let password = "this_is_a_very_long_password_with_many_characters".to_string();
        assert!(Password::parse(password).is_ok());
    }
}
