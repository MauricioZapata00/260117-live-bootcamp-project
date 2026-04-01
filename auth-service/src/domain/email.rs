use std::hash::Hash;
use color_eyre::eyre::{eyre, Result};
use secrecy::{ExposeSecret, SecretString};
use validator::ValidateEmail;

#[derive(Debug, Clone)]
pub struct Email(SecretString);

impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl Eq for Email {}

impl Hash for Email {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.expose_secret().hash(state);
    }
}

impl Email {
    pub fn parse(s: SecretString) -> Result<Self> {
        if s.expose_secret().validate_email() {
            Ok(Self(s))
        } else {
            Err(eyre!(
                "{} is not a valid email.",
                s.expose_secret()
            ))
        }
    }
}

impl AsRef<SecretString> for Email {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fake::faker::internet::en::SafeEmail;
    use quickcheck::Gen;

    #[test]
    fn empty_string_is_rejected() {
        let email = SecretString::new("".to_owned().into_boxed_str());
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn email_missing_at_symbol_is_rejected() {
        let email = SecretString::new("ursuladomain.com".to_owned().into_boxed_str());
        assert!(Email::parse(email).is_err());
    }

    #[test]
    fn email_missing_subject_is_rejected() {
        let email = SecretString::new("@domain.com".to_owned().into_boxed_str());
        assert!(Email::parse(email).is_err());
    }

    #[derive(Debug, Clone)]
    struct ValidEmailFixture(pub String);

    impl quickcheck::Arbitrary for ValidEmailFixture {
        fn arbitrary(_g: &mut Gen) -> Self {
            use fake::Fake;
            let email: String = SafeEmail().fake();
            Self(email)
        }
    }

    #[quickcheck_macros::quickcheck]
    fn valid_emails_are_parsed_successfully(valid_email: ValidEmailFixture) -> bool {
        Email::parse(SecretString::new(valid_email.0.into_boxed_str())).is_ok()
    }
}
