use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version,
};
use color_eyre::eyre::{eyre, Context, Result};
use secrecy::{ExposeSecret, SecretString};

#[derive(Debug, Clone)]
pub struct HashedPassword(SecretString);

impl PartialEq for HashedPassword {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl HashedPassword {
    #[tracing::instrument(name = "HashedPassword Parse", skip_all)]
    pub async fn parse(s: SecretString) -> Result<Self> {
        if validate_password(&s) {
            let result = compute_password_hash(&s).await?;
            Ok(Self(result))
        } else {
            Err(eyre!("Failed to parse string to a HashedPassword type"))
        }
    }

    #[tracing::instrument(name = "HashedPassword Parse password hash", skip_all)]
    pub fn parse_password_hash(hash: SecretString) -> Result<HashedPassword> {
        if let Ok(hashed_string) = PasswordHash::new(hash.expose_secret().as_ref()) {
            Ok(Self(SecretString::new(
                hashed_string.to_string().into_boxed_str(),
            )))
        } else {
            Err(eyre!("Failed to parse string to a HashedPassword type"))
        }
    }

    #[tracing::instrument(name = "Verify raw password", skip_all)]
    pub async fn verify_raw_password(
        &self,
        password_candidate: &SecretString,
    ) -> Result<()> {
        let current_span: tracing::Span = tracing::Span::current();
        let password_hash = self.as_ref().expose_secret().to_owned();
        let password_candidate = password_candidate.expose_secret().to_owned();

        let result = tokio::task::spawn_blocking(move || {
            current_span.in_scope(|| {
                let expected_password_hash = PasswordHash::new(&password_hash)?;
                Argon2::default()
                    .verify_password(password_candidate.as_bytes(), &expected_password_hash)
                    .wrap_err("failed to verify password hash")
            })
        })
        .await;
        result?
    }
}

fn validate_password(s: &SecretString) -> bool {
    s.expose_secret().len() >= 8
}

impl AsRef<SecretString> for HashedPassword {
    fn as_ref(&self) -> &SecretString {
        &self.0
    }
}

#[tracing::instrument(name = "Computing password hash", skip_all)]
async fn compute_password_hash(password: &SecretString) -> Result<SecretString> {
    let current_span: tracing::Span = tracing::Span::current();
    let password = password.expose_secret().to_owned();
    let result = tokio::task::spawn_blocking(move || {
        current_span.in_scope(|| {
            let salt = SaltString::generate(&mut OsRng);
            let password_hash = Argon2::new(
                Algorithm::Argon2id,
                Version::V0x13,
                Params::new(15000, 2, 1, None)?,
            )
            .hash_password(password.as_bytes(), &salt)?
            .to_string();
            Ok(SecretString::new(password_hash.into_boxed_str()))
        })
    })
    .await;
    result?
}

#[cfg(test)]
mod tests {
    use super::HashedPassword;
    use argon2::{
        password_hash::{rand_core::OsRng, SaltString},
        Algorithm, Argon2, Params, PasswordHasher, Version,
    };
    use secrecy::SecretString;

    #[tokio::test]
    async fn empty_string_is_rejected() {
        let password = SecretString::new("".to_owned().into_boxed_str());
        assert!(HashedPassword::parse(password).await.is_err());
    }

    #[tokio::test]
    async fn string_less_than_8_characters_is_rejected() {
        let password = SecretString::new("1234567".to_owned().into_boxed_str());
        assert!(HashedPassword::parse(password).await.is_err());
    }

    #[test]
    fn can_parse_valid_argon2_hash() {
        let raw_password = "TestPassword123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        );

        let hash_string = argon2
            .hash_password(raw_password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let hash_password =
            HashedPassword::parse_password_hash(SecretString::new(hash_string.clone().into_boxed_str()))
                .unwrap();

        use secrecy::ExposeSecret;
        assert_eq!(hash_password.as_ref().expose_secret(), hash_string.as_str());
        assert!(hash_password.as_ref().expose_secret().starts_with("$argon2id$v=19$"));
    }

    #[tokio::test]
    async fn can_verify_raw_password() {
        let raw_password = "TestPassword123";
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            Params::new(15000, 2, 1, None).unwrap(),
        );

        let hash_string = argon2
            .hash_password(raw_password.as_bytes(), &salt)
            .unwrap()
            .to_string();

        let hash_password =
            HashedPassword::parse_password_hash(SecretString::new(hash_string.clone().into_boxed_str()))
                .unwrap();

        use secrecy::ExposeSecret;
        assert_eq!(hash_password.as_ref().expose_secret(), hash_string.as_str());
        assert!(hash_password.as_ref().expose_secret().starts_with("$argon2id$v=19$"));

        let password_candidate = SecretString::new(raw_password.to_owned().into_boxed_str());
        let result = hash_password.verify_raw_password(&password_candidate).await;
        assert!(result.is_ok());
    }

    #[derive(Debug, Clone)]
    struct ValidPasswordFixture(pub SecretString);

    impl quickcheck::Arbitrary for ValidPasswordFixture {
        fn arbitrary(_g: &mut quickcheck::Gen) -> Self {
            use fake::faker::internet::en::Password as FakePassword;
            use fake::Fake;
            let password: String = FakePassword(8..30).fake();
            Self(SecretString::new(password.into_boxed_str()))
        }
    }

    #[tokio::test]
    #[quickcheck_macros::quickcheck]
    async fn valid_passwords_are_parsed_successfully(valid_password: ValidPasswordFixture) -> bool {
        HashedPassword::parse(valid_password.0).await.is_ok()
    }
}
