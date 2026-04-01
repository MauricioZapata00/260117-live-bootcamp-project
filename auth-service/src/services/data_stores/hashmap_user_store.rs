use std::collections::HashMap;
use secrecy::SecretString;
use crate::domain::{Email, User, UserStore, UserStoreError};
#[cfg(test)]
use crate::domain::HashedPassword;

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        if self.users.contains_key(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }
        self.users.insert(user.email.clone(), user);
        Ok(())
    }

    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        self.users
            .get(email)
            .cloned()
            .ok_or(UserStoreError::UserNotFound)
    }

    async fn validate_user(&self, email: &Email, raw_password: &SecretString) -> Result<(), UserStoreError> {
        let user = self.users
            .get(email)
            .ok_or(UserStoreError::UserNotFound)?;

        user.password
            .verify_raw_password(raw_password)
            .await
            .map_err(|_| UserStoreError::InvalidCredentials)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn make_user(email: &str, password: &str, requires_2fa: bool) -> User {
        let email = Email::parse(SecretString::new(email.to_owned().into_boxed_str())).unwrap();
        let password = HashedPassword::parse(SecretString::new(password.to_owned().into_boxed_str())).await.unwrap();
        User::new(email, password, requires_2fa)
    }

    #[tokio::test]
    async fn test_add_user() {
        let mut store = HashmapUserStore::default();
        let user = make_user("test@example.com", "password123", false).await;

        assert!(store.add_user(user.clone()).await.is_ok());
        assert_eq!(store.add_user(user).await, Err(UserStoreError::UserAlreadyExists));
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut store = HashmapUserStore::default();
        let email = Email::parse(SecretString::new("test@example.com".to_owned().into_boxed_str())).unwrap();
        let user = make_user("test@example.com", "password123", true).await;

        assert_eq!(store.get_user(&email).await, Err(UserStoreError::UserNotFound));

        store.add_user(user.clone()).await.unwrap();
        assert_eq!(store.get_user(&email).await.unwrap(), user);
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = HashmapUserStore::default();
        let email = Email::parse(SecretString::new("test@example.com".to_owned().into_boxed_str())).unwrap();
        let user = make_user("test@example.com", "password123", false).await;
        let correct_password = SecretString::new("password123".to_owned().into_boxed_str());
        let wrong_password = SecretString::new("wrongpassword".to_owned().into_boxed_str());

        assert_eq!(
            store.validate_user(&email, &correct_password).await,
            Err(UserStoreError::UserNotFound)
        );

        store.add_user(user).await.unwrap();

        assert!(store.validate_user(&email, &correct_password).await.is_ok());
        assert_eq!(
            store.validate_user(&email, &wrong_password).await,
            Err(UserStoreError::InvalidCredentials)
        );
    }
}
