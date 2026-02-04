use std::collections::HashMap;
use crate::domain::{User, UserStore, UserStoreError};

#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<String, User>,
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

    async fn get_user(&self, email: &str) -> Result<User, UserStoreError> {
        self.users
            .get(email)
            .cloned()
            .ok_or(UserStoreError::UserNotFound)
    }

    async fn validate_user(&self, email: &str, password: &str) -> Result<(), UserStoreError> {
        let user = self.users
            .get(email)
            .ok_or(UserStoreError::UserNotFound)?;

        if user.password != password {
            return Err(UserStoreError::InvalidCredentials);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new("test@example.com".to_string(), "password123".to_string(), false);

        // Adding user should succeed
        assert!(store.add_user(user.clone()).await.is_ok());

        // Adding the same user again should fail
        assert_eq!(store.add_user(user).await, Err(UserStoreError::UserAlreadyExists));
    }

    #[tokio::test]
    async fn test_get_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new("test@example.com".to_string(), "password123".to_string(), true);

        // Getting non-existent user should fail
        assert_eq!(store.get_user("test@example.com").await, Err(UserStoreError::UserNotFound));

        // Add user and try to get it
        store.add_user(user.clone()).await.unwrap();
        assert_eq!(store.get_user("test@example.com").await.unwrap(), user);
    }

    #[tokio::test]
    async fn test_validate_user() {
        let mut store = HashmapUserStore::default();
        let user = User::new("test@example.com".to_string(), "password123".to_string(), false);

        // Validating non-existent user should fail
        assert_eq!(
            store.validate_user("test@example.com", "password123").await,
            Err(UserStoreError::UserNotFound)
        );

        // Add user
        store.add_user(user).await.unwrap();

        // Validating with correct password should succeed
        assert!(store.validate_user("test@example.com", "password123").await.is_ok());

        // Validating with incorrect password should fail
        assert_eq!(
            store.validate_user("test@example.com", "wrongpassword").await,
            Err(UserStoreError::InvalidCredentials)
        );
    }
}
