use std::collections::HashSet;
use secrecy::{ExposeSecret, SecretString};
use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn add_banned_token(&mut self, token: SecretString) -> Result<(), BannedTokenStoreError> {
        self.tokens.insert(token.expose_secret().to_owned());
        Ok(())
    }

    async fn contains_token(&self, token: &SecretString) -> Result<bool, BannedTokenStoreError> {
        Ok(self.tokens.contains(token.expose_secret()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_banned_token() {
        let mut store = HashsetBannedTokenStore::default();
        let token = SecretString::new("test-token".to_owned().into_boxed_str());
        assert!(store.add_banned_token(token.clone()).await.is_ok());
        assert!(store.contains_token(&token).await.unwrap());
    }

    #[tokio::test]
    async fn test_contains_token_returns_false_for_unknown_token() {
        let store = HashsetBannedTokenStore::default();
        let token = SecretString::new("unknown".to_owned().into_boxed_str());
        assert!(!store.contains_token(&token).await.unwrap());
    }
}
