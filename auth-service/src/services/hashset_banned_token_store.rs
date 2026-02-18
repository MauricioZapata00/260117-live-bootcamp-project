use std::collections::HashSet;
use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashsetBannedTokenStore {
    tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashsetBannedTokenStore {
    async fn add_banned_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        self.tokens.insert(token);
        Ok(())
    }

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        Ok(self.tokens.contains(token))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_banned_token() {
        let mut store = HashsetBannedTokenStore::default();
        let token = "test-token".to_owned();
        assert!(store.add_banned_token(token.clone()).await.is_ok());
        assert!(store.contains_token(&token).await.unwrap());
    }

    #[tokio::test]
    async fn test_contains_token_returns_false_for_unknown_token() {
        let store = HashsetBannedTokenStore::default();
        assert!(!store.contains_token("unknown").await.unwrap());
    }
}
