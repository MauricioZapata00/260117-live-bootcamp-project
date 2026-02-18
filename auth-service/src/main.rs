use auth_service::app_state::AppState;
use auth_service::domain::{BannedTokenStore, UserStore};
use auth_service::services::hashmap_user_store::HashmapUserStore;
use auth_service::services::hashset_banned_token_store::HashsetBannedTokenStore;
use auth_service::utils::constants::prod;
use auth_service::Application;
use std::sync::Arc;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() {
    let user_store = Arc::new(RwLock::new(HashmapUserStore::default())) as Arc<RwLock<dyn UserStore>>;
    let banned_token_store = Arc::new(RwLock::new(HashsetBannedTokenStore::default())) as Arc<RwLock<dyn BannedTokenStore>>;
    let app_state = AppState::new(user_store, banned_token_store);

    let app = Application::build(app_state, prod::APP_ADDRESS)
        .await
        .expect("Failed to build app");

    app.run().await.expect("Failed to run app");
}
