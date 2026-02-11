use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::Deserialize;
use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password},
};

#[derive(Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    // Parse and validate email using Email::parse
    let email = match Email::parse(request.email) {
        Ok(email) => email,
        Err(_) => return Err(AuthAPIError::InvalidCredentials),
    };

    // Parse and validate password using Password::parse
    let password = match Password::parse(request.password) {
        Ok(password) => password,
        Err(_) => return Err(AuthAPIError::InvalidCredentials),
    };

    let user_store = &state.user_store.read().await;

    // Validate user credentials
    match user_store.validate_user(&email, &password).await {
        Ok(_) => {},
        Err(_) => return Err(AuthAPIError::IncorrectCredentials),
    };

    // Get the user from the store
    let _user = match user_store.get_user(&email).await {
        Ok(user) => user,
        Err(_) => return Err(AuthAPIError::IncorrectCredentials),
    };

    Ok(StatusCode::OK)
}
