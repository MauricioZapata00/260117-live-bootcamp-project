use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use crate::{
    app_state::AppState,
    domain::{AuthAPIError, User},
};

#[derive(Serialize)]
pub struct SignupResponse {
    pub message: String,
}

pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
) -> Result<impl IntoResponse, AuthAPIError> {
    let email = request.email;
    let password = request.password;

    // Validate email - early return AuthAPIError::InvalidCredentials if:
    // - email is empty or does not contain '@'
    if email.is_empty() || !email.contains('@') {
        return Err(AuthAPIError::InvalidCredentials);
    }

    // Validate password - early return AuthAPIError::InvalidCredentials if:
    // - password is less than 8 characters
    if password.len() < 8 {
        return Err(AuthAPIError::InvalidCredentials);
    }

    let user = User::new(email, password, request.requires_2fa);

    let mut user_store = state.user_store.write().await;

    // Early return AuthAPIError::UserAlreadyExists if email exists in user_store.
    // Instead of using unwrap, early return AuthAPIError::UnexpectedError if add_user() fails.
    match user_store.add_user(user) {
        Ok(_) => {},
        Err(crate::services::hashmap_user_store::UserStoreError::UserAlreadyExists) => {
            return Err(AuthAPIError::UserAlreadyExists);
        }
        Err(_) => {
            return Err(AuthAPIError::UnexpectedError);
        }
    }

    let response = Json(SignupResponse {
        message: "User created successfully!".to_string(),
    });

    Ok((StatusCode::CREATED, response))
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}
