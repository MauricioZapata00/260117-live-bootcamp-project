use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use serde::{Deserialize, Serialize};
use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, Password, User},
};

#[derive(Serialize)]
pub struct SignupResponse {
    pub message: String,
}

pub async fn signup(
    State(state): State<AppState>,
    Json(request): Json<SignupRequest>,
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

    let user = User::new(email, password, request.requires_2fa);

    let mut user_store = state.user_store.write().await;

    // Early return AuthAPIError::UserAlreadyExists if email exists in user_store.
    // Instead of using unwrap, early return AuthAPIError::UnexpectedError if add_user() fails.
    match user_store.add_user(user).await {
        Ok(_) => {},
        Err(crate::domain::UserStoreError::UserAlreadyExists) => {
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
