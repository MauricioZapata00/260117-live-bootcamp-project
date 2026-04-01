use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::CookieJar;
use secrecy::SecretString;
use serde::Deserialize;
use crate::{
    app_state::AppState,
    domain::{AuthAPIError, Email, LoginAttemptId, TwoFACode},
    utils::auth::generate_auth_cookie,
};

#[derive(Deserialize)]
pub struct Verify2FARequest {
    pub email: String,
    #[serde(rename = "loginAttemptId")]
    pub login_attempt_id: String,
    #[serde(rename = "2FACode")]
    pub two_fa_code: String,
}

#[tracing::instrument(name = "Verify 2FA", skip_all)]
pub async fn verify_2fa(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(request): Json<Verify2FARequest>,
) -> (CookieJar, Result<impl IntoResponse, AuthAPIError>) {
    let email = match Email::parse(SecretString::new(request.email.into_boxed_str())) {
        Ok(email) => email,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    let login_attempt_id = match LoginAttemptId::parse(request.login_attempt_id) {
        Ok(id) => id,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    let two_fa_code = match TwoFACode::parse(request.two_fa_code) {
        Ok(code) => code,
        Err(_) => return (jar, Err(AuthAPIError::InvalidCredentials)),
    };

    let mut two_fa_code_store = state.two_fa_code_store.write().await;

    let (stored_login_attempt_id, stored_two_fa_code) =
        match two_fa_code_store.get_code(&email).await {
            Ok(code_tuple) => code_tuple,
            Err(_) => return (jar, Err(AuthAPIError::IncorrectCredentials)),
        };

    if login_attempt_id != stored_login_attempt_id || two_fa_code != stored_two_fa_code {
        return (jar, Err(AuthAPIError::IncorrectCredentials));
    }

    if let Err(e) = two_fa_code_store.remove_code(&email).await {
        return (jar, Err(AuthAPIError::UnexpectedError(e.into())));
    }

    let auth_cookie = match generate_auth_cookie(&email) {
        Ok(cookie) => cookie,
        Err(e) => return (jar, Err(AuthAPIError::UnexpectedError(e))),
    };

    let updated_jar = jar.add(auth_cookie);

    (updated_jar, Ok(StatusCode::OK))
}
