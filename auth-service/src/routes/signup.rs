use axum::{http::StatusCode, response::IntoResponse, Json};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct SignupResponse {
    pub message: String,
}

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

pub async fn signup(Json(request): Json<SignupRequest>) -> impl IntoResponse {
    // Validate email format
    if request.email.is_empty() {
        let error_response = ErrorResponse {
            error: "Email cannot be empty".to_string(),
        };
        return (StatusCode::BAD_REQUEST, Json(error_response)).into_response();
    }

    if !is_valid_email(&request.email) {
        let error_response = ErrorResponse {
            error: "Invalid email format".to_string(),
        };
        return (StatusCode::BAD_REQUEST, Json(error_response)).into_response();
    }

    // Validate password
    if request.password.is_empty() {
        let error_response = ErrorResponse {
            error: "Password cannot be empty".to_string(),
        };
        return (StatusCode::BAD_REQUEST, Json(error_response)).into_response();
    }

    // If validation passes, return 201 Created
    let response = SignupResponse {
        message: "User created successfully!".to_string(),
    };
    (StatusCode::CREATED, Json(response)).into_response()
}

fn is_valid_email(email: &str) -> bool {
    // Email validation using regex pattern
    // Pattern: ^[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9-]+\.)+(com|com\.[a-zA-Z]{2,4})$
    // This validates emails with .com or .com.XX domains
    let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@(?:[a-zA-Z0-9-]+\.)+(com|com\.[a-zA-Z]{2,4})$")
        .expect("Invalid regex pattern");

    email_regex.is_match(email)
}

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    #[serde(rename = "requires2FA")]
    pub requires_2fa: bool,
}
