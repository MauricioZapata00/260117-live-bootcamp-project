use auth_service::utils::constants::JWT_COOKIE_NAME;
use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let response = app.post_verify_token(&serde_json::json!({ "bad_field": "value" })).await;

    assert_eq!(response.status().as_u16(), 422);
}

#[tokio::test]
async fn should_return_200_valid_token() {
    let app = TestApp::new().await;
    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });
    app.post_signup(&signup_body).await;

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123"
    });
    let login_response = app.post_login(&login_body).await;

    let auth_cookie = login_response
        .cookies()
        .find(|c| c.name() == JWT_COOKIE_NAME)
        .expect("No JWT cookie found");

    let token = auth_cookie.value().to_owned();

    let response = app.post_verify_token(&serde_json::json!({ "token": token })).await;
    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    let response = app.post_verify_token(&serde_json::json!({ "token": "invalid-token" })).await;

    assert_eq!(response.status().as_u16(), 401);
}
