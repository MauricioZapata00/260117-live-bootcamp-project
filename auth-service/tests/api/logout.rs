use auth_service::utils::constants::JWT_COOKIE_NAME;
use reqwest::Url;
use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_400_if_jwt_cookie_missing() {
    let app = TestApp::new().await;
    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 400);
}

#[tokio::test]
async fn should_return_401_if_invalid_token() {
    let app = TestApp::new().await;

    app.cookie_jar.add_cookie_str(
        &format!(
            "{}=invalid; HttpOnly; SameSite=Lax; Secure; Path=/",
            JWT_COOKIE_NAME
        ),
        &Url::parse("http://127.0.0.1").expect("Failed to parse URL"),
    );

    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 401);
}

#[tokio::test]
async fn should_return_200_if_valid_jwt_cookie() {
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

    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 200);

    let is_banned = app
        .banned_token_store
        .read()
        .await
        .contains_token(&token)
        .await
        .unwrap();
    assert!(is_banned);
}

#[tokio::test]
async fn should_return_400_if_logout_called_twice_in_a_row() {
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
    app.post_login(&login_body).await;

    app.post_logout().await;

    let response = app.post_logout().await;
    assert_eq!(response.status().as_u16(), 400);
}
