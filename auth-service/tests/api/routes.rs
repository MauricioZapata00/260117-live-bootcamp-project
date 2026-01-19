use crate::helpers::TestApp;

#[tokio::test]
async fn root_returns_auth_ui() {
    let app = TestApp::new().await;
    let response = app.get_root().await;

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(response.headers().get("content-type").unwrap(), "text/html");
}

#[tokio::test]
async fn signup_returns_200() {
    let app = TestApp::new().await;
    let body = serde_json::json!({
        "email": "test@email.com",
        "password": "password",
        "requires2FA": false
    });
    let response = app.post_signup(&body).await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn login_returns_200() {
    let app = TestApp::new().await;
    let body = serde_json::json!({
        "email": "test@email.com",
        "password": "password"
    });
    let response = app.post_login(&body).await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn logout_returns_200() {
    let app = TestApp::new().await;
    let response = app.post_logout().await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn verify_2fa_returns_200() {
    let app = TestApp::new().await;
    let body = serde_json::json!({
        "email": "test@email.com",
        "loginAttemptId": "some-id",
        "2FACode": "123456"
    });
    let response = app.post_verify_2fa(&body).await;

    assert_eq!(response.status().as_u16(), 200);
}

#[tokio::test]
async fn verify_token_returns_200() {
    let app = TestApp::new().await;
    let body = serde_json::json!({
        "token": "some-token"
    });
    let response = app.post_verify_token(&body).await;

    assert_eq!(response.status().as_u16(), 200);
}
