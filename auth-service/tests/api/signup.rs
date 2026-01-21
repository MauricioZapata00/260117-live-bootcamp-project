use crate::helpers::TestApp;

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
