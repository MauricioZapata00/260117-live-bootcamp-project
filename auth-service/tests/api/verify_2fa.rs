use crate::helpers::TestApp;

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
