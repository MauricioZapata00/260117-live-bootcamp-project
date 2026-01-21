use crate::helpers::TestApp;

#[tokio::test]
async fn verify_token_returns_200() {
    let app = TestApp::new().await;
    let body = serde_json::json!({
        "token": "some-token"
    });
    let response = app.post_verify_token(&body).await;

    assert_eq!(response.status().as_u16(), 200);
}
