use auth_service::ErrorResponse;
use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let app = TestApp::new().await;

    // Test with malformed JSON (missing fields)
    let test_cases = [
        serde_json::json!({}),
        serde_json::json!({"email": "test@example.com"}),
        serde_json::json!({"password": "password123"}),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    // Test with invalid email and password formats
    let test_cases = [
        serde_json::json!({
            "email": "invalid-email",
            "password": "password123"
        }),
        serde_json::json!({
            "email": "test@example.com",
            "password": "short"
        }),
        serde_json::json!({
            "email": "",
            "password": "password123"
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_login(test_case).await;
        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );

        let error_response = response
            .json::<ErrorResponse>()
            .await
            .expect("Failed to deserialize error response");

        assert_eq!(error_response.error, "Invalid credentials");
    }
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;

    // Test with user that doesn't exist
    let random_email = get_random_email();
    let response = app
        .post_login(&serde_json::json!({
            "email": random_email,
            "password": "password123"
        }))
        .await;

    assert_eq!(response.status().as_u16(), 401);

    let error_response = response
        .json::<ErrorResponse>()
        .await
        .expect("Failed to deserialize error response");

    assert_eq!(error_response.error, "Incorrect credentials");

    // Test with existing user but wrong password
    let signup_body = serde_json::json!({
        "email": "test@example.com",
        "password": "password123",
        "requires2FA": false
    });
    let signup_response = app.post_signup(&signup_body).await;
    assert_eq!(signup_response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": "test@example.com",
        "password": "wrong_password123"
    });
    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 401);

    let error_response = response
        .json::<ErrorResponse>()
        .await
        .expect("Failed to deserialize error response");

    assert_eq!(error_response.error, "Incorrect credentials");
}
