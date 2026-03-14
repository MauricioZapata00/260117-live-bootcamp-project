use auth_service::ErrorResponse;
use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_201_if_valid_input() {
    let app = TestApp::new().await;

    let test_cases = [
        serde_json::json!({
            "email": get_random_email(),
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": get_random_email(),
            "password": "averylongpassword12345",
            "requires2FA": false
        }),
        serde_json::json!({
            "email": "test.user+tag@example.com",
            "password": "P@ssw0rd!",
            "requires2FA": true
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            201,
            "Failed for input: {:?}",
            test_case
        );

        let json: serde_json::Value = response
            .json()
            .await
            .expect("Failed to parse response body");

        assert_eq!(
            json["message"],
            "User created successfully!",
            "Response message mismatch"
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    let test_cases = [
        serde_json::json!({
            "email": "",
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": "invalidemail",
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": get_random_email(),
            "password": "pass",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": get_random_email(),
            "password": "",
            "requires2FA": true
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );

        assert_eq!(
            response
                .json::<ErrorResponse>()
                .await
                .expect("Could not deserialize response body to ErrorResponse")
                .error,
            "Invalid credentials".to_owned()
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
        serde_json::json!({
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "password": "password123"
        }),
        serde_json::json!({}),
        serde_json::json!({
            "email": 12345,
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": true,
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": {"nested": "object"},
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "password": 12345,
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "password": false,
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "password": ["array", "value"],
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "password": "password123",
            "requires2FA": "true"
        }),
        serde_json::json!({
            "email": random_email,
            "password": "password123",
            "requires2FA": 1
        }),
        serde_json::json!({
            "email": random_email,
            "password": "password123",
            "requires2FA": {}
        }),
        serde_json::json!({
            "email": null,
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "password": null,
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "password": "password123",
            "requires2FA": null
        }),
        serde_json::json!({
            "email": 123,
            "password": 456,
            "requires2FA": true
        }),
        serde_json::json!({
            "email": ["test@example.com"],
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": [["test@example.com"]],
            "password": "password123",
            "requires2FA": true
        }),
        serde_json::json!({
            "email": random_email,
            "password": {"value": "password123"},
            "requires2FA": true
        }),
        serde_json::json!({
            "email": 123,
            "password": true,
            "requires2FA": "false"
        }),
        serde_json::json!({
            "email": null,
            "password": 12345,
            "requires2FA": "true"
        }),
        serde_json::json!({
            "email": random_email,
            "password": "password123",
            "requires2FA": [true]
        }),
        serde_json::json!({
            "email": {"user": "test", "domain": "example.com"},
            "password": "password123",
            "requires2FA": true
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_signup(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            422,
            "Failed for input: {:?}",
            test_case
        );
    }

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_409_if_email_already_exists() {
    let app = TestApp::new().await;

    let signup_request = serde_json::json!({
        "email": get_random_email(),
        "password": "password123",
        "requires2FA": true
    });

    let response = app.post_signup(&signup_request).await;
    assert_eq!(response.status().as_u16(), 201);

    let response = app.post_signup(&signup_request).await;
    assert_eq!(response.status().as_u16(), 409);

    assert_eq!(
        response
            .json::<ErrorResponse>()
            .await
            .expect("Could not deserialize response body to ErrorResponse")
            .error,
        "User already exists".to_owned()
    );

    app.clean_up().await;
}
