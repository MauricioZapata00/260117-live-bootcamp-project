use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let random_email = get_random_email();

    let test_cases = [
        // Missing email field
        serde_json::json!({
            "password": "password123",
            "requires2FA": true
        }),
        // Missing password field
        serde_json::json!({
            "email": random_email,
            "requires2FA": true
        }),
        // Missing requires2FA field
        serde_json::json!({
            "email": random_email,
            "password": "password123"
        }),
        // Empty object - all fields missing
        serde_json::json!({}),
        // Wrong type for email (number instead of string)
        serde_json::json!({
            "email": 12345,
            "password": "password123",
            "requires2FA": true
        }),
        // Wrong type for email (boolean instead of string)
        serde_json::json!({
            "email": true,
            "password": "password123",
            "requires2FA": true
        }),
        // Wrong type for email (object instead of string)
        serde_json::json!({
            "email": {"nested": "object"},
            "password": "password123",
            "requires2FA": true
        }),
        // Wrong type for password (number instead of string)
        serde_json::json!({
            "email": random_email,
            "password": 12345,
            "requires2FA": true
        }),
        // Wrong type for password (boolean instead of string)
        serde_json::json!({
            "email": random_email,
            "password": false,
            "requires2FA": true
        }),
        // Wrong type for password (array instead of string)
        serde_json::json!({
            "email": random_email,
            "password": ["array", "value"],
            "requires2FA": true
        }),
        // Wrong type for requires2FA (string instead of boolean)
        serde_json::json!({
            "email": random_email,
            "password": "password123",
            "requires2FA": "true"
        }),
        // Wrong type for requires2FA (number instead of boolean)
        serde_json::json!({
            "email": random_email,
            "password": "password123",
            "requires2FA": 1
        }),
        // Wrong type for requires2FA (object instead of boolean)
        serde_json::json!({
            "email": random_email,
            "password": "password123",
            "requires2FA": {}
        }),
        // Null value for email
        serde_json::json!({
            "email": null,
            "password": "password123",
            "requires2FA": true
        }),
        // Null value for password
        serde_json::json!({
            "email": random_email,
            "password": null,
            "requires2FA": true
        }),
        // Null value for requires2FA
        serde_json::json!({
            "email": random_email,
            "password": "password123",
            "requires2FA": null
        }),
        // Multiple fields wrong - email and password as numbers
        serde_json::json!({
            "email": 123,
            "password": 456,
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
}
