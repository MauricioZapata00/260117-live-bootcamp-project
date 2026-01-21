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

        // Check response body
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
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

    let test_cases = [
        // Empty email
        (
            serde_json::json!({
                "email": "",
                "password": "password123",
                "requires2FA": true
            }),
            "Email cannot be empty"
        ),
        // Invalid email - no @
        (
            serde_json::json!({
                "email": "invalidemail",
                "password": "password123",
                "requires2FA": true
            }),
            "Invalid email format"
        ),
        // Invalid email - no domain
        (
            serde_json::json!({
                "email": "test@",
                "password": "password123",
                "requires2FA": true
            }),
            "Invalid email format"
        ),
        // Invalid email - no local part
        (
            serde_json::json!({
                "email": "@example.com",
                "password": "password123",
                "requires2FA": true
            }),
            "Invalid email format"
        ),
        // Invalid email - no TLD
        (
            serde_json::json!({
                "email": "test@example",
                "password": "password123",
                "requires2FA": true
            }),
            "Invalid email format"
        ),
        // Invalid email - double @
        (
            serde_json::json!({
                "email": "test@@example.com",
                "password": "password123",
                "requires2FA": true
            }),
            "Invalid email format"
        ),
        // Invalid email - ends with dot
        (
            serde_json::json!({
                "email": "test@example.com.",
                "password": "password123",
                "requires2FA": true
            }),
            "Invalid email format"
        ),
        // Empty password
        (
            serde_json::json!({
                "email": get_random_email(),
                "password": "",
                "requires2FA": true
            }),
            "Password cannot be empty"
        ),
        // Invalid email - doesn't match .com or .com.XX pattern
        (
            serde_json::json!({
                "email": "qSdy6asQjL8siKA@m.fegl",
                "password": "password123",
                "requires2FA": true
            }),
            "Invalid email format"
        ),
        // Invalid email - .net domain
        (
            serde_json::json!({
                "email": "test@example.net",
                "password": "password123",
                "requires2FA": true
            }),
            "Invalid email format"
        ),
        // Invalid email - .org domain
        (
            serde_json::json!({
                "email": "user@domain.org",
                "password": "password123",
                "requires2FA": true
            }),
            "Invalid email format"
        ),
    ];

    for (test_case, expected_error) in test_cases.iter() {
        let response = app.post_signup(test_case).await;

        assert_eq!(
            response.status().as_u16(),
            400,
            "Failed for input: {:?}",
            test_case
        );

        // Check error message
        let json: serde_json::Value = response
            .json()
            .await
            .expect("Failed to parse response body");

        assert_eq!(
            json["error"],
            *expected_error,
            "Error message mismatch for input: {:?}",
            test_case
        );
    }
}

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
        // Email as array
        serde_json::json!({
            "email": ["test@example.com"],
            "password": "password123",
            "requires2FA": true
        }),
        // Email as nested array
        serde_json::json!({
            "email": [["test@example.com"]],
            "password": "password123",
            "requires2FA": true
        }),
        // Password as object
        serde_json::json!({
            "email": random_email,
            "password": {"value": "password123"},
            "requires2FA": true
        }),
        // All fields with wrong types
        serde_json::json!({
            "email": 123,
            "password": true,
            "requires2FA": "false"
        }),
        // Email as null, password as number, requires2FA as string
        serde_json::json!({
            "email": null,
            "password": 12345,
            "requires2FA": "true"
        }),
        // requires2FA as array
        serde_json::json!({
            "email": random_email,
            "password": "password123",
            "requires2FA": [true]
        }),
        // Extra nested structure for email
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
}
