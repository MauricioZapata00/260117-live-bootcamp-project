use auth_service::{
    domain::Email,
    routes::TwoFactorAuthResponse,
    utils::constants::JWT_COOKIE_NAME,
    ErrorResponse,
};
use secrecy::{ExposeSecret, SecretString};
use wiremock::{Mock, ResponseTemplate};
use wiremock::matchers::{method, path};
use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_credentials() {
    let app = TestApp::new().await;

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

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_400_if_invalid_input() {
    let app = TestApp::new().await;

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

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_incorrect_credentials() {
    let app = TestApp::new().await;

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

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_valid_credentials_and_2fa_disabled() {
    let app = TestApp::new().await;

    let random_email = get_random_email();
    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": false
    });
    let response = app.post_signup(&signup_body).await;

    assert_eq!(response.status().as_u16(), 201);

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
    });
    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|cookie| cookie.name() == JWT_COOKIE_NAME)
        .expect("No auth cookie found");

    assert!(!auth_cookie.value().is_empty());

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_206_if_valid_credentials_and_2fa_enabled() {
    let app = TestApp::new().await;
    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });
    let response = app.post_signup(&signup_body).await;
    assert_eq!(response.status().as_u16(), 201);

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123"
    });
    let response = app.post_login(&login_body).await;

    assert_eq!(response.status().as_u16(), 206);

    let json_body: TwoFactorAuthResponse = response
        .json()
        .await
        .expect("Could not deserialize response body to TwoFactorAuthResponse");

    assert_eq!(json_body.message, "2FA required".to_owned());

    let email = Email::parse(SecretString::new(random_email.into_boxed_str())).unwrap();
    let result = app.two_fa_code_store.read().await.get_code(&email).await;
    assert!(result.is_ok());
    let (login_attempt_id, _) = result.unwrap();
    assert_eq!(login_attempt_id.as_ref().expose_secret(), &json_body.login_attempt_id);

    app.clean_up().await;
}
