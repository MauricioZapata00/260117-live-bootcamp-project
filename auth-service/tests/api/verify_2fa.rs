use auth_service::{
    domain::{Email, LoginAttemptId, TwoFACode},
    routes::TwoFactorAuthResponse,
    utils::constants::JWT_COOKIE_NAME,
    ErrorResponse,
};
use secrecy::{ExposeSecret, SecretString};
use wiremock::{Mock, ResponseTemplate};
use wiremock::matchers::{method, path};
use crate::helpers::{get_random_email, TestApp};

#[tokio::test]
async fn should_return_422_if_malformed_input() {
    let app = TestApp::new().await;

    let test_cases = [
        serde_json::json!({}),
        serde_json::json!({ "email": "test@example.com" }),
        serde_json::json!({ "email": "test@example.com", "loginAttemptId": "some-id" }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(test_case).await;
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
            "email": "not-an-email",
            "loginAttemptId": LoginAttemptId::default().as_ref().expose_secret().to_owned(),
            "2FACode": "123456"
        }),
        serde_json::json!({
            "email": "test@example.com",
            "loginAttemptId": "not-a-uuid",
            "2FACode": "123456"
        }),
        serde_json::json!({
            "email": "test@example.com",
            "loginAttemptId": LoginAttemptId::default().as_ref().expose_secret().to_owned(),
            "2FACode": "123"
        }),
    ];

    for test_case in test_cases.iter() {
        let response = app.post_verify_2fa(test_case).await;
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

    let response = app
        .post_verify_2fa(&serde_json::json!({
            "email": get_random_email(),
            "loginAttemptId": LoginAttemptId::default().as_ref().expose_secret().to_owned(),
            "2FACode": TwoFACode::default().as_ref().expose_secret().to_owned(),
        }))
        .await;

    assert_eq!(response.status().as_u16(), 401);

    let error_response = response
        .json::<ErrorResponse>()
        .await
        .expect("Failed to deserialize error response");

    assert_eq!(error_response.error, "Incorrect credentials");

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_old_code() {
    let app = TestApp::new().await;
    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });
    app.post_signup(&signup_body).await;

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123"
    });

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(2)
        .mount(&app.email_server)
        .await;

    app.post_login(&login_body).await;

    let email = Email::parse(SecretString::new(random_email.clone().into_boxed_str())).unwrap();
    let (old_login_attempt_id, old_code) = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&email)
        .await
        .unwrap();

    app.post_login(&login_body).await;

    let response = app
        .post_verify_2fa(&serde_json::json!({
            "email": random_email,
            "loginAttemptId": old_login_attempt_id.as_ref().expose_secret().to_owned(),
            "2FACode": old_code.as_ref().expose_secret().to_owned(),
        }))
        .await;

    assert_eq!(response.status().as_u16(), 401);

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_200_if_correct_code() {
    let app = TestApp::new().await;
    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });
    app.post_signup(&signup_body).await;

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123"
    });

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let login_response = app.post_login(&login_body).await;

    let login_attempt_id = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize login response")
        .login_attempt_id;

    let email = Email::parse(SecretString::new(random_email.clone().into_boxed_str())).unwrap();
    let (_, code) = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&email)
        .await
        .unwrap();

    let response = app
        .post_verify_2fa(&serde_json::json!({
            "email": random_email,
            "loginAttemptId": login_attempt_id,
            "2FACode": code.as_ref().expose_secret().to_owned(),
        }))
        .await;

    assert_eq!(response.status().as_u16(), 200);

    let auth_cookie = response
        .cookies()
        .find(|c| c.name() == JWT_COOKIE_NAME)
        .expect("No JWT cookie found");

    assert!(!auth_cookie.value().is_empty());

    app.clean_up().await;
}

#[tokio::test]
async fn should_return_401_if_same_code_twice() {
    let app = TestApp::new().await;
    let random_email = get_random_email();

    let signup_body = serde_json::json!({
        "email": random_email,
        "password": "password123",
        "requires2FA": true
    });
    app.post_signup(&signup_body).await;

    let login_body = serde_json::json!({
        "email": random_email,
        "password": "password123"
    });

    Mock::given(path("/email"))
        .and(method("POST"))
        .respond_with(ResponseTemplate::new(200))
        .expect(1)
        .mount(&app.email_server)
        .await;

    let login_response = app.post_login(&login_body).await;

    let login_attempt_id = login_response
        .json::<TwoFactorAuthResponse>()
        .await
        .expect("Could not deserialize login response")
        .login_attempt_id;

    let email = Email::parse(SecretString::new(random_email.clone().into_boxed_str())).unwrap();
    let (_, code) = app
        .two_fa_code_store
        .read()
        .await
        .get_code(&email)
        .await
        .unwrap();

    let verify_body = serde_json::json!({
        "email": random_email,
        "loginAttemptId": login_attempt_id,
        "2FACode": code.as_ref().expose_secret().to_owned(),
    });

    let response = app.post_verify_2fa(&verify_body).await;
    assert_eq!(response.status().as_u16(), 200);

    let response = app.post_verify_2fa(&verify_body).await;
    assert_eq!(response.status().as_u16(), 401);

    app.clean_up().await;
}
