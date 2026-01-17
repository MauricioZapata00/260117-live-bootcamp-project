use axum::{response::Html, routing::get, serve, Router};
use tower_http::services::ServeDir;

#[tokio::main]
async fn main() {
    let assets_dir = ServeDir::new("assets");
    let app = Router::new()
        .fallback_service(assets_dir)
        .route("/hello", get(hello_handler));

    // Here we are using ip 0.0.0.0 so the service is listening on all the configured network interfaces.
    // This is needed for Docker to work, which we will add later on.
    // See: https://stackoverflow.com/questions/39525820/docker-port-forwarding-not-working
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("listening on {}", listener.local_addr().unwrap());

    axum::serve(listener, app).await.unwrap();
}

async fn hello_handler() -> Html<&'static str> {
    Html(r#"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Auth Service</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            color: #333;
        }

        .container {
            background: white;
            border-radius: 20px;
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
            padding: 60px;
            max-width: 600px;
            text-align: center;
            animation: fadeIn 0.8s ease-in;
        }

        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }

        .logo {
            width: 80px;
            height: 80px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 50%;
            margin: 0 auto 30px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 40px;
            color: white;
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.4);
        }

        h1 {
            font-size: 42px;
            color: #2d3748;
            margin-bottom: 20px;
            font-weight: 700;
        }

        .subtitle {
            font-size: 18px;
            color: #718096;
            margin-bottom: 40px;
            line-height: 1.6;
        }

        .features {
            display: grid;
            gap: 20px;
            margin-top: 40px;
        }

        .feature {
            background: #f7fafc;
            padding: 20px;
            border-radius: 12px;
            border-left: 4px solid #667eea;
            text-align: left;
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }

        .feature:hover {
            transform: translateX(5px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.2);
        }

        .feature-title {
            font-weight: 600;
            color: #2d3748;
            margin-bottom: 8px;
            font-size: 16px;
        }

        .feature-desc {
            color: #718096;
            font-size: 14px;
            line-height: 1.5;
        }

        .status {
            display: inline-flex;
            align-items: center;
            gap: 8px;
            background: #48bb78;
            color: white;
            padding: 10px 20px;
            border-radius: 25px;
            font-weight: 600;
            margin-top: 30px;
            box-shadow: 0 4px 12px rgba(72, 187, 120, 0.3);
        }

        .status-dot {
            width: 10px;
            height: 10px;
            background: white;
            border-radius: 50%;
            animation: pulse 2s infinite;
        }

        @keyframes pulse {
            0%, 100% {
                opacity: 1;
            }
            50% {
                opacity: 0.5;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🔐</div>
        <h1>Auth Service</h1>
        <p class="subtitle">
            Secure, scalable authentication service built with Rust and Axum
        </p>

        <div class="features">
            <div class="feature">
                <div class="feature-title">🚀 High Performance</div>
                <div class="feature-desc">Built with Rust for maximum speed and reliability</div>
            </div>
            <div class="feature">
                <div class="feature-title">🛡️ Secure by Design</div>
                <div class="feature-desc">Industry-standard security practices and encryption</div>
            </div>
            <div class="feature">
                <div class="feature-title">⚡ Lightning Fast</div>
                <div class="feature-desc">Powered by Axum and Tokio for async performance</div>
            </div>
        </div>

        <div class="status">
            <div class="status-dot"></div>
            Service Online
        </div>
    </div>
</body>
</html>"#)
}
