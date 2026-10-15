use lettre::message::header::ContentType;
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Message, AsyncSmtpTransport, AsyncTransport, Tokio1Executor};
use std::env;

pub async fn send_verification_email(to_email: &str, otp: &str) -> Result<(), Box<dyn std::error::Error>> {
    let smtp_username = env::var("SMTP_USERNAME").unwrap_or_else(|_| "baton.security@gmail.com".to_string());
    let smtp_password = env::var("SMTP_PASSWORD").unwrap_or_else(|_| "mock_password".to_string());

    // Using unencrypted for mock/testing if mock password, else real SMTP
    

    let email = Message::builder()
        .from(format!("Baton Security <{}>", smtp_username).parse()?)
        .to(to_email.parse()?)
        .subject("Your Baton Verification Code")
        .header(ContentType::TEXT_PLAIN)
        .body(format!("Your verification code is: {}\n\nThis code will expire in 15 minutes.", otp))?;

    let creds = Credentials::new(smtp_username.clone(), smtp_password);

    let mailer: AsyncSmtpTransport<Tokio1Executor> = AsyncSmtpTransport::<Tokio1Executor>::relay("smtp.gmail.com")?
        .credentials(creds)
        .build();

    mailer.send(email).await.map_err(|e| {
        eprintln!("SMTP error: {:?}", e);
        anyhow::anyhow!("Failed to send email: {}", e)
    })?;

    Ok(())
}
