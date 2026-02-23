use crate::config::AppConfig;
use crate::error::{EcError, EcResult};
use regex::Regex;
use reqwest::blocking::Client;
use reqwest::header::{CONTENT_TYPE, COOKIE};
use rsa::rand_core::OsRng;
use rsa::{BigUint, RsaPublicKey, pkcs1v15::Pkcs1v15Encrypt};
use urlencoding::encode;

pub fn login(config: &AppConfig) -> EcResult<String> {
    let base_url = normalize_base_url(&config.server);
    let client = build_http_client()?;

    let login_auth_url = format!("{base_url}/por/login_auth.csp?apiversion=1");
    let login_auth_body = client
        .get(login_auth_url)
        .send()
        .and_then(|r| r.error_for_status())
        .map_err(|e| EcError::Runtime(format!("login_auth request failed: {e}")))?
        .text()
        .map_err(|e| EcError::Runtime(format!("login_auth body read failed: {e}")))?;

    let mut twf_id = extract_tag(&login_auth_body, "TwfID")
        .ok_or_else(|| EcError::Runtime("missing <TwfID> in login_auth response".to_string()))?;
    let rsa_key = extract_tag(&login_auth_body, "RSA_ENCRYPT_KEY").ok_or_else(|| {
        EcError::Runtime("missing <RSA_ENCRYPT_KEY> in login_auth response".to_string())
    })?;
    let rsa_exp =
        extract_tag(&login_auth_body, "RSA_ENCRYPT_EXP").unwrap_or_else(|| "65537".to_string());
    let csrf = extract_tag(&login_auth_body, "CSRF_RAND_CODE").unwrap_or_default();

    let password_input = if csrf.is_empty() {
        config.password.clone()
    } else {
        format!("{}_{}", config.password, csrf)
    };
    let encrypted_password_hex = encrypt_password_hex(&password_input, &rsa_key, &rsa_exp)?;

    let login_psw_url = format!("{base_url}/por/login_psw.csp?anti_replay=1&encrypt=1&type=cs");
    let body = format!(
        "svpn_rand_code=&mitm=&svpn_req_randcode={}&svpn_name={}&svpn_password={}",
        encode(&csrf),
        encode(&config.username),
        encode(&encrypted_password_hex)
    );

    let login_psw_body = client
        .post(login_psw_url)
        .header(COOKIE, format!("TWFID={twf_id}"))
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(body)
        .send()
        .and_then(|r| r.error_for_status())
        .map_err(|e| EcError::Runtime(format!("login_psw request failed: {e}")))?
        .text()
        .map_err(|e| EcError::Runtime(format!("login_psw body read failed: {e}")))?;

    if login_psw_body.contains("<NextService>auth/sms</NextService>")
        || login_psw_body.contains("<NextAuth>2</NextAuth>")
    {
        return Err(EcError::NotImplemented(
            "sms 2fa is out of current minimal scope",
        ));
    }
    if login_psw_body.contains("<NextService>auth/token</NextService>")
        || login_psw_body.contains("<NextServiceSubType>totp</NextServiceSubType>")
    {
        return Err(EcError::NotImplemented(
            "totp 2fa is out of current minimal scope",
        ));
    }
    if !login_psw_body.contains("<Result>1</Result>") {
        return Err(EcError::Runtime(
            "login failed: missing success result marker".to_string(),
        ));
    }

    if let Some(updated) = extract_tag(&login_psw_body, "TwfID") {
        twf_id = updated;
    }

    Ok(twf_id)
}

fn build_http_client() -> EcResult<Client> {
    Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| EcError::Runtime(format!("http client build failed: {e}")))
}

fn normalize_base_url(server: &str) -> String {
    if server.starts_with("https://") || server.starts_with("http://") {
        server.to_string()
    } else {
        format!("https://{server}")
    }
}

fn extract_tag(body: &str, tag: &str) -> Option<String> {
    let pattern = format!(r"<{tag}>([^<]*)</{tag}>");
    let regex = Regex::new(&pattern).ok()?;
    regex
        .captures(body)
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str().to_string())
}

fn encrypt_password_hex(password: &str, rsa_key_hex: &str, rsa_exp: &str) -> EcResult<String> {
    let modulus = BigUint::parse_bytes(rsa_key_hex.as_bytes(), 16)
        .ok_or_else(|| EcError::Runtime("invalid RSA modulus".to_string()))?;
    let exponent_u32 = rsa_exp
        .parse::<u32>()
        .map_err(|e| EcError::Runtime(format!("invalid RSA exponent: {e}")))?;
    let exponent = BigUint::from(exponent_u32);
    let public_key = RsaPublicKey::new(modulus, exponent)
        .map_err(|e| EcError::Runtime(format!("invalid RSA public key: {e}")))?;

    let encrypted = public_key
        .encrypt(&mut OsRng, Pkcs1v15Encrypt, password.as_bytes())
        .map_err(|e| EcError::Runtime(format!("RSA encrypt failed: {e}")))?;

    Ok(hex::encode(encrypted))
}

#[cfg(test)]
mod tests {
    use super::{extract_tag, normalize_base_url};

    #[test]
    fn normalize_base_url_adds_https_scheme() {
        assert_eq!(
            normalize_base_url("vpn.example.com:443"),
            "https://vpn.example.com:443"
        );
    }

    #[test]
    fn normalize_base_url_keeps_existing_scheme() {
        assert_eq!(
            normalize_base_url("https://vpn.example.com"),
            "https://vpn.example.com"
        );
    }

    #[test]
    fn extract_tag_reads_expected_value() {
        let input = "<root><TwfID>ABC123</TwfID></root>";
        assert_eq!(extract_tag(input, "TwfID").as_deref(), Some("ABC123"));
    }
}
