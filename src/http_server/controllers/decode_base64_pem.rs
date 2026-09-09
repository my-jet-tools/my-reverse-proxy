use base64::Engine;
use my_http_server::HttpFailResult;

/// Decodes a base64 json field into the PEM bytes the certificate loaders expect. Both the
/// empty field and broken base64 are reported by name, so the caller knows which one to fix
/// instead of getting a generic "bad certificate" from the PEM parser further down.
///
/// All whitespace is stripped first: `base64 < cert.pem` and `openssl base64` wrap their output
/// at 76 characters, and the strict engine would otherwise reject the line breaks.
pub fn decode_base64_pem(value: &str, field: &str) -> Result<Vec<u8>, HttpFailResult> {
    let value: String = value.chars().filter(|c| !c.is_whitespace()).collect();

    if value.is_empty() {
        return Err(HttpFailResult::as_validation_error(format!(
            "'{}' must not be empty",
            field
        )));
    }

    base64::engine::general_purpose::STANDARD
        .decode(value.as_str())
        .map_err(|err| {
            // A backslash can only come from a json escape that was never resolved (see the
            // action descriptions), which in practice means line-wrapped base64.
            let hint = if value.contains('\\') {
                " - send the base64 as a single line, without line breaks"
            } else {
                ""
            };

            HttpFailResult::as_validation_error(format!(
                "'{}' is not a valid base64 of the PEM text: {}{}",
                field, err, hint
            ))
        })
}
