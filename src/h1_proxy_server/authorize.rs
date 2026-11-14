use crate::{
    configurations::*, google_auth::GoogleAuthError, h1_utils::*,
    http_proxy_pass::HttpProxyPassIdentity, network_stream::*,
};

use rust_extensions::slice_of_u8_utils::SliceOfU8Ext;

use super::*;

/// The values of the first two `X-Api-Key` headers of the request. A request with more than one
/// is refused whatever they are, so a third is never looked for.
fn find_api_key_values<'a>(http_headers: &Http1Headers, data: &'a [u8]) -> [Option<&'a [u8]>; 2] {
    let mut result = [None, None];
    let mut found = 0;

    let mut pos = http_headers.first_line_end + crate::consts::HTTP_CR_LF.len();
    loop {
        let Some(next) = data.find_sequence_pos(crate::consts::HTTP_CR_LF, pos) else {
            return result;
        };
        if next == pos {
            return result;
        }
        if let Some(header) = HttpHeader::new(data, pos, next) {
            if header.is_my_header_name(crate::api_keys::API_KEY_HEADER.as_bytes()) {
                let value_pos = header.get_value();
                result[found] = Some(&data[value_pos.start..value_pos.end]);
                found += 1;

                if found == result.len() {
                    return result;
                }
            }
        }
        pos = next + crate::consts::HTTP_CR_LF.len();
    }
}

impl<TNetworkReadPart: NetworkStreamReadPart + Send + Sync + 'static> H1Reader<TNetworkReadPart> {
    pub async fn authorize(
        &self,
        endpoint_info: &HttpEndpointInfo,
        location: &ProxyPassLocationConfig,
        http_connection_info: &HttpConnectionInfo,
        http_headers: &Http1Headers,
    ) -> Result<Option<HttpProxyPassIdentity>, ProxyServerError> {
        // The connection-level client cert becomes an identity only for
        // endpoints requiring the same CA that verified it: on a cross-`Host`
        // request (coalescing / keep-alive reuse) another vhost's CN must not
        // leak into this endpoint's allowed_users checks or
        // ${CLIENT_CERT_CN} headers.
        let cert_identity = http_connection_info
            .cn_user_name
            .as_ref()
            .filter(|cert| endpoint_info.client_cert_identity_applies(cert))
            .cloned()
            .map(HttpProxyPassIdentity::ClientCert);

        if location.api_keys_auth.is_some() {
            let values = find_api_key_values(http_headers, self.loop_buffer.get_data());

            if !location.api_keys_auth_accepts(values.into_iter().flatten()) {
                crate::api_keys::register_rejection(
                    http_connection_info.connection_ip.get_ip_addr(),
                );
                return Err(ProxyServerError::NotAuthorized);
            }
        }

        if let Some(authorize) = endpoint_info.must_be_authorized() {
            match authorize {
                AuthorizationRequired::GoogleAuth(google_auth_settings) => {
                    let headers_reader = HttpHeadersReader {
                        http_headers,
                        payload: self.loop_buffer.get_data(),
                    };
                    let result = crate::google_auth::handle_google_auth(
                        &headers_reader,
                        google_auth_settings,
                        endpoint_info.debug,
                    )
                    .await;

                    match result {
                        Ok(ok_result) => match ok_result {
                            crate::google_auth::GoogleAuthOkResult::Passed(email) => {
                                return Ok(Some(HttpProxyPassIdentity::GoogleUser(email)));
                            }
                            crate::google_auth::GoogleAuthOkResult::SetToken(email) => {
                                let body = crate::google_auth::generate_authenticated_user(
                                    &headers_reader,
                                    email.as_str(),
                                );
                                let token = crate::google_auth::token::generate(email.as_str());
                                let cookie_value = format!(
                                    "{}={}; SameSite=None; Secure;",
                                    crate::consts::AUTHORIZED_COOKIE_NAME,
                                    token
                                );
                                return Err(ProxyServerError::HttpResponse(
                                    Http1ResponseBuilder::new_as_html()
                                        .add_header("Set-Cookie", cookie_value.as_str())
                                        .build_with_body(body.as_bytes()),
                                ));
                            }
                            crate::google_auth::GoogleAuthOkResult::ShowLoginPage(
                                google_auth_credentials,
                            ) => {
                                let body = crate::google_auth::generate_login_page(
                                    &headers_reader,
                                    &google_auth_credentials,
                                );
                                return Err(ProxyServerError::HttpResponse(
                                    Http1ResponseBuilder::new_as_html()
                                        .build_with_body(body.as_bytes()),
                                ));
                            }
                        },
                        Err(err) => {
                            let err = from_google_auth_error(err, &headers_reader);
                            return Err(err);
                        }
                    }
                }
                AuthorizationRequired::ClientCertificate => {
                    return Ok(cert_identity);
                }
            };
        }

        Ok(cert_identity)
    }
}

fn from_google_auth_error(
    value: GoogleAuthError,
    headers_reader: &impl crate::types::HttpRequestReader,
) -> ProxyServerError {
    match value {
        crate::google_auth::GoogleAuthError::ShowLogoutPage => {
            let body = crate::google_auth::generate_logout_page(
                headers_reader,
                "You have successfully logged out!",
            );
            ProxyServerError::HttpResponse(
                Http1ResponseBuilder::new_as_html().build_with_body(body.as_bytes()),
            )
        }
        crate::google_auth::GoogleAuthError::EmailDomainIsNotAuthorized => {
            ProxyServerError::NotAuthorized
        }
        crate::google_auth::GoogleAuthError::ShowEmailDomainIsNotAuthorizedPage => {
            let body = crate::google_auth::generate_logout_page(
                headers_reader,
                "Unauthorized email domain",
            );
            ProxyServerError::HttpResponse(
                Http1ResponseBuilder::new_as_html().build_with_body(body.as_bytes()),
            )
        }
        crate::google_auth::GoogleAuthError::ShowUserAuthenticatedPage(email) => {
            let body =
                crate::google_auth::generate_authenticated_user(headers_reader, email.as_str());
            ProxyServerError::HttpResponse(
                Http1ResponseBuilder::new_as_html().build_with_body(body.as_bytes()),
            )
        }
        crate::google_auth::GoogleAuthError::ShowError(err) => ProxyServerError::HttpResponse(
            Http1ResponseBuilder::new_as_html().build_with_body(err.as_bytes()),
        ),
    }
}
