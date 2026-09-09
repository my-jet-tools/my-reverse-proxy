use my_http_server::{
    macros::{http_route, MyHttpInput, MyHttpObjectStructure},
    HttpContext, HttpFailResult, HttpOkResult, HttpOutput,
};
use serde::Serialize;

#[http_route(
    method: "GET",
    route: "/api/ClientCertificates/Ca",
    summary: "Get metadata of a loaded client certificate ca",
    description: "Returns metadata (CN, expiry, origin, whether it is a real CA certificate, and how many revoked serials its CRL carries) of the client certificate ca currently loaded under the given id. The raw CA PEM material is never returned.",
    controller: "ClientCertificates",
    input_data: GetClientCertificateCaHttpInput,
    result:[
        {status_code: 200, description: "Ok response", model:"ClientCertificateCaHttpModel"},
        {status_code: 404, description: "No client certificate ca loaded under this id"},
    ]
)]
pub struct GetClientCertificateCaAction;

async fn handle_request(
    _action: &GetClientCertificateCaAction,
    input_data: GetClientCertificateCaHttpInput,
    _ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let details = crate::scripts::get_client_ca_details(&input_data.ca_id)
        .await
        .ok_or_else(|| {
            HttpFailResult::as_not_found(
                format!(
                    "No client certificate ca loaded under id '{}'",
                    input_data.ca_id.trim()
                ),
                false,
            )
        })?;

    let model = ClientCertificateCaHttpModel {
        id: details.id,
        cn: details.cn,
        expires: details.expires.to_rfc3339(),
        is_ca: details.is_ca,
        expired: details.expired,
        origin: details.origin,
        crl_records: details.crl_records,
    };

    HttpOutput::as_json(model).into_ok_result(true).into()
}

#[derive(MyHttpInput)]
pub struct GetClientCertificateCaHttpInput {
    #[http_query(name = "caId", description = "Id of the client certificate ca")]
    pub ca_id: String,
}

#[derive(Debug, Serialize, MyHttpObjectStructure)]
pub struct ClientCertificateCaHttpModel {
    pub id: String,
    pub cn: String,
    pub expires: String,
    pub is_ca: bool,
    pub expired: bool,
    pub origin: String,
    pub crl_records: usize,
}
