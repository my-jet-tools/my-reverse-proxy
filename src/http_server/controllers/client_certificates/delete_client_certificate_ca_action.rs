use my_http_server::{
    macros::{http_route, MyHttpInput, MyHttpObjectStructure},
    HttpContext, HttpFailResult, HttpOkResult, HttpOutput,
};
use serde::Serialize;

use crate::configurations::SslCertificateIdRef;

#[http_route(
    method: "DELETE",
    route: "/api/ClientCertificates/Ca",
    summary: "Drop a loaded client certificate ca",
    description: "Removes the client certificate ca loaded under this id from the running proxy - the undo for a wrong upload, since a manually provided ca has no source to re-read. The endpoints requiring it go back to cutting every TLS connection until a ca is provided again: this NEVER opens an endpoint up, it closes it. A ca that has a configured 'ca:' source comes back on the next RefreshCaCertificate or settings reload; a manually uploaded one has to be uploaded again.",
    controller: "ClientCertificates",
    input_data: DeleteClientCertificateCaHttpInput,
    result:[
        {status_code: 200, description: "The ca was dropped", model:"DeleteClientCertificateCaResultHttpModel"},
        {status_code: 404, description: "No client certificate ca loaded under this id"},
    ]
)]
pub struct DeleteClientCertificateCaAction;

async fn handle_request(
    _action: &DeleteClientCertificateCaAction,
    input_data: DeleteClientCertificateCaHttpInput,
    _ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let ca_id = input_data.ca_id.trim();

    // Named before the removal, so the answer says which endpoints stop verifying clients.
    let endpoints: Vec<String> = crate::scripts::get_client_ca_endpoints_status()
        .await
        .into_iter()
        .filter(|endpoint| endpoint.ca_id == ca_id)
        .map(|endpoint| endpoint.endpoint_host)
        .collect();

    let removed = crate::app::APP_CTX
        .ssl_certificates_cache
        .write_with_result(|config| config.client_ca.remove(SslCertificateIdRef::new(ca_id)))
        .await;

    if !removed {
        return HttpFailResult::as_not_found(
            format!("No client certificate ca loaded under id '{}'", ca_id),
            false,
        )
        .into_err();
    }

    println!(
        "Client certificate ca '{}' has been dropped. Endpoints cutting connections until it is provided again: [{}]",
        ca_id,
        endpoints.join(", ")
    );

    let model = DeleteClientCertificateCaResultHttpModel {
        ca_id: ca_id.to_string(),
        endpoints,
    };

    HttpOutput::as_json(model).into_ok_result(true)
}

#[derive(MyHttpInput)]
pub struct DeleteClientCertificateCaHttpInput {
    #[http_query(name = "caId", description = "Id of the client certificate ca to drop")]
    pub ca_id: String,
}

#[derive(Debug, Serialize, MyHttpObjectStructure)]
pub struct DeleteClientCertificateCaResultHttpModel {
    pub ca_id: String,
    // Endpoints that required this ca and now cut every TLS connection.
    pub endpoints: Vec<String>,
}
