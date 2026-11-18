use my_http_server::{macros::http_route, HttpContext, HttpFailResult, HttpOkResult, HttpOutput};

/// The two answers, word for word.
const INITIALIZED: &str = "True";
const NOT_INITIALIZED: &str = "False";

#[http_route(
    method: "GET",
    route: "/api/initialize",
    summary: "Whether the proxy is initialized",
    description: "`True` once `POST /api/initialize` has opened the secure store with the files key in this process, `False` after every start until then. It takes no key and says nothing about the keys: it is how whoever runs the proxy, or a script watching it, knows that the files key has to be given. See docs/secure-parameters.md.",
    controller: "Initialize",
    result:[
        {status_code: 200, description: "`True` or `False`"},
    ]
)]
pub struct IsInitializedAction;

async fn handle_request(
    _action: &IsInitializedAction,
    _ctx: &HttpContext,
) -> Result<HttpOkResult, HttpFailResult> {
    let answer = if crate::app::APP_CTX.secure.is_initialized() {
        INITIALIZED
    } else {
        NOT_INITIALIZED
    };

    HttpOutput::as_text(answer.to_string()).into_ok_result(true)
}
