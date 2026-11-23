use mcp_server_middleware::*;
use serde::*;

use super::AuthorizedKeyMcpModel;

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct GetGatewayAuthorizedKeysInputData {}

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct GetGatewayAuthorizedKeysResponse {
    #[property(description = "Whether this proxy runs a gateway server at all.")]
    pub gateway_server: bool,

    #[property(
        description = "The public keys of the secure store the gateway server lets in, by the ids in order: each under its gateway name, from its ip_white_list."
    )]
    pub authorized_keys: Vec<AuthorizedKeyMcpModel>,
}

pub struct GetGatewayAuthorizedKeysHandler;

impl ToolDefinition for GetGatewayAuthorizedKeysHandler {
    const FUNC_NAME: &'static str = "get_gateway_authorized_keys";
    const DESCRIPTION: &'static str = "The public keys kept in the secure store which the gateway server of this proxy lets in - set with set_gateway_authorized_key or over the encrypted API - each under its gateway name (the id) and from its ip_white_list only. The keys of the authorized_keys files of the settings count too and are not listed here. Empty before the proxy is initialized. Reading is never gated.";
}

#[async_trait::async_trait]
impl McpToolCall<GetGatewayAuthorizedKeysInputData, GetGatewayAuthorizedKeysResponse>
    for GetGatewayAuthorizedKeysHandler
{
    async fn execute_tool_call(
        &self,
        _model: GetGatewayAuthorizedKeysInputData,
    ) -> Result<GetGatewayAuthorizedKeysResponse, String> {
        let authorized_keys = crate::app::APP_CTX
            .secure
            .gateway_authorized_keys
            .list()
            .iter()
            .map(|itm| AuthorizedKeyMcpModel {
                id: itm.id.clone(),
                public_key: crate::secure::openssh_verifying_key(&itm.key),
                ip_white_list: itm.ip_white_list.clone(),
            })
            .collect();

        Ok(GetGatewayAuthorizedKeysResponse {
            gateway_server: crate::app::APP_CTX.gateway_server.get().is_some(),
            authorized_keys,
        })
    }
}
