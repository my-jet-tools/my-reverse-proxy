use mcp_server_middleware::*;
use serde::*;

use super::GatewayConnectionMcpModel;

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct GetGatewayConnectionsInputData {}

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct GetGatewayConnectionsResponse {
    #[property(description = "The connections of the secure store, by the ids in order.")]
    pub gateway_connections: Vec<GatewayConnectionMcpModel>,
}

pub struct GetGatewayConnectionsHandler;

impl ToolDefinition for GetGatewayConnectionsHandler {
    const FUNC_NAME: &'static str = "get_gateway_connections";
    const DESCRIPTION: &'static str = "The connections to gateways kept in the secure store - set with set_gateway_connection or over the encrypted API - and whether each is connected now. The gateway clients of the settings files are not here (get_settings lists their ids). Empty before the proxy is initialized. Reading is never gated.";
}

#[async_trait::async_trait]
impl McpToolCall<GetGatewayConnectionsInputData, GetGatewayConnectionsResponse>
    for GetGatewayConnectionsHandler
{
    async fn execute_tool_call(
        &self,
        _model: GetGatewayConnectionsInputData,
    ) -> Result<GetGatewayConnectionsResponse, String> {
        let gateway_connections = crate::scripts::list_gateway_connections()
            .into_iter()
            .map(|itm| GatewayConnectionMcpModel::new(itm.connection, itm.connected))
            .collect();

        Ok(GetGatewayConnectionsResponse {
            gateway_connections,
        })
    }
}
