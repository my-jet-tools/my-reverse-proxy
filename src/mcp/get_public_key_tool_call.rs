use mcp_server_middleware::*;
use serde::*;

use super::PublicKeyMcpModel;

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct GetPublicKeyInputData {
    #[property(
        description = "Id of a private key of the secure store. Left out - the public keys of every private key."
    )]
    pub id: Option<String>,
}

#[derive(ApplyJsonSchema, Debug, Serialize, Deserialize)]
pub struct GetPublicKeyResponse {
    #[property(description = "The public keys, by the ids in order.")]
    pub public_keys: Vec<PublicKeyMcpModel>,
}

pub struct GetPublicKeyHandler;

impl ToolDefinition for GetPublicKeyHandler {
    const FUNC_NAME: &'static str = "get_public_key";
    const DESCRIPTION: &'static str = "The public key of a private key of the secure store, in OpenSSH form (`ssh-ed25519 AAAA...`) - what the proxy which runs the gateway server lets in, with set_gateway_authorized_key or a line of its authorized_keys file. Without `id`, the public keys of every private key: which ids exist. A private key itself is never given over MCP. Reading is never gated.";
}

#[async_trait::async_trait]
impl McpToolCall<GetPublicKeyInputData, GetPublicKeyResponse> for GetPublicKeyHandler {
    async fn execute_tool_call(
        &self,
        model: GetPublicKeyInputData,
    ) -> Result<GetPublicKeyResponse, String> {
        let secure = &crate::app::APP_CTX.secure;

        if !secure.is_initialized() {
            return Err(crate::secure::SecureStoreError::NotInitialized.message());
        }

        let public_keys = match model.id.as_deref().map(str::trim) {
            Some(id) => {
                let key = secure
                    .private_keys
                    .get(id)
                    .ok_or_else(|| format!("The secure store has no private key '{id}'"))?;

                vec![PublicKeyMcpModel {
                    id: id.to_string(),
                    public_key: crate::secure::openssh_public_key(&key),
                }]
            }
            None => secure
                .private_keys
                .list()
                .into_iter()
                .map(|(id, key)| PublicKeyMcpModel {
                    public_key: crate::secure::openssh_public_key(&key),
                    id,
                })
                .collect(),
        };

        Ok(GetPublicKeyResponse { public_keys })
    }
}
