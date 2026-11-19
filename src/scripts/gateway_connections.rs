use crate::{
    app::APP_CTX,
    secure::{GatewayConnectionInput, SecureStoreError, StoredGatewayConnection},
};

/// Keeps a connection to a gateway in the secure store - in place of the one of its id - and
/// starts its client, in place of the one there was. The encrypted API and MCP both come here.
pub async fn set_gateway_connection(
    input: GatewayConnectionInput,
) -> Result<StoredGatewayConnection, SecureStoreError> {
    let connection = input.check().map_err(SecureStoreError::Invalid)?;

    if APP_CTX.gateway_clients.is_from_settings(&connection.id) {
        return Err(SecureStoreError::Conflict(format!(
            "The settings have a gateway client '{}': a connection of the secure store takes another id",
            connection.id
        )));
    }

    APP_CTX
        .secure
        .set_gateway_connection(connection.clone())
        .await?;

    apply_gateway_connections_of_store();

    Ok(connection)
}

/// Removes the connection `id` from the store and stops its client: its gateway connection, and
/// everything tunnelled through it, are closed. `false`: there was no such connection.
pub async fn delete_gateway_connection(id: &str) -> Result<bool, SecureStoreError> {
    let deleted = APP_CTX.secure.delete_gateway_connection(id.trim()).await?;

    if deleted {
        apply_gateway_connections_of_store();
    }

    Ok(deleted)
}

/// Starts and stops the clients of the store to match its connections.
pub fn apply_gateway_connections_of_store() {
    APP_CTX.gateway_clients.apply_store_connections(
        &APP_CTX.secure.gateway_connections(),
        &APP_CTX.secure.private_keys,
    );
}

/// A connection of the store, and whether its gateway connection is up now.
pub struct GatewayConnectionState {
    pub connection: StoredGatewayConnection,
    pub connected: bool,
}

/// The connections of the store, by their ids in order.
pub fn list_gateway_connections() -> Vec<GatewayConnectionState> {
    APP_CTX
        .secure
        .gateway_connections()
        .into_iter()
        .map(|connection| GatewayConnectionState {
            connected: APP_CTX
                .gateway_clients
                .is_store_client_connected(&connection.id),
            connection,
        })
        .collect()
}
