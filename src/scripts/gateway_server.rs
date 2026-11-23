use crate::{
    app::APP_CTX,
    secure::{GatewayServerInput, SecureStoreError, StoredGatewayServer},
};

/// Runs the gateway server `input` says, in place of the one of the store which runs, and keeps
/// it in the secure store. It is started first: a port which can not be had is refused with the
/// store as it was, and the server there was goes on.
pub async fn set_gateway_server(
    input: GatewayServerInput,
) -> Result<StoredGatewayServer, SecureStoreError> {
    let server = input.check().map_err(SecureStoreError::Invalid)?;

    if !APP_CTX.secure.is_initialized() {
        return Err(SecureStoreError::NotInitialized);
    }

    let authorized_keys = &APP_CTX.secure.gateway_authorized_keys;
    let mut change = APP_CTX.gateway_server.change().await;

    change
        .apply(Some(&server), authorized_keys)
        .await
        .map_err(SecureStoreError::Conflict)?;

    if let Err(err) = APP_CTX.secure.set_gateway_server(server.clone()).await {
        // Not kept: what the store keeps runs, as it will after a restart.
        let kept = APP_CTX.secure.gateway_server();

        if let Err(again) = change.apply(kept.as_ref(), authorized_keys).await {
            println!("Gateway server of the secure store does not start again: {again}");
        }

        return Err(err);
    }

    Ok(server)
}

/// Removes the gateway server from the store and stops it: its port is closed, and the
/// connections of its clients with it. `false`: the store had none.
pub async fn delete_gateway_server() -> Result<bool, SecureStoreError> {
    let mut change = APP_CTX.gateway_server.change().await;

    // The store first: one which can not be written leaves the server running, as it will run
    // after a restart.
    let deleted = APP_CTX.secure.delete_gateway_server().await?;

    change
        .apply(None, &APP_CTX.secure.gateway_authorized_keys)
        .await
        .map_err(SecureStoreError::Conflict)?;

    Ok(deleted)
}

/// Right after initialize: the gateway server of the store is started.
pub async fn start_gateway_server_of_store() {
    let server = APP_CTX.secure.gateway_server();

    let mut change = APP_CTX.gateway_server.change().await;

    match change
        .apply(server.as_ref(), &APP_CTX.secure.gateway_authorized_keys)
        .await
    {
        Ok(()) => {
            if let Some(server) = server.as_ref() {
                println!(
                    "Gateway server of the secure store runs at port {}",
                    server.port
                );
            }
        }
        Err(err) => println!("Gateway server of the secure store is not started: {err}"),
    }
}

/// The gateway server which runs.
pub struct RunningGatewayServer {
    /// `true` - the one of the secure store; `false` - the one of the settings.
    pub from_secure_store: bool,
    pub listen: String,
    /// The gateway names of the clients connected now, in order.
    pub clients: Vec<String>,
}

pub async fn running_gateway_server() -> Option<RunningGatewayServer> {
    let server = APP_CTX.gateway_server.get()?;

    let mut clients: Vec<String> = server
        .get_gateway_connections()
        .iter()
        .map(|connection| connection.get_gateway_id().to_string())
        .collect();
    clients.sort();

    Some(RunningGatewayServer {
        from_secure_store: APP_CTX.gateway_server.settings_server().is_none(),
        listen: server.listen_addr().to_string(),
        clients,
    })
}
