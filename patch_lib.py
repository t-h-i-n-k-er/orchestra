import sys
content = open('agent/src/lib.rs').read()

old1 = '''        info!("Agent started, waiting for commands...");
        loop {
            let msg = {
                let mut transport = self.transport.lock().await;
                transport.recv().await
            };
            match msg {
                Ok(Message::TaskRequest {
                    task_id,
                    command,
                    operator_id,
                }) => {
                    info!("Received command: {:?}", command);
                    let crypto = self.crypto.clone();
                    let config = self.config.clone();
                    let transport = self.transport.clone();
                    tokio::spawn(async move {'''

new1 = '''        info!("Agent started, waiting for commands...");
        let mut tasks = tokio::task::JoinSet::new();

        loop {
            let msg_fut = async {
                let mut transport = self.transport.lock().await;
                transport.recv().await
            };

            let msg = tokio::select! {
                res = msg_fut => res,
                _ = crate::handlers::SHUTDOWN_NOTIFY.notified() => {
                    info!("Shutdown signal received, draining tasks and shutting down.");
                    break;
                }
            };

            match msg {
                Ok(Message::TaskRequest {
                    task_id,
                    command,
                    operator_id,
                }) => {
                    info!("Received command: {:?}", command);
                    let crypto = self.crypto.clone();
                    let config = self.config.clone();
                    let transport = self.transport.clone();
                    tasks.spawn(async move {'''

content = content.replace(old1, new1)

old2 = '''                Err(e) => {
                    error!("Transport error: {}", e);
                    // Return the error so the caller (e.g. outbound reconnect
                    // loop) can detect disconnection and re-establish the
                    // session, rather than spinning forever on a dead socket.
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}'''

new2 = '''                Err(e) => {
                    error!("Transport error: {}", e);
                    // Drain tasks before returning error
                    while let Some(_) = tasks.join_next().await {}
                    return Err(e);
                }
            }
        }

        while let Some(_) = tasks.join_next().await {}
        Ok(())
    }
}'''

content = content.replace(old2, new2)

open('agent/src/lib.rs', 'w').write(content)
