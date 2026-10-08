use std::sync::{Arc, Mutex};

use crate::ssl::test::server::Server;
use crate::ssl::ExtensionType;

/// Connects a client to a loopback server and returns the payload of the Next Protocol
/// Negotiation extension (13172) from the ClientHello, or `None` if it was not sent.
fn client_hello_npn(enable: bool) -> Option<Vec<u8>> {
    let seen = Arc::new(Mutex::new(None));

    let mut server = Server::builder();
    server.ctx().set_select_certificate_callback({
        let seen = Arc::clone(&seen);
        move |client_hello| {
            *seen.lock().unwrap() = Some(
                client_hello
                    .get_extension(ExtensionType::NEXT_PROTO_NEG)
                    .map(ToOwned::to_owned),
            );
            Ok(())
        }
    });
    let server = server.build();

    let mut client = server.client();
    if enable {
        client.ctx().enable_npn_extension();
    }
    client.connect();

    let result = seen
        .lock()
        .unwrap()
        .take()
        .expect("server should have seen a ClientHello");
    result
}

#[test]
fn npn_extension_not_sent_by_default() {
    assert_eq!(client_hello_npn(false), None);
}

#[test]
fn npn_extension_sent_empty_when_enabled() {
    // The extension is offered with an empty payload, and the handshake still completes
    // against a server that does not implement NPN.
    assert_eq!(client_hello_npn(true), Some(Vec::new()));
}
