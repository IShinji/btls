use std::sync::{Arc, Mutex};

use crate::ec::{EcGroup, EcKey};
use crate::nid::Nid;
use crate::pkey::{PKey, Private};
use crate::ssl::test::server::Server;
use crate::ssl::ExtensionType;

fn key_for_curve(nid: Nid) -> PKey<Private> {
    let group = EcGroup::from_curve_name(nid).unwrap();
    PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap()
}

/// Connects a client to a loopback server and returns whether the ClientHello carried the
/// Channel ID extension (30032).
fn client_hello_has_channel_id(key: Option<&PKey<Private>>) -> bool {
    let seen = Arc::new(Mutex::new(None));

    let mut server = Server::builder();
    server.ctx().set_select_certificate_callback({
        let seen = Arc::clone(&seen);
        move |client_hello| {
            *seen.lock().unwrap() = Some(
                client_hello
                    .get_extension(ExtensionType::CHANNEL_ID)
                    .is_some(),
            );
            Ok(())
        }
    });
    let server = server.build();

    let mut client = server.client().build().builder();
    if let Some(key) = key {
        client.ssl().set_channel_id(key).unwrap();
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
fn channel_id_extension_not_sent_by_default() {
    assert!(!client_hello_has_channel_id(None));
}

#[test]
fn channel_id_extension_sent_when_key_set() {
    let key = key_for_curve(Nid::X9_62_PRIME256V1);
    assert!(client_hello_has_channel_id(Some(&key)));
}

#[test]
fn channel_id_rejects_non_p256_key() {
    let server = Server::builder().build();
    let key = key_for_curve(Nid::SECP384R1);

    let mut client = server.client().build().builder();
    assert!(client.ssl().set_channel_id(&key).is_err());

    // The server thread is waiting for a connection; let it finish.
    client.connect();
}
