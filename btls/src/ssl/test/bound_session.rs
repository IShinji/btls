use std::sync::{Arc, Mutex};

use crate::ssl::test::server::Server;
use crate::ssl::{BoundSession, SslSessionCacheMode};

#[test]
fn bound_session_resumes_on_same_context_only() {
    let mut server = Server::builder();
    server.expected_connections_count(3);
    let server = server.build();

    let bound = Arc::new(Mutex::new(None));

    let mut client = server.client();
    client
        .ctx()
        .set_session_cache_mode(SslSessionCacheMode::CLIENT);
    client.ctx().set_new_session_callback({
        let bound = Arc::clone(&bound);
        move |ssl, session| {
            bound
                .lock()
                .unwrap()
                .get_or_insert_with(|| BoundSession::new(ssl, session));
        }
    });
    let client = client.build();

    // First connection: full handshake, which hands out a session.
    let first = client.builder().connect();
    assert!(!first.ssl().session_reused());
    let bound = bound
        .lock()
        .unwrap()
        .take()
        .expect("client should have received a session");

    // Same context: the session is accepted and the connection resumes.
    let mut same = client.builder();
    assert!(same.ssl().set_bound_session(&bound).unwrap());
    assert!(same.ssl().session().is_some());
    let same = same.connect();
    assert!(same.ssl().session_reused());

    // A different context: refused, and the connection is left unchanged.
    let other = server.client().build();
    let mut different = other.builder();
    assert!(!different.ssl().set_bound_session(&bound).unwrap());
    assert!(different.ssl().session().is_none());
    let different = different.connect();
    assert!(!different.ssl().session_reused());
}
