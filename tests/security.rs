//! Security regression tests (M4): base_url confinement, redirect policy,
//! decoded response-size cap, and the egress guard — all against real local
//! HTTP servers.

use std::io::Write;

use armature_http_client::egress::{EgressError, EgressPolicy};
use armature_http_client::{HttpClient, HttpClientConfig, HttpClientError};
use wiremock::{Mock, MockServer, ResponseTemplate, matchers};

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::best());
    enc.write_all(data).unwrap();
    enc.finish().unwrap()
}

async fn gzip_bomb_server(decoded_len: usize) -> MockServer {
    let server = MockServer::start().await;
    let compressed = gzip(&vec![0u8; decoded_len]);
    assert!(
        compressed.len() < 64 * 1024,
        "the bomb must be small on the wire"
    );
    Mock::given(matchers::path("/bomb"))
        .respond_with(
            ResponseTemplate::new(200)
                .insert_header("content-encoding", "gzip")
                .set_body_raw(compressed, "application/octet-stream"),
        )
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn gzip_bomb_is_cut_off_at_the_decoded_size_limit() {
    // 32 MiB of zeros compresses to ~32 KiB; the default cap is 10 MiB.
    let server = gzip_bomb_server(32 * 1024 * 1024).await;
    let client = HttpClient::new(HttpClientConfig::default());
    let err = client
        .get(format!("{}/bomb", server.uri()))
        .send()
        .await
        .unwrap_err();
    assert!(
        matches!(err, HttpClientError::ResponseTooLarge { limit } if limit == 10 * 1024 * 1024),
        "got {err:?}"
    );
}

#[tokio::test]
async fn decoded_body_within_a_raised_limit_is_returned() {
    let server = gzip_bomb_server(2 * 1024 * 1024).await;
    let config = HttpClientConfig::builder()
        .max_response_size(4 * 1024 * 1024)
        .build();
    let response = HttpClient::new(config)
        .get(format!("{}/bomb", server.uri()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.bytes().len(), 2 * 1024 * 1024);
}

#[tokio::test]
async fn plain_body_over_the_limit_is_refused() {
    let server = MockServer::start().await;
    Mock::given(matchers::path("/big"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'a'; 2048]))
        .mount(&server)
        .await;
    let config = HttpClientConfig::builder().max_response_size(1024).build();
    let err = HttpClient::new(config)
        .get(format!("{}/big", server.uri()))
        .send()
        .await
        .unwrap_err();
    assert!(matches!(
        err,
        HttpClientError::ResponseTooLarge { limit: 1024 }
    ));
}

async fn redirecting_server(to: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(matchers::path("/r"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", to))
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn redirects_are_not_followed_by_default() {
    let server = redirecting_server("http://169.254.169.254/latest/meta-data/").await;
    let response = HttpClient::new(HttpClientConfig::default())
        .get(format!("{}/r", server.uri()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 302);
}

#[tokio::test]
async fn cross_origin_redirect_is_refused_unless_allowed() {
    let target = MockServer::start().await;
    Mock::given(matchers::path("/landing"))
        .respond_with(ResponseTemplate::new(200).set_body_string("landed"))
        .mount(&target)
        .await;
    // A different port is a different origin.
    let server = redirecting_server(&format!("{}/landing", target.uri())).await;

    let config = HttpClientConfig::builder().follow_redirects(true).build();
    let err = HttpClient::new(config)
        .get(format!("{}/r", server.uri()))
        .header("X-Api-Key", "secret")
        .send()
        .await
        .unwrap_err();
    assert!(
        matches!(err, HttpClientError::RedirectRefused(_)),
        "got {err:?}"
    );

    let config = HttpClientConfig::builder()
        .follow_redirects(true)
        .allow_cross_origin_redirects(true)
        .build();
    let response = HttpClient::new(config)
        .get(format!("{}/r", server.uri()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.text().unwrap(), "landed");
}

#[tokio::test]
async fn same_origin_redirect_is_followed_when_enabled() {
    let server = MockServer::start().await;
    Mock::given(matchers::path("/r"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "/landing"))
        .mount(&server)
        .await;
    Mock::given(matchers::path("/landing"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    let config = HttpClientConfig::builder().follow_redirects(true).build();
    let response = HttpClient::new(config)
        .get(format!("{}/r", server.uri()))
        .send()
        .await
        .unwrap();
    assert_eq!(response.text().unwrap(), "ok");
}

#[tokio::test]
async fn https_only_refuses_http() {
    let config = HttpClientConfig::builder().https_only(true).build();
    let err = HttpClient::new(config)
        .get("http://example.com/")
        .send()
        .await
        .unwrap_err();
    assert!(matches!(err, HttpClientError::InvalidUrl(_)), "got {err:?}");
}

#[tokio::test]
async fn base_url_cannot_be_escaped_with_an_authority_path() {
    let server = MockServer::start().await;
    let config = HttpClientConfig::builder().base_url(server.uri()).build();
    let client = HttpClient::new(config);
    for path in [
        "//169.254.169.254/latest/meta-data/",
        "https://169.254.169.254/",
        "\\\\169.254.169.254/",
    ] {
        let err = client.get(path).send().await.unwrap_err();
        assert!(
            matches!(err, HttpClientError::InvalidUrl(_)),
            "{path}: {err:?}"
        );
    }
}

#[tokio::test]
async fn egress_policy_refuses_internal_targets() {
    let server = MockServer::start().await;
    Mock::given(matchers::any())
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;

    let config = HttpClientConfig::builder()
        .egress_policy(EgressPolicy::default())
        .build();
    let client = HttpClient::new(config);
    for url in [
        server.uri(),
        "https://169.254.169.254/latest/meta-data/".to_string(),
        "https://[::ffff:10.0.0.1]/".to_string(),
        "https://metadata.google.internal/".to_string(),
    ] {
        let err = client.get(&url).send().await.unwrap_err();
        assert!(matches!(err, HttpClientError::Egress(_)), "{url}: {err:?}");
    }
    assert!(server.received_requests().await.unwrap().is_empty());

    // The explicit loopback opt-in reaches the local stub.
    let config = HttpClientConfig::builder()
        .egress_policy(EgressPolicy::default().allow_insecure_loopback(true))
        .build();
    let response = HttpClient::new(config)
        .get(server.uri())
        .send()
        .await
        .unwrap();
    assert!(response.is_success());
}

#[tokio::test]
async fn egress_policy_rechecks_every_redirect_hop() {
    let server = redirecting_server("https://169.254.169.254/latest/meta-data/").await;
    let config = HttpClientConfig::builder()
        .egress_policy(EgressPolicy::default().allow_insecure_loopback(true))
        .follow_redirects(true)
        .allow_cross_origin_redirects(true)
        .build();
    let err = HttpClient::new(config)
        .get(format!("{}/r", server.uri()))
        .send()
        .await
        .unwrap_err();
    assert!(
        matches!(err, HttpClientError::Egress(EgressError::InternalAddress)),
        "got {err:?}"
    );
}
