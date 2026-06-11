use rumqttc::{AsyncClient, ConnectReturnCode, Event, MqttOptions, Packet, QoS, SubscribeReasonCode, Transport};
use serde_json::json;
use std::process::Child;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::timeout;

struct Broker {
    child: Child,
    tcp_port: u16,
    ws_port: u16,
    api_port: u16,
}

impl Drop for Broker {
    fn drop(&mut self) {
        let _ = self.child.kill();
    }
}

async fn start_broker(message_expiry_secs: u64, auto_subscribe: bool) -> Broker {
    let tcp_port = portpicker::pick_unused_port().unwrap();
    let ws_port = portpicker::pick_unused_port().unwrap();
    let api_port = portpicker::pick_unused_port().unwrap();
    let auth_port = portpicker::pick_unused_port().unwrap();
    let dir = std::env::temp_dir().join(format!("ciqadamq-test-{tcp_port}-{api_port}"));
    std::fs::create_dir_all(&dir).unwrap();
    let db_path = dir.join("users.db").to_string_lossy().replace('\\', "/");
    let cfg = format!(
        r#"
[mqtt]
tcp_addr = "127.0.0.1:{tcp_port}"
ws_addr = "127.0.0.1:{ws_port}"
message_expiry_secs = {message_expiry_secs}

[api]
addr = "127.0.0.1:{api_port}"
internal_auth_addr = "127.0.0.1:{auth_port}"
token = "test-token"

[db]
url = "sqlite://{db_path}"

[fanout]
auto_subscribe = {auto_subscribe}
"#
    );
    let cfg_path = dir.join("config.toml");
    std::fs::write(&cfg_path, cfg).unwrap();
    let child = std::process::Command::new(env!("CARGO_BIN_EXE_ciqadamq"))
        .arg(&cfg_path)
        .env("RUST_LOG_STYLE", "never")
        .env("NO_COLOR", "1")
        .spawn()
        .unwrap();
    let broker = Broker { child, tcp_port, ws_port, api_port };
    let http = reqwest::Client::new();
    let health_url = format!("http://127.0.0.1:{api_port}/health");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok(resp) = http.get(&health_url).send().await {
            if resp.status().is_success() {
                break;
            }
        }
        if tokio::time::Instant::now() > deadline {
            panic!("broker did not become healthy in 30s");
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    broker
}

async fn create_user(
    http: &reqwest::Client,
    api_port: u16,
    username: &str,
    userid: &str,
    password: &str,
    superuser: bool,
    admin: bool,
) {
    let resp = http
        .post(format!("http://127.0.0.1:{api_port}/api/v1/users"))
        .bearer_auth("test-token")
        .json(&json!({
            "username": username,
            "userid": userid,
            "password": password,
            "superuser": superuser,
            "admin": admin
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "creating {username}");
}

struct TestClient {
    client: AsyncClient,
    msgs: mpsc::UnboundedReceiver<(String, Vec<u8>)>,
    subacks: mpsc::UnboundedReceiver<Vec<SubscribeReasonCode>>,
}

async fn connect_opts(opts: MqttOptions, client_id: &str) -> TestClient {
    let (client, mut eventloop) = AsyncClient::new(opts, 32);
    let connack = timeout(Duration::from_secs(10), async {
        loop {
            match eventloop.poll().await {
                Ok(Event::Incoming(Packet::ConnAck(ack))) => return ack,
                Ok(_) => {}
                Err(e) => panic!("{client_id} connection failed: {e}"),
            }
        }
    })
    .await
    .expect("timed out waiting for connack");
    assert_eq!(connack.code, ConnectReturnCode::Success, "{client_id} not accepted");
    let (tx, rx) = mpsc::unbounded_channel();
    let (tx_sub, rx_sub) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        loop {
            match eventloop.poll().await {
                Ok(Event::Incoming(Packet::Publish(p))) => {
                    let _ = tx.send((p.topic.clone(), p.payload.to_vec()));
                }
                Ok(Event::Incoming(Packet::SubAck(s))) => {
                    let _ = tx_sub.send(s.return_codes.clone());
                }
                Ok(Event::Outgoing(rumqttc::Outgoing::Disconnect)) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
    TestClient { client, msgs: rx, subacks: rx_sub }
}

fn tcp_opts(port: u16, client_id: &str, username: &str, password: &str) -> MqttOptions {
    let mut opts = MqttOptions::new(client_id, "127.0.0.1", port);
    opts.set_credentials(username, password);
    opts.set_keep_alive(Duration::from_secs(10));
    opts
}

async fn connect(port: u16, client_id: &str, username: &str, password: &str) -> TestClient {
    connect_opts(tcp_opts(port, client_id, username, password), client_id).await
}

async fn connect_persistent(port: u16, client_id: &str, username: &str, password: &str) -> TestClient {
    let mut opts = tcp_opts(port, client_id, username, password);
    opts.set_clean_session(false);
    connect_opts(opts, client_id).await
}

async fn connect_ws(port: u16, client_id: &str, username: &str, password: &str) -> TestClient {
    let mut opts = MqttOptions::new(client_id, format!("ws://127.0.0.1:{port}/mqtt"), port);
    opts.set_transport(Transport::Ws);
    opts.set_credentials(username, password);
    opts.set_keep_alive(Duration::from_secs(10));
    connect_opts(opts, client_id).await
}

impl TestClient {
    async fn subscribe_expect(&mut self, topic: &str, expect_ok: bool) {
        self.client.subscribe(topic, QoS::AtLeastOnce).await.unwrap();
        let codes = timeout(Duration::from_secs(5), self.subacks.recv())
            .await
            .expect("timed out waiting for suback")
            .expect("suback channel closed");
        let ok = matches!(codes.first(), Some(SubscribeReasonCode::Success(_)));
        assert_eq!(ok, expect_ok, "subscription to {topic}: got {codes:?}");
    }

    async fn recv(&mut self) -> (String, Vec<u8>) {
        timeout(Duration::from_secs(5), self.msgs.recv())
            .await
            .expect("timed out waiting for message")
            .expect("client channel closed")
    }

    async fn expect_silence(&mut self) {
        if let Ok(Some((topic, _))) = timeout(Duration::from_secs(2), self.msgs.recv()).await {
            panic!("unexpected message on {topic}");
        }
    }
}

async fn expect_rejected(port: u16, client_id: &str, username: &str, password: &str) {
    let mut opts = MqttOptions::new(client_id, "127.0.0.1", port);
    opts.set_credentials(username, password);
    let (_client, mut eventloop) = AsyncClient::new(opts, 8);
    let outcome = timeout(Duration::from_secs(10), async {
        loop {
            match eventloop.poll().await {
                Ok(Event::Incoming(Packet::ConnAck(ack))) => return Ok(ack.code),
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
    })
    .await
    .expect("timed out waiting for auth rejection");
    match outcome {
        Ok(code) => assert_ne!(code, ConnectReturnCode::Success, "{client_id} unexpectedly accepted"),
        Err(rumqttc::ConnectionError::ConnectionRefused(code)) => {
            assert_ne!(code, ConnectReturnCode::Success)
        }
        Err(_) => {}
    }
}

#[tokio::test]
async fn end_to_end() {
    let broker = start_broker(1200, false).await;
    let http = reqwest::Client::new();
    let users_url = format!("http://127.0.0.1:{}/api/v1/users", broker.api_port);

    let resp = http
        .post(&users_url)
        .json(&json!({"username": "tok-user1", "userid": "u1001", "password": "pw-user1"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "request without token must be rejected");

    create_user(&http, broker.api_port, "tok-user1", "u1001", "pw-user1", false, false).await;
    create_user(&http, broker.api_port, "backend", "svc", "pw-backend", true, false).await;

    let resp = http
        .post(&users_url)
        .bearer_auth("test-token")
        .json(&json!({"username": "tok-user1", "userid": "u1001", "password": "other"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 409, "duplicate user must conflict");

    let resp = http
        .post(&users_url)
        .bearer_auth("test-token")
        .json(&json!({"username": "bad name", "userid": "u1", "password": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "username with whitespace must be rejected");

    let resp = http
        .post(&users_url)
        .bearer_auth("test-token")
        .json(&json!({"username": "ok-name", "userid": "bad/uid", "password": "x"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "userid with slash must be rejected");

    expect_rejected(broker.tcp_port, "intruder", "tok-user1", "wrong-password").await;
    expect_rejected(broker.tcp_port, "ghost", "nobody", "pw").await;

    let mut dev_a = connect(broker.tcp_port, "devA", "tok-user1", "pw-user1").await;
    let mut dev_b = connect(broker.tcp_port, "devB", "tok-user1", "pw-user1").await;
    let mut backend = connect(broker.tcp_port, "backend1", "backend", "pw-backend").await;

    dev_a.subscribe_expect("chat/u1001/m/all", true).await;
    dev_a.subscribe_expect("update/u1001/m/all", true).await;
    dev_a.subscribe_expect("fanout/all", true).await;
    dev_b.subscribe_expect("chat/u1001/m/all", true).await;
    dev_b.subscribe_expect("fanout/all", true).await;

    dev_a.subscribe_expect("chat/u9999/m/all", false).await;
    dev_a.subscribe_expect("#", false).await;
    dev_a.subscribe_expect("adminfanout/all", false).await;

    backend.subscribe_expect("chatsync", true).await;

    backend
        .client
        .publish("chat/u1001/m/all", QoS::AtLeastOnce, false, "chat-msg")
        .await
        .unwrap();
    let (topic_a, payload_a) = dev_a.recv().await;
    let (topic_b, payload_b) = dev_b.recv().await;
    assert_eq!(topic_a, "chat/u1001/m/all");
    assert_eq!(topic_b, "chat/u1001/m/all");
    assert_eq!(payload_a, b"chat-msg");
    assert_eq!(payload_b, b"chat-msg");

    backend
        .client
        .publish("update/u1001/m/all", QoS::AtLeastOnce, false, "update-msg")
        .await
        .unwrap();
    let (topic_a, payload_a) = dev_a.recv().await;
    assert_eq!(topic_a, "update/u1001/m/all");
    assert_eq!(payload_a, b"update-msg");
    dev_b.expect_silence().await;

    backend
        .client
        .publish("fanout/all", QoS::AtLeastOnce, false, "fanout-msg")
        .await
        .unwrap();
    let (topic_a, _) = dev_a.recv().await;
    let (topic_b, _) = dev_b.recv().await;
    assert_eq!(topic_a, "fanout/all");
    assert_eq!(topic_b, "fanout/all");

    dev_a
        .client
        .publish("chatsync", QoS::AtLeastOnce, false, "from-device")
        .await
        .unwrap();
    let (topic, payload) = backend.recv().await;
    assert_eq!(topic, "chatsync");
    assert_eq!(payload, b"from-device");

    let rogue = connect(broker.tcp_port, "rogue", "tok-user1", "pw-user1").await;
    rogue
        .client
        .publish("chat/u1001/m/all", QoS::AtLeastOnce, false, "forged")
        .await
        .unwrap();
    dev_a.expect_silence().await;
    dev_b.expect_silence().await;

    let resp = http
        .get(&users_url)
        .bearer_auth("test-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["users"],
        json!([
            {"username": "backend", "userid": "svc", "superuser": true, "admin": false},
            {"username": "tok-user1", "userid": "u1001", "superuser": false, "admin": false}
        ])
    );

    let resp = http
        .delete(format!("{users_url}/tok-user1"))
        .bearer_auth("test-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    expect_rejected(broker.tcp_port, "devC", "tok-user1", "pw-user1").await;

    let resp = http
        .delete(format!("{users_url}/tok-user1"))
        .bearer_auth("test-token")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn websocket_transport() {
    let broker = start_broker(1200, false).await;
    let http = reqwest::Client::new();

    create_user(&http, broker.api_port, "tok-ws", "u2000", "pw-ws", false, false).await;
    create_user(&http, broker.api_port, "wsbackend", "svc", "pw-b", true, false).await;

    let mut ws_dev = connect_ws(broker.ws_port, "wsdev", "tok-ws", "pw-ws").await;
    let mut backend = connect(broker.tcp_port, "backend2", "wsbackend", "pw-b").await;

    ws_dev.subscribe_expect("update/u2000/w/all", true).await;
    backend.subscribe_expect("chatsync", true).await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    backend
        .client
        .publish("update/u2000/w/all", QoS::AtLeastOnce, false, "to-ws")
        .await
        .unwrap();
    let (topic, payload) = ws_dev.recv().await;
    assert_eq!(topic, "update/u2000/w/all");
    assert_eq!(payload, b"to-ws");

    ws_dev
        .client
        .publish("chatsync", QoS::AtLeastOnce, false, "from-ws")
        .await
        .unwrap();
    let (topic, payload) = backend.recv().await;
    assert_eq!(topic, "chatsync");
    assert_eq!(payload, b"from-ws");
}

#[tokio::test]
async fn auto_subscribe_fanout() {
    let broker = start_broker(1200, true).await;
    let http = reqwest::Client::new();

    create_user(&http, broker.api_port, "tok-auto", "u4000", "pw-a", false, false).await;
    create_user(&http, broker.api_port, "autobackend", "svc", "pw-b", true, false).await;

    let mut dev_a = connect(broker.tcp_port, "adevA", "tok-auto", "pw-a").await;
    let mut dev_b = connect(broker.tcp_port, "adevB", "tok-auto", "pw-a").await;
    let backend = connect(broker.tcp_port, "backend3", "autobackend", "pw-b").await;
    tokio::time::sleep(Duration::from_millis(500)).await;

    backend
        .client
        .publish("chat/u4000/m/all", QoS::AtLeastOnce, false, "auto-chat")
        .await
        .unwrap();
    let (topic_a, payload_a) = dev_a.recv().await;
    let (topic_b, _) = dev_b.recv().await;
    assert_eq!(topic_a, "chat/u4000/m/all");
    assert_eq!(topic_b, "chat/u4000/m/all");
    assert_eq!(payload_a, b"auto-chat");

    backend
        .client
        .publish("fanout/all", QoS::AtLeastOnce, false, "auto-fanout")
        .await
        .unwrap();
    let (topic_a, _) = dev_a.recv().await;
    let (topic_b, _) = dev_b.recv().await;
    assert_eq!(topic_a, "fanout/all");
    assert_eq!(topic_b, "fanout/all");
}

#[tokio::test]
async fn offline_messages_expire() {
    let broker = start_broker(2, false).await;
    let http = reqwest::Client::new();

    create_user(&http, broker.api_port, "tok-e", "u3000", "pw-e", false, false).await;
    create_user(&http, broker.api_port, "epub", "svc", "pw-p", true, false).await;

    let publisher = connect(broker.tcp_port, "epub1", "epub", "pw-p").await;

    let mut dev_e = connect_persistent(broker.tcp_port, "devE", "tok-e", "pw-e").await;
    dev_e.subscribe_expect("chat/u3000/m/all", true).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    dev_e.client.disconnect().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    publisher
        .client
        .publish("chat/u3000/m/all", QoS::AtLeastOnce, false, "queued-msg")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut dev_e = connect_persistent(broker.tcp_port, "devE", "tok-e", "pw-e").await;
    let (topic, payload) = dev_e.recv().await;
    assert_eq!(topic, "chat/u3000/m/all");
    assert_eq!(payload, b"queued-msg");

    dev_e.client.disconnect().await.unwrap();
    tokio::time::sleep(Duration::from_millis(300)).await;

    publisher
        .client
        .publish("chat/u3000/m/all", QoS::AtLeastOnce, false, "expired-msg")
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(4)).await;

    let mut dev_e = connect_persistent(broker.tcp_port, "devE", "tok-e", "pw-e").await;
    dev_e.expect_silence().await;
}
