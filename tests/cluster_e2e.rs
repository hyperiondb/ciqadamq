use rumqttc::{
    AsyncClient, ConnectReturnCode, Event, MqttOptions, Packet, QoS, SubscribeReasonCode,
};
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::time::timeout;

fn nodes() -> Vec<(String, u16)> {
    std::env::var("CLUSTER_NODES")
        .unwrap_or_else(|_| "127.0.0.1:1883,127.0.0.1:1884,127.0.0.1:1885".into())
        .split(',')
        .map(|s| {
            let (h, p) = s
                .trim()
                .rsplit_once(':')
                .expect("node addr must be host:port");
            (h.to_string(), p.parse().expect("invalid port"))
        })
        .collect()
}

fn api_bases() -> Vec<String> {
    std::env::var("CLUSTER_APIS")
        .unwrap_or_else(|_| {
            "http://127.0.0.1:8090,http://127.0.0.1:8091,http://127.0.0.1:8092".into()
        })
        .split(',')
        .map(|s| s.trim().to_string())
        .collect()
}

fn token() -> String {
    std::env::var("API_TOKEN").unwrap_or_else(|_| "change-me".into())
}

fn unique(prefix: &str) -> String {
    let n = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis();
    format!("{prefix}{n}")
}

struct TestClient {
    client: AsyncClient,
    msgs: mpsc::UnboundedReceiver<(String, Vec<u8>)>,
    subacks: mpsc::UnboundedReceiver<Vec<SubscribeReasonCode>>,
}

async fn try_connect(
    node: &(String, u16),
    client_id: &str,
    username: &str,
    password: &str,
) -> Result<TestClient, String> {
    let mut opts = MqttOptions::new(client_id, &node.0, node.1);
    opts.set_credentials(username, password);
    opts.set_keep_alive(Duration::from_secs(10));
    let (client, mut eventloop) = AsyncClient::new(opts, 32);
    let connack = timeout(Duration::from_secs(15), async {
        loop {
            match eventloop.poll().await {
                Ok(Event::Incoming(Packet::ConnAck(ack))) => return Ok(ack),
                Ok(_) => {}
                Err(e) => return Err(format!("{e}")),
            }
        }
    })
    .await
    .map_err(|_| "timed out waiting for connack".to_string())??;
    if connack.code != ConnectReturnCode::Success {
        return Err(format!("not accepted: {:?}", connack.code));
    }
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
    Ok(TestClient {
        client,
        msgs: rx,
        subacks: rx_sub,
    })
}

async fn connect(
    node: &(String, u16),
    client_id: &str,
    username: &str,
    password: &str,
) -> TestClient {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        match try_connect(node, client_id, username, password).await {
            Ok(tc) => return tc,
            Err(e) => {
                if tokio::time::Instant::now() >= deadline {
                    panic!("{client_id} connection failed after retries: {e}");
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
}

impl TestClient {
    async fn subscribe_expect(&mut self, topic: &str, expect_ok: bool) {
        self.client
            .subscribe(topic, QoS::AtLeastOnce)
            .await
            .unwrap();
        let codes = timeout(Duration::from_secs(10), self.subacks.recv())
            .await
            .expect("timed out waiting for suback")
            .expect("suback channel closed");
        let ok = matches!(codes.first(), Some(SubscribeReasonCode::Success(_)));
        assert_eq!(ok, expect_ok, "subscription to {topic}: got {codes:?}");
    }

    async fn recv(&mut self) -> (String, Vec<u8>) {
        timeout(Duration::from_secs(10), self.msgs.recv())
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

async fn expect_rejected(node: &(String, u16), client_id: &str, username: &str, password: &str) {
    let mut opts = MqttOptions::new(client_id, &node.0, node.1);
    opts.set_credentials(username, password);
    let (_client, mut eventloop) = AsyncClient::new(opts, 8);
    let outcome = timeout(Duration::from_secs(15), async {
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
        Ok(code) => assert_ne!(
            code,
            ConnectReturnCode::Success,
            "{client_id} unexpectedly accepted"
        ),
        Err(rumqttc::ConnectionError::ConnectionRefused(code)) => {
            assert_ne!(code, ConnectReturnCode::Success)
        }
        Err(_) => {}
    }
}

#[tokio::test]
#[ignore]
async fn cluster_cross_node() {
    let nodes = nodes();
    assert_eq!(nodes.len(), 3, "expected 3 nodes");
    let apis = api_bases();
    let token = token();
    let http = reqwest::Client::new();

    let user = unique("tok-u");
    let userid = unique("uid");
    let backend = unique("tok-b");

    let resp = http
        .post(format!("{}/api/v1/users", apis[0]))
        .bearer_auth(&token)
        .json(&json!({"username": user, "userid": userid, "password": "pw-user"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "create user via node1 api");

    let resp = http
        .post(format!("{}/api/v1/users", apis[2]))
        .bearer_auth(&token)
        .json(&json!({"username": backend, "userid": "svc", "password": "pw-backend", "superuser": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "create backend via node3 api");

    let mut dev_a = connect(&nodes[0], "cdevA", &user, "pw-user").await;
    let mut dev_b = connect(&nodes[1], "cdevB", &user, "pw-user").await;
    let mut publisher = connect(&nodes[2], "cbackend", &backend, "pw-backend").await;

    let chat_topic = format!("chat/{userid}/m/all");
    let update_topic = format!("update/{userid}/m/all");
    dev_a.subscribe_expect(&chat_topic, true).await;
    dev_a.subscribe_expect(&update_topic, true).await;
    dev_a.subscribe_expect("fanout/all", true).await;
    dev_b.subscribe_expect(&chat_topic, true).await;
    dev_b.subscribe_expect("fanout/all", true).await;
    dev_b.subscribe_expect("chat/otheruser/m/all", false).await;
    publisher.subscribe_expect("chatsync", true).await;
    tokio::time::sleep(Duration::from_millis(700)).await;

    publisher
        .client
        .publish(
            chat_topic.as_str(),
            QoS::AtLeastOnce,
            false,
            "cross-node-chat",
        )
        .await
        .unwrap();
    let (topic_a, payload_a) = dev_a.recv().await;
    let (topic_b, payload_b) = dev_b.recv().await;
    assert_eq!(topic_a, chat_topic);
    assert_eq!(topic_b, chat_topic);
    assert_eq!(payload_a, b"cross-node-chat");
    assert_eq!(payload_b, b"cross-node-chat");

    publisher
        .client
        .publish(update_topic.as_str(), QoS::AtLeastOnce, false, "only-devA")
        .await
        .unwrap();
    let (topic_a, payload_a) = dev_a.recv().await;
    assert_eq!(topic_a, update_topic);
    assert_eq!(payload_a, b"only-devA");
    dev_b.expect_silence().await;

    publisher
        .client
        .publish("fanout/all", QoS::AtLeastOnce, false, "to-everyone")
        .await
        .unwrap();
    let (topic_a, _) = dev_a.recv().await;
    let (topic_b, _) = dev_b.recv().await;
    assert_eq!(topic_a, "fanout/all");
    assert_eq!(topic_b, "fanout/all");

    dev_b
        .client
        .publish("chatsync", QoS::AtLeastOnce, false, "device-to-backend")
        .await
        .unwrap();
    let (topic, payload) = publisher.recv().await;
    assert_eq!(topic, "chatsync");
    assert_eq!(payload, b"device-to-backend");

    expect_rejected(&nodes[1], "cintruder", &user, "wrong").await;

    let resp = http
        .delete(format!("{}/api/v1/users/{user}", apis[2]))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "delete user via node3 api");

    expect_rejected(&nodes[0], "cdevC", &user, "pw-user").await;

    let resp = http
        .delete(format!("{}/api/v1/users/{backend}", apis[0]))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}

#[tokio::test]
#[ignore]
async fn cluster_user_lifecycle() {
    let nodes = nodes();
    assert_eq!(nodes.len(), 3, "expected 3 nodes");
    let apis = api_bases();
    let token = token();
    let http = reqwest::Client::new();

    let user = unique("lc-u");
    let userid = unique("lcid");

    let resp = http
        .post(format!("{}/api/v1/users", apis[1]))
        .bearer_auth(&token)
        .json(&json!({"username": user, "userid": userid, "password": "pw-lc"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 201, "create user via node2 api");

    let dev1 = connect(&nodes[0], "lc-dev1", &user, "pw-lc").await;
    let dev3 = connect(&nodes[2], "lc-dev3", &user, "pw-lc").await;
    drop(dev1);
    drop(dev3);

    expect_rejected(&nodes[0], "lc-bad", &user, "nope").await;

    let resp = http
        .delete(format!("{}/api/v1/users/{user}", apis[0]))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "delete user via node1 api");

    expect_rejected(&nodes[1], "lc-dev1b", &user, "pw-lc").await;
    expect_rejected(&nodes[2], "lc-dev3b", &user, "pw-lc").await;
}
