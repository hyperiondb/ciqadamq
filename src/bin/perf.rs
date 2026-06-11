use anyhow::{anyhow, Context, Result};
use rumqttc::{AsyncClient, ConnectReturnCode, Event, MqttOptions, Packet, QoS};
use serde_json::json;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, Semaphore};
use tokio::time::timeout;

#[derive(Clone)]
struct Settings {
    nodes: Vec<(String, u16)>,
    api: String,
    token: String,
    sub_counts: Vec<usize>,
    messages: u64,
    devices_per_user: usize,
    payload_size: usize,
    out: String,
}

#[derive(Debug, Clone)]
struct RoundResult {
    subscribers: usize,
    users: usize,
    published: u64,
    expected: u64,
    delivered: u64,
    duration_secs: f64,
    delivered_per_sec: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.into())
}

fn load_settings() -> Result<Settings> {
    let nodes = env_or("PERF_NODES", "127.0.0.1:1883,127.0.0.1:1884,127.0.0.1:1885")
        .split(',')
        .map(|s| {
            let (h, p) = s.trim().rsplit_once(':').ok_or_else(|| anyhow!("bad node addr: {s}"))?;
            Ok((h.to_string(), p.parse::<u16>()?))
        })
        .collect::<Result<Vec<_>>>()?;
    let sub_counts = env_or("PERF_SUBS", "100,500,1000,2500,5000,10000")
        .split(',')
        .map(|s| s.trim().parse::<usize>().context("PERF_SUBS must be integers"))
        .collect::<Result<Vec<_>>>()?;
    Ok(Settings {
        nodes,
        api: env_or("PERF_API", "http://127.0.0.1:8090"),
        token: env_or("API_TOKEN", "change-me"),
        sub_counts,
        messages: env_or("PERF_MSGS", "10000").parse()?,
        devices_per_user: env_or("PERF_DEVICES_PER_USER", "1").parse()?,
        payload_size: env_or("PERF_PAYLOAD", "256").parse()?,
        out: env_or("PERF_OUT", "perf-results.svg"),
    })
}

fn now_nanos() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
}

async fn create_user(
    http: &reqwest::Client,
    s: &Settings,
    username: &str,
    userid: &str,
    superuser: bool,
) -> Result<()> {
    let resp = http
        .post(format!("{}/api/v1/users", s.api))
        .bearer_auth(&s.token)
        .json(&json!({
            "username": username,
            "userid": userid,
            "password": "perf-pass",
            "superuser": superuser
        }))
        .send()
        .await?;
    if resp.status() == 201 || resp.status() == 409 {
        Ok(())
    } else {
        Err(anyhow!("creating {username}: {}", resp.status()))
    }
}

async fn delete_user(http: &reqwest::Client, s: &Settings, username: &str) {
    let _ = http
        .delete(format!("{}/api/v1/users/{username}", s.api))
        .bearer_auth(&s.token)
        .send()
        .await;
}

struct Subscriber {
    client: AsyncClient,
}

async fn connect_subscriber(
    node: (String, u16),
    client_id: String,
    username: String,
    topic: String,
    latencies_tx: mpsc::UnboundedSender<u64>,
    delivered: Arc<AtomicU64>,
) -> Result<Subscriber> {
    let max_attempts = 8;
    for attempt in 1..=max_attempts {
        match try_connect(&node, &client_id, &username).await {
            Ok(pair) => {
                return finish_subscriber(pair, &client_id, &topic, latencies_tx, delivered).await;
            }
            Err(e) if attempt < max_attempts => {
                if attempt >= 3 {
                    eprintln!("{client_id} connect attempt {attempt} failed ({e}), retrying");
                }
                tokio::time::sleep(Duration::from_millis(500 * attempt)).await;
            }
            Err(e) => return Err(e.context(format!("{client_id} gave up after {max_attempts} attempts"))),
        }
    }
    unreachable!()
}

async fn try_connect(
    node: &(String, u16),
    client_id: &str,
    username: &str,
) -> Result<(AsyncClient, rumqttc::EventLoop)> {
    let mut opts = MqttOptions::new(client_id, &node.0, node.1);
    opts.set_credentials(username, "perf-pass");
    opts.set_keep_alive(Duration::from_secs(30));
    let (client, mut eventloop) = AsyncClient::new(opts, 128);
    timeout(Duration::from_secs(30), async {
        loop {
            match eventloop.poll().await {
                Ok(Event::Incoming(Packet::ConnAck(ack))) => {
                    if ack.code != ConnectReturnCode::Success {
                        return Err(anyhow!("rejected: {:?}", ack.code));
                    }
                    return Ok(());
                }
                Ok(_) => {}
                Err(e) => return Err(anyhow!("connect failed: {e}")),
            }
        }
    })
    .await
    .context("connack timeout")??;
    Ok((client, eventloop))
}

async fn finish_subscriber(
    (client, mut eventloop): (AsyncClient, rumqttc::EventLoop),
    client_id: &str,
    topic: &str,
    latencies_tx: mpsc::UnboundedSender<u64>,
    delivered: Arc<AtomicU64>,
) -> Result<Subscriber> {
    client.subscribe(topic, QoS::AtLeastOnce).await?;
    timeout(Duration::from_secs(30), async {
        loop {
            match eventloop.poll().await {
                Ok(Event::Incoming(Packet::SubAck(ack))) => {
                    if matches!(ack.return_codes.first(), Some(rumqttc::SubscribeReasonCode::Success(_))) {
                        return Ok(());
                    }
                    return Err(anyhow!("{client_id} subscribe denied"));
                }
                Ok(_) => {}
                Err(e) => return Err(anyhow!("{client_id} suback failed: {e}")),
            }
        }
    })
    .await
    .context("suback timeout")??;
    tokio::spawn(async move {
        loop {
            match eventloop.poll().await {
                Ok(Event::Incoming(Packet::Publish(p))) => {
                    let recv_ns = now_nanos();
                    delivered.fetch_add(1, Ordering::Relaxed);
                    if let Some(sent) = std::str::from_utf8(&p.payload)
                        .ok()
                        .and_then(|s| s.split('|').next())
                        .and_then(|s| s.parse::<u64>().ok())
                    {
                        let _ = latencies_tx.send(recv_ns.saturating_sub(sent));
                    }
                }
                Ok(Event::Outgoing(rumqttc::Outgoing::Disconnect)) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
    Ok(Subscriber { client })
}

async fn run_round(s: &Settings, run_id: &str, subscribers: usize) -> Result<RoundResult> {
    let users = (subscribers + s.devices_per_user - 1) / s.devices_per_user;
    let userids: Vec<String> = (0..users).map(|i| format!("uid-{run_id}-{i}")).collect();
    let usernames: Vec<String> = (0..users).map(|i| format!("tok-{run_id}-{i}")).collect();

    let delivered = Arc::new(AtomicU64::new(0));
    let (lat_tx, mut lat_rx) = mpsc::unbounded_channel::<u64>();

    let sem = Arc::new(Semaphore::new(32));
    let mut handles = Vec::with_capacity(subscribers);
    for i in 0..subscribers {
        let user_idx = i / s.devices_per_user;
        let node = s.nodes[i % s.nodes.len()].clone();
        let client_id = format!("perf-{run_id}-{i}");
        let username = usernames[user_idx].clone();
        let topic = format!("chat/{}/m/all", userids[user_idx]);
        let lat_tx = lat_tx.clone();
        let delivered = delivered.clone();
        let sem = sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            connect_subscriber(node, client_id, username, topic, lat_tx, delivered).await
        }));
    }
    drop(lat_tx);
    let mut subs = Vec::with_capacity(subscribers);
    for h in handles {
        subs.push(h.await??);
    }

    let pub_node = &s.nodes[0];
    let mut opts = MqttOptions::new(format!("perf-pub-{run_id}-{subscribers}"), &pub_node.0, pub_node.1);
    opts.set_credentials(format!("tok-pub-{run_id}"), "perf-pass");
    opts.set_keep_alive(Duration::from_secs(30));
    let (publisher, mut pub_loop) = AsyncClient::new(opts, 512);
    let pub_done = Arc::new(AtomicU64::new(0));
    let pub_done2 = pub_done.clone();
    tokio::spawn(async move {
        loop {
            match pub_loop.poll().await {
                Ok(Event::Incoming(Packet::PubAck(_))) => {
                    pub_done2.fetch_add(1, Ordering::Relaxed);
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
    tokio::time::sleep(Duration::from_millis(500)).await;

    let padding = "x".repeat(s.payload_size);
    let expected = s.messages * s.devices_per_user as u64;
    let start = Instant::now();
    for seq in 0..s.messages {
        let topic = format!("chat/{}/m/all", userids[(seq as usize) % users]);
        let payload = format!("{}|{}", now_nanos(), padding);
        publisher.publish(topic, QoS::AtLeastOnce, false, payload).await?;
    }

    let mut latencies: Vec<u64> = Vec::with_capacity(expected as usize);
    let hard_deadline = Instant::now() + Duration::from_secs(180);
    let mut last_progress = Instant::now();
    let mut last_count = 0u64;
    loop {
        let count = delivered.load(Ordering::Relaxed);
        if count >= expected {
            break;
        }
        if count != last_count {
            last_count = count;
            last_progress = Instant::now();
        }
        if last_progress.elapsed() > Duration::from_secs(15) || Instant::now() > hard_deadline {
            eprintln!("round {subscribers}: stalled at {count}/{expected} delivered");
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let duration = start.elapsed();
    while let Ok(l) = lat_rx.try_recv() {
        latencies.push(l);
    }

    for sub in &subs {
        let _ = sub.client.disconnect().await;
    }
    let _ = publisher.disconnect().await;
    tokio::time::sleep(Duration::from_millis(300)).await;

    latencies.sort_unstable();
    let pct = |p: f64| -> f64 {
        if latencies.is_empty() {
            return 0.0;
        }
        let idx = ((latencies.len() as f64 - 1.0) * p) as usize;
        latencies[idx] as f64 / 1_000_000.0
    };
    let delivered_n = delivered.load(Ordering::Relaxed);
    Ok(RoundResult {
        subscribers,
        users,
        published: s.messages,
        expected,
        delivered: delivered_n,
        duration_secs: duration.as_secs_f64(),
        delivered_per_sec: delivered_n as f64 / duration.as_secs_f64(),
        p50_ms: pct(0.50),
        p95_ms: pct(0.95),
        p99_ms: pct(0.99),
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let s = load_settings()?;
    let http = reqwest::Client::new();
    let run_id = format!("{:x}", now_nanos() / 1_000_000);

    let max_subs = *s.sub_counts.iter().max().unwrap_or(&0);
    let max_users = (max_subs + s.devices_per_user - 1) / s.devices_per_user;
    println!("run {run_id}: provisioning {max_users} users + 1 publisher");
    let t0 = Instant::now();
    create_user(&http, &s, &format!("tok-pub-{run_id}"), "svc-perf", true).await?;
    let sem = Arc::new(Semaphore::new(32));
    let mut handles = Vec::with_capacity(max_users);
    for i in 0..max_users {
        let http = http.clone();
        let s = s.clone();
        let run_id = run_id.clone();
        let sem = sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            create_user(&http, &s, &format!("tok-{run_id}-{i}"), &format!("uid-{run_id}-{i}"), false).await
        }));
    }
    for h in handles {
        h.await??;
    }
    println!("provisioned in {:.1}s", t0.elapsed().as_secs_f64());

    let mut results = Vec::new();
    for &n in &s.sub_counts {
        println!("round: {n} subscribers ({} msgs)...", s.messages);
        let r = run_round(&s, &run_id, n).await?;
        println!(
            "  delivered {}/{} in {:.2}s -> {:.0} msg/s, p50 {:.1}ms p95 {:.1}ms p99 {:.1}ms",
            r.delivered, r.expected, r.duration_secs, r.delivered_per_sec, r.p50_ms, r.p95_ms, r.p99_ms
        );
        results.push(r);
    }

    println!("cleaning up users");
    delete_user(&http, &s, &format!("tok-pub-{run_id}")).await;
    let sem = Arc::new(Semaphore::new(32));
    let mut handles = Vec::with_capacity(max_users);
    for i in 0..max_users {
        let http = http.clone();
        let s = s.clone();
        let run_id = run_id.clone();
        let sem = sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            delete_user(&http, &s, &format!("tok-{run_id}-{i}")).await;
        }));
    }
    for h in handles {
        let _ = h.await;
    }

    let csv_path = s.out.replace(".svg", ".csv");
    let mut csv = String::from("subscribers,users,published,expected,delivered,duration_secs,delivered_per_sec,p50_ms,p95_ms,p99_ms\n");
    for r in &results {
        csv.push_str(&format!(
            "{},{},{},{},{},{:.3},{:.1},{:.2},{:.2},{:.2}\n",
            r.subscribers, r.users, r.published, r.expected, r.delivered, r.duration_secs,
            r.delivered_per_sec, r.p50_ms, r.p95_ms, r.p99_ms
        ));
    }
    std::fs::write(&csv_path, csv)?;
    std::fs::write(&s.out, render_svg(&results))?;
    println!("wrote {} and {}", s.out, csv_path);
    Ok(())
}

fn render_svg(results: &[RoundResult]) -> String {
    let w = 860.0;
    let panel_h = 300.0;
    let h = panel_h * 2.0 + 60.0;
    let ml = 80.0;
    let mr = 30.0;
    let mt = 40.0;
    let gap = 70.0;
    let plot_w = w - ml - mr;
    let plot_h = panel_h - mt - 30.0;

    let xs: Vec<f64> = results.iter().map(|r| r.subscribers as f64).collect();
    let x_max = xs.iter().cloned().fold(1.0, f64::max) * 1.05;
    let x_pos = |v: f64| ml + v / x_max * plot_w;

    let mut svg = String::new();
    svg.push_str(&format!(
        r#"<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" viewBox="0 0 {w} {h}" font-family="monospace" font-size="12">"#
    ));
    svg.push_str(&format!(r#"<rect width="{w}" height="{h}" fill="white"/>"#));

    let panels: [(&str, Vec<(&str, &str, Vec<f64>)>); 2] = [
        (
            "messages delivered to end users / second",
            vec![("msg/s", "#1f77b4", results.iter().map(|r| r.delivered_per_sec).collect())],
        ),
        (
            "end-to-end delivery latency (ms)",
            vec![
                ("p50", "#2ca02c", results.iter().map(|r| r.p50_ms).collect()),
                ("p95", "#ff7f0e", results.iter().map(|r| r.p95_ms).collect()),
                ("p99", "#d62728", results.iter().map(|r| r.p99_ms).collect()),
            ],
        ),
    ];

    for (panel_idx, (title, series)) in panels.iter().enumerate() {
        let top = mt + panel_idx as f64 * (panel_h + gap - mt);
        let bottom = top + plot_h;
        let y_max = series
            .iter()
            .flat_map(|(_, _, vals)| vals.iter().cloned())
            .fold(1.0, f64::max)
            * 1.1;
        let y_pos = |v: f64| bottom - v / y_max * plot_h;

        svg.push_str(&format!(
            r#"<text x="{}" y="{}" font-size="14" font-weight="bold">{title}</text>"#,
            ml,
            top - 12.0
        ));
        svg.push_str(&format!(
            r#"<line x1="{ml}" y1="{bottom}" x2="{}" y2="{bottom}" stroke="black"/>"#,
            ml + plot_w
        ));
        svg.push_str(&format!(r#"<line x1="{ml}" y1="{top}" x2="{ml}" y2="{bottom}" stroke="black"/>"#));

        for t in 0..=5 {
            let yv = y_max / 5.0 * t as f64;
            let y = y_pos(yv);
            svg.push_str(&format!(
                r#"<line x1="{ml}" y1="{y}" x2="{}" y2="{y}" stroke="lightgray"/>"#,
                ml + plot_w
            ));
            svg.push_str(&format!(
                r#"<text x="{}" y="{}" text-anchor="end">{}</text>"#,
                ml - 6.0,
                y + 4.0,
                format_tick(yv)
            ));
        }
        for x in &xs {
            let xp = x_pos(*x);
            svg.push_str(&format!(
                r#"<text x="{xp}" y="{}" text-anchor="middle">{}</text>"#,
                bottom + 18.0,
                x
            ));
        }
        svg.push_str(&format!(
            r#"<text x="{}" y="{}" text-anchor="middle">subscribers</text>"#,
            ml + plot_w / 2.0,
            bottom + 36.0
        ));

        for (si, (label, color, vals)) in series.iter().enumerate() {
            let points: Vec<String> =
                xs.iter().zip(vals.iter()).map(|(x, v)| format!("{:.1},{:.1}", x_pos(*x), y_pos(*v))).collect();
            svg.push_str(&format!(
                r#"<polyline points="{}" fill="none" stroke="{color}" stroke-width="2"/>"#,
                points.join(" ")
            ));
            for (x, v) in xs.iter().zip(vals.iter()) {
                svg.push_str(&format!(
                    r#"<circle cx="{:.1}" cy="{:.1}" r="3.5" fill="{color}"/>"#,
                    x_pos(*x),
                    y_pos(*v)
                ));
            }
            let lx = ml + plot_w - 90.0;
            let ly = top + 16.0 + si as f64 * 18.0;
            svg.push_str(&format!(r#"<rect x="{lx}" y="{}" width="12" height="12" fill="{color}"/>"#, ly - 10.0));
            svg.push_str(&format!(r#"<text x="{}" y="{ly}">{label}</text>"#, lx + 18.0));
        }
    }
    svg.push_str("</svg>");
    svg
}

fn format_tick(v: f64) -> String {
    if v >= 10_000.0 {
        format!("{:.0}k", v / 1000.0)
    } else if v >= 100.0 {
        format!("{v:.0}")
    } else {
        format!("{v:.1}")
    }
}
