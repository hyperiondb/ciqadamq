use anyhow::{anyhow, Context, Result};
use rumqttc::{AsyncClient, ConnectReturnCode, Event, MqttOptions, Packet, QoS};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio::time::timeout;

#[derive(Clone)]
struct Settings {
    nodes: Vec<(String, u16)>,
    api: String,
    token: String,
    sub_levels: Vec<usize>,
    devices_per_user: usize,
    services: Vec<String>,
    settle_secs: u64,
    samples: usize,
    out: String,
}

#[derive(Debug, Clone)]
struct LevelResult {
    subscribers: usize,
    cpu_pct: Vec<f64>,
    mem_mb: Vec<f64>,
    cpu_total_pct: f64,
    mem_total_mb: f64,
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
    let mut sub_levels = env_or("PERF_RES_SUBS", "0,1000,2500,5000,7500,10000")
        .split(',')
        .map(|s| s.trim().parse::<usize>().context("PERF_RES_SUBS must be integers"))
        .collect::<Result<Vec<_>>>()?;
    sub_levels.sort_unstable();
    sub_levels.dedup();
    let services = env_or("PERF_SERVICES", "node1,node2,node3")
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    Ok(Settings {
        nodes,
        api: env_or("PERF_API", "http://127.0.0.1:8090"),
        token: env_or("API_TOKEN", "change-me"),
        sub_levels,
        devices_per_user: env_or("PERF_DEVICES_PER_USER", "1").parse()?,
        services,
        settle_secs: env_or("PERF_SETTLE_SECS", "10").parse()?,
        samples: env_or("PERF_SAMPLES", "3").parse()?,
        out: env_or("PERF_RES_OUT", "perf-resources.svg"),
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
) -> Result<()> {
    let resp = http
        .post(format!("{}/api/v1/users", s.api))
        .bearer_auth(&s.token)
        .json(&json!({
            "username": username,
            "userid": userid,
            "password": "perf-pass",
            "superuser": false
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
) -> Result<Subscriber> {
    let max_attempts = 8;
    for attempt in 1..=max_attempts {
        match try_connect(&node, &client_id, &username).await {
            Ok(pair) => {
                return finish_subscriber(pair, &client_id, &topic).await;
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
                Ok(Event::Outgoing(rumqttc::Outgoing::Disconnect)) => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }
    });
    Ok(Subscriber { client })
}

async fn resolve_containers(services: &[String]) -> Result<Vec<String>> {
    let mut ids = Vec::with_capacity(services.len());
    for svc in services {
        let out = Command::new("docker")
            .args([
                "ps",
                "--filter",
                &format!("label=com.docker.compose.service={svc}"),
                "--format",
                "{{.ID}}",
            ])
            .output()
            .await
            .context("running docker ps")?;
        if !out.status.success() {
            return Err(anyhow!("docker ps failed: {}", String::from_utf8_lossy(&out.stderr)));
        }
        let id = String::from_utf8_lossy(&out.stdout).lines().next().unwrap_or("").trim().to_string();
        if id.is_empty() {
            return Err(anyhow!("no running container for compose service {svc}"));
        }
        ids.push(id);
    }
    Ok(ids)
}

fn parse_mem_mb(s: &str) -> Result<f64> {
    let scales = [
        ("TiB", 1024.0 * 1024.0),
        ("GiB", 1024.0),
        ("MiB", 1.0),
        ("KiB", 1.0 / 1024.0),
        ("B", 1.0 / (1024.0 * 1024.0)),
    ];
    for (suffix, scale) in scales {
        if let Some(num) = s.strip_suffix(suffix) {
            return Ok(num.trim().parse::<f64>()? * scale);
        }
    }
    Err(anyhow!("cannot parse memory value: {s}"))
}

async fn sample_stats(ids: &[String]) -> Result<Vec<(f64, f64)>> {
    let out = Command::new("docker")
        .args(["stats", "--no-stream", "--format", "{{.ID}};{{.CPUPerc}};{{.MemUsage}}"])
        .args(ids)
        .output()
        .await
        .context("running docker stats")?;
    if !out.status.success() {
        return Err(anyhow!("docker stats failed: {}", String::from_utf8_lossy(&out.stderr)));
    }
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let mut by_id: HashMap<String, (f64, f64)> = HashMap::new();
    for line in text.lines() {
        let parts: Vec<&str> = line.trim().split(';').collect();
        if parts.len() != 3 {
            continue;
        }
        let cpu = parts[1].trim().trim_end_matches('%').parse::<f64>().unwrap_or(0.0);
        let mem = parse_mem_mb(parts[2].split('/').next().unwrap_or("").trim())?;
        by_id.insert(parts[0].trim().to_string(), (cpu, mem));
    }
    ids.iter()
        .map(|id| {
            by_id
                .iter()
                .find(|(k, _)| id.starts_with(k.as_str()) || k.starts_with(id.as_str()))
                .map(|(_, v)| *v)
                .ok_or_else(|| anyhow!("no stats for container {id}"))
        })
        .collect()
}

async fn measure_level(s: &Settings, ids: &[String], subscribers: usize) -> Result<LevelResult> {
    tokio::time::sleep(Duration::from_secs(s.settle_secs)).await;
    let mut cpu_sum = vec![0.0; ids.len()];
    let mut mem_sum = vec![0.0; ids.len()];
    for _ in 0..s.samples {
        let stats = sample_stats(ids).await?;
        for (i, (cpu, mem)) in stats.into_iter().enumerate() {
            cpu_sum[i] += cpu;
            mem_sum[i] += mem;
        }
    }
    let cpu_pct: Vec<f64> = cpu_sum.iter().map(|v| v / s.samples as f64).collect();
    let mem_mb: Vec<f64> = mem_sum.iter().map(|v| v / s.samples as f64).collect();
    Ok(LevelResult {
        subscribers,
        cpu_total_pct: cpu_pct.iter().sum(),
        mem_total_mb: mem_mb.iter().sum(),
        cpu_pct,
        mem_mb,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let s = load_settings()?;
    let ids = resolve_containers(&s.services).await?;
    let http = reqwest::Client::new();
    let run_id = format!("{:x}", now_nanos() / 1_000_000);

    let max_subs = *s.sub_levels.iter().max().unwrap_or(&0);
    let max_users = if max_subs == 0 { 0 } else { (max_subs + s.devices_per_user - 1) / s.devices_per_user };
    println!("run {run_id}: provisioning {max_users} users");
    let t0 = Instant::now();
    let sem = Arc::new(Semaphore::new(32));
    let mut handles = Vec::with_capacity(max_users);
    for i in 0..max_users {
        let http = http.clone();
        let s = s.clone();
        let run_id = run_id.clone();
        let sem = sem.clone();
        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.unwrap();
            create_user(&http, &s, &format!("tok-{run_id}-{i}"), &format!("uid-{run_id}-{i}")).await
        }));
    }
    for h in handles {
        h.await??;
    }
    println!("provisioned in {:.1}s", t0.elapsed().as_secs_f64());

    let mut subs: Vec<Subscriber> = Vec::new();
    let mut results = Vec::new();
    for &level in &s.sub_levels {
        if level > subs.len() {
            println!("ramping to {level} idle subscribers...");
            let sem = Arc::new(Semaphore::new(32));
            let mut handles = Vec::with_capacity(level - subs.len());
            for i in subs.len()..level {
                let user_idx = i / s.devices_per_user;
                let node = s.nodes[i % s.nodes.len()].clone();
                let client_id = format!("perfres-{run_id}-{i}");
                let username = format!("tok-{run_id}-{user_idx}");
                let topic = format!("chat/uid-{run_id}-{user_idx}/m/all");
                let sem = sem.clone();
                handles.push(tokio::spawn(async move {
                    let _permit = sem.acquire().await.unwrap();
                    connect_subscriber(node, client_id, username, topic).await
                }));
            }
            for h in handles {
                subs.push(h.await??);
            }
        }
        let r = measure_level(&s, &ids, level).await?;
        let per_node = s
            .services
            .iter()
            .zip(r.cpu_pct.iter().zip(r.mem_mb.iter()))
            .map(|(svc, (c, m))| format!("{svc} {c:.1}%/{m:.0}MB"))
            .collect::<Vec<_>>()
            .join(", ");
        println!(
            "  {} subscribers -> cpu {:.1}% mem {:.1} MB ({per_node})",
            r.subscribers, r.cpu_total_pct, r.mem_total_mb
        );
        results.push(r);
    }

    for sub in &subs {
        let _ = sub.client.disconnect().await;
    }

    println!("cleaning up users");
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
    let mut csv = String::from("subscribers");
    for svc in &s.services {
        csv.push_str(&format!(",{svc}_cpu_pct,{svc}_mem_mb"));
    }
    csv.push_str(",total_cpu_pct,total_mem_mb\n");
    for r in &results {
        csv.push_str(&r.subscribers.to_string());
        for i in 0..s.services.len() {
            csv.push_str(&format!(",{:.2},{:.2}", r.cpu_pct[i], r.mem_mb[i]));
        }
        csv.push_str(&format!(",{:.2},{:.2}\n", r.cpu_total_pct, r.mem_total_mb));
    }
    std::fs::write(&csv_path, csv)?;
    std::fs::write(&s.out, render_svg(&s.services, &results))?;
    println!("wrote {} and {}", s.out, csv_path);
    Ok(())
}

fn render_svg(services: &[String], results: &[LevelResult]) -> String {
    let node_colors = ["#1f77b4", "#2ca02c", "#ff7f0e", "#9467bd", "#8c564b", "#e377c2"];
    let mut cpu_series: Vec<(String, &str, Vec<f64>)> = Vec::new();
    let mut mem_series: Vec<(String, &str, Vec<f64>)> = Vec::new();
    for (i, svc) in services.iter().enumerate() {
        let color = node_colors[i % node_colors.len()];
        cpu_series.push((svc.clone(), color, results.iter().map(|r| r.cpu_pct[i]).collect()));
        mem_series.push((svc.clone(), color, results.iter().map(|r| r.mem_mb[i]).collect()));
    }
    cpu_series.push(("total".into(), "#d62728", results.iter().map(|r| r.cpu_total_pct).collect()));
    mem_series.push(("total".into(), "#d62728", results.iter().map(|r| r.mem_total_mb).collect()));

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

    let panels: [(&str, &Vec<(String, &str, Vec<f64>)>); 2] = [
        ("broker cpu usage on idle subscribers (%, docker stats)", &cpu_series),
        ("broker memory usage on idle subscribers (MB)", &mem_series),
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
            let lx = ml + 12.0;
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
