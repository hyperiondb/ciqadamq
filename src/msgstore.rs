use anyhow::{Context, Result};
use async_trait::async_trait;
use redb::{Database, ReadableTable, TableDefinition};
use rmqtt::message::MessageManager;
use rmqtt::types::{ClientId, From as MsgFrom, MsgID, Publish, SharedGroup, TopicFilter};
use rmqtt::Result as RmqttResult;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const COUNTER_MASK: u64 = 0xFFFF_FFFF_FFFF;
const MESSAGES: TableDefinition<u64, &[u8]> = TableDefinition::new("messages");

#[derive(Clone, Serialize, Deserialize)]
struct StoredMsg {
    from: MsgFrom,
    publish: Publish,
    expiry_at: i64,
    delivered_to: Vec<String>,
}

fn approx_size(m: &StoredMsg) -> usize {
    m.publish.payload.len() + m.publish.topic.len() + 384
}

struct MemState {
    msgs: HashMap<u64, StoredMsg>,
    order: VecDeque<u64>,
    bytes: usize,
    dirty: HashSet<u64>,
    removed: HashSet<u64>,
}

impl MemState {
    fn evict(&mut self, now: i64, max_msgs: usize, max_bytes: usize) {
        while let Some(&id) = self.order.front() {
            let over_cap = (max_msgs > 0 && self.msgs.len() > max_msgs)
                || (max_bytes > 0 && self.bytes > max_bytes);
            let expired = self.msgs.get(&id).map(|m| m.expiry_at <= now).unwrap_or(true);
            if !over_cap && !expired {
                break;
            }
            self.order.pop_front();
            if let Some(m) = self.msgs.remove(&id) {
                self.bytes = self.bytes.saturating_sub(approx_size(&m));
                self.dirty.remove(&id);
                self.removed.insert(id);
            }
        }
    }
}

#[derive(Clone)]
pub struct RedbMessageStore {
    db: Arc<Database>,
    node_id: u64,
    counter: Arc<AtomicU64>,
    state: Arc<Mutex<MemState>>,
    max_msgs: usize,
    max_bytes: usize,
}

impl RedbMessageStore {
    pub fn open(path: &Path, node_id: u64) -> Result<Self> {
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let db = Database::create(path).context("opening redb message store")?;
        let wtx = db.begin_write()?;
        {
            wtx.open_table(MESSAGES)?;
        }
        wtx.commit()?;

        let now = now_millis();
        let mut msgs = HashMap::new();
        let mut start = 0u64;
        {
            let rtx = db.begin_read()?;
            let t = rtx.open_table(MESSAGES)?;
            for item in t.iter()? {
                let (k, v) = item?;
                let id = k.value();
                if (id >> 48) == node_id {
                    let c = (id & COUNTER_MASK) + 1;
                    if c > start {
                        start = c;
                    }
                }
                if let Ok(msg) = bincode::deserialize::<StoredMsg>(v.value()) {
                    if msg.expiry_at > now {
                        msgs.insert(id, msg);
                    }
                }
            }
        }
        let mut entries: Vec<(i64, u64)> = msgs.iter().map(|(id, m)| (m.expiry_at, *id)).collect();
        entries.sort_unstable();
        let order: VecDeque<u64> = entries.into_iter().map(|(_, id)| id).collect();
        let bytes: usize = msgs.values().map(approx_size).sum();

        let max_msgs = std::env::var("MSG_MAX_MSGS").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
        let max_bytes = std::env::var("MSG_MAX_BYTES")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(256 * 1024 * 1024);
        log::info!("message store memory cap: max_msgs={max_msgs} max_bytes={max_bytes} (0 = unbounded)");

        Ok(Self {
            db: Arc::new(db),
            node_id,
            counter: Arc::new(AtomicU64::new(start)),
            state: Arc::new(Mutex::new(MemState {
                msgs,
                order,
                bytes,
                dirty: HashSet::new(),
                removed: HashSet::new(),
            })),
            max_msgs,
            max_bytes,
        })
    }

    pub async fn flush(&self) {
        let now = now_millis();
        let (batch, removed): (Vec<(u64, Vec<u8>)>, Vec<u64>) = {
            let mut st = match self.state.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            st.evict(now, self.max_msgs, self.max_bytes);
            let dirty: Vec<u64> = st.dirty.drain().collect();
            let mut batch = Vec::with_capacity(dirty.len());
            for id in dirty {
                if let Some(m) = st.msgs.get(&id) {
                    match bincode::serialize(m) {
                        Ok(bytes) => batch.push((id, bytes)),
                        Err(e) => log::warn!("message store encode failed: {e}"),
                    }
                }
            }
            let removed: Vec<u64> = st.removed.drain().collect();
            (batch, removed)
        };
        if batch.is_empty() && removed.is_empty() {
            return;
        }
        let db = self.db.clone();
        let res = tokio::task::spawn_blocking(move || -> Result<()> {
            let wtx = db.begin_write()?;
            {
                let mut t = wtx.open_table(MESSAGES)?;
                for id in removed {
                    t.remove(id)?;
                }
                for (id, bytes) in batch {
                    t.insert(id, bytes.as_slice())?;
                }
            }
            wtx.commit()?;
            Ok(())
        })
        .await;
        if let Ok(Err(e)) = res {
            log::warn!("message store flush failed: {e}");
        }
    }
}

fn now_millis() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as i64).unwrap_or(0)
}

fn topic_matches(topic: &str, filter: &str) -> bool {
    let mut t = topic.split('/');
    let mut f = filter.split('/');
    loop {
        match (f.next(), t.next()) {
            (Some("#"), _) => return true,
            (Some("+"), Some(_)) => continue,
            (Some(fseg), Some(tseg)) if fseg == tseg => continue,
            (None, None) => return true,
            _ => return false,
        }
    }
}

#[async_trait]
impl MessageManager for RedbMessageStore {
    fn enable(&self) -> bool {
        true
    }

    fn next_msg_id(&self) -> MsgID {
        let c = self.counter.fetch_add(1, Ordering::Relaxed) & COUNTER_MASK;
        ((self.node_id << 48) | c) as MsgID
    }

    async fn store(
        &self,
        msg_id: MsgID,
        from: MsgFrom,
        p: Publish,
        expiry_interval: Duration,
        sub_client_ids: Option<Vec<(ClientId, Option<(TopicFilter, SharedGroup)>)>>,
    ) -> RmqttResult<()> {
        let now = now_millis();
        let expiry_at = now.saturating_add(expiry_interval.as_millis() as i64);
        let delivered_to: Vec<String> = sub_client_ids
            .unwrap_or_default()
            .into_iter()
            .map(|(cid, _)| cid.to_string())
            .collect();
        let key = msg_id as u64;
        let msg = StoredMsg { from, publish: p, expiry_at, delivered_to };
        let size = approx_size(&msg);
        if let Ok(mut st) = self.state.lock() {
            st.removed.remove(&key);
            match st.msgs.insert(key, msg) {
                Some(old) => {
                    st.bytes = st.bytes.saturating_sub(approx_size(&old)).saturating_add(size);
                }
                None => {
                    st.order.push_back(key);
                    st.bytes = st.bytes.saturating_add(size);
                }
            }
            st.dirty.insert(key);
            st.evict(now, self.max_msgs, self.max_bytes);
        }
        Ok(())
    }

    async fn get(
        &self,
        client_id: &str,
        topic_filter: &str,
        _group: Option<&SharedGroup>,
    ) -> RmqttResult<Vec<(MsgID, MsgFrom, Publish)>> {
        let now = now_millis();
        let mut out = Vec::new();
        if let Ok(mut st) = self.state.lock() {
            st.evict(now, self.max_msgs, self.max_bytes);
            let mut touched = Vec::new();
            for (id, msg) in st.msgs.iter() {
                if msg.expiry_at <= now || msg.delivered_to.iter().any(|c| c == client_id) {
                    continue;
                }
                if !topic_matches(&msg.publish.topic, topic_filter) {
                    continue;
                }
                out.push((*id as MsgID, msg.from.clone(), msg.publish.clone()));
                touched.push(*id);
            }
            for id in touched {
                if let Some(m) = st.msgs.get_mut(&id) {
                    m.delivered_to.push(client_id.to_string());
                }
                st.dirty.insert(id);
            }
        }
        Ok(out)
    }

    async fn count(&self) -> isize {
        let now = now_millis();
        match self.state.lock() {
            Ok(st) => st.msgs.values().filter(|m| m.expiry_at > now).count() as isize,
            Err(_) => -1,
        }
    }

    fn should_merge_on_get(&self) -> bool {
        false
    }
}
