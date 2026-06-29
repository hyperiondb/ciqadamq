use crate::config::{AclConfig, FanoutConfig};
use crate::db::UserStore;
use async_trait::async_trait;
use rmqtt::Result;
use rmqtt::codec::v5::{RetainHandling, SubscriptionOptions};
use rmqtt::subscribe::AutoSubscription;
use rmqtt::types::{Id, QoS, Subscribe, TopicFilter};
use std::sync::Arc;

pub struct UseridAutoSubscription {
    store: Arc<dyn UserStore>,
    qos: QoS,
    fanout_prefixes: Vec<String>,
    admin_prefixes: Vec<String>,
}

impl UseridAutoSubscription {
    pub fn new(store: Arc<dyn UserStore>, fanout: &FanoutConfig, acl: &AclConfig) -> Self {
        Self {
            store,
            qos: QoS::try_from(fanout.qos.min(2)).unwrap_or(QoS::AtLeastOnce),
            fanout_prefixes: acl.fanout_prefixes.clone(),
            admin_prefixes: acl.admin_prefixes.clone(),
        }
    }

    fn subscription(&self, filter: String) -> Result<Subscribe> {
        let opts = SubscriptionOptions {
            qos: self.qos,
            no_local: false,
            retain_as_published: false,
            retain_handling: RetainHandling::AtSubscribe,
        };
        Subscribe::from_v5(&TopicFilter::from(filter), &opts, true, true, None)
    }
}

#[async_trait]
impl AutoSubscription for UseridAutoSubscription {
    fn enable(&self) -> bool {
        true
    }

    async fn subscribes(&self, id: &Id) -> Result<Vec<Subscribe>> {
        let Some(username) = &id.username else {
            return Ok(Vec::new());
        };
        let record = match self.store.get_user(username).await {
            Ok(Some(record)) => record,
            Ok(None) => {
                log::warn!("{id} auto subscribe skipped, user not found");
                return Ok(Vec::new());
            }
            Err(e) => {
                log::error!("{id} auto subscribe user lookup failed: {e:#}");
                return Ok(Vec::new());
            }
        };
        let mut filters = vec![format!("+/{}/#", record.userid)];
        for p in &self.fanout_prefixes {
            filters.push(format!("{p}/#"));
        }
        if record.admin {
            for p in &self.admin_prefixes {
                filters.push(format!("{p}/#"));
            }
        }
        let mut subs = Vec::with_capacity(filters.len());
        for f in filters {
            subs.push(self.subscription(f)?);
        }
        Ok(subs)
    }
}
