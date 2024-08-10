mod db;
mod question;
mod record;
mod respone;
mod types;
mod zonefile;

use std::io;

pub use db::*;
pub use question::*;
pub use record::*;
pub use respone::*;
pub use types::*;
pub use zonefile::*;

pub struct DnsZoneResolver {
    // dbs: FxHashMap<ResourceRecordClass, RecordMap>,
    db: RecordMap,
    zone: DnsString,
}

impl DnsZoneResolver {
    pub fn new(zf: Zonefile) -> io::Result<Self> {
        let db = zf
            .records
            .into_iter()
            .map(DnsResourceRecord::try_from)
            .collect::<Result<RecordMap, _>>()?;

        let soa = db.soa().expect("expected soa");
        Ok(Self {
            zone: soa.name().clone(),
            db,
        })
    }

    pub fn query(&self, question: DnsQuestion) -> QueryResponse {
        let mut response = QueryResponse::default();

        let results = self.db.query(&question);

        if results.is_empty() {
            for (follow_up, kind) in question.on_unanwsered(self) {
                let follow_up_result = self.db.query(&follow_up);
                if !follow_up_result.is_empty() {
                    response.merge(follow_up_result, kind);
                    for (additional, kind) in follow_up.on_anwsered(follow_up_result) {
                        response.merge(self.db.query(&additional), kind);
                    }
                }
            }
        } else {
            response.anwsers.extend(results.iter().cloned());
            for (additional, kind) in question.on_anwsered(results) {
                response.merge(self.db.query(&additional), kind);
            }
        }

        response
    }
}
