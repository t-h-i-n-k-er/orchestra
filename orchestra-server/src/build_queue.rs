use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use std::collections::HashMap;

#[derive(Clone)]
pub struct JobState {
    pub status: String,
    pub log: String,
    pub started_at: u64,
}

#[derive(Clone)]
pub struct BuildQueue {
    pub jobs: Arc<Mutex<HashMap<String, JobState>>>,
    pub sender: mpsc::Sender<crate::build_handler::BuildJob>,
}
