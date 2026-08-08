fn require_permission() -> bool {
    true
}

fn dispatch() {
    if require_permission() {
        std::fs::write("ledger", "entry").unwrap();
    }
}

fn bypass() {
    std::fs::write("ledger", "unguarded").unwrap();
}

enum JobState {
    Queued,
    Completed,
}

fn reopen(job: &mut Job) {
    job.state = JobState::Completed;
    job.state = JobState::Queued;
    callback.call();
}

fn main() {
    dispatch();
}
