use std::fs;

pub trait Dispatcher {
    fn dispatch(&self, job: Job);
}

pub enum JobState { Queued, Running, Complete }

pub fn run_job(dispatcher: &dyn Dispatcher, job: Job) {
    dispatcher.dispatch(job);
    fs::write("job.out", b"complete").unwrap();
}

#[test]
fn writes_job_output() {
    let dispatcher = TestDispatcher;
    run_job(&dispatcher, Job::default());
}
