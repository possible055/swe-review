mod cli;
mod credentials;
mod diff;
mod protobuf;
mod quick_review;
mod review_options;
mod upstream;
mod util;

pub fn run() -> i32 {
    cli::run()
}
