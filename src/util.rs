pub fn estimate_tokens(text: &str) -> u64 {
    (text.chars().count() as u64 / 4).max(1)
}

pub fn progress(on_progress: Option<&(dyn Fn(&str) + Sync)>, message: &str) {
    if let Some(on_progress) = on_progress {
        on_progress(message);
    }
}

pub fn build_review_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
}
