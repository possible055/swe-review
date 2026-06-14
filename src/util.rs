pub fn estimate_tokens(text: &str) -> u64 {
    tiktoken_rs::o200k_base_singleton()
        .encode_with_special_tokens(text)
        .len() as u64
}

pub fn exceeds_token_limit(text: &str, limit: u64) -> Option<u64> {
    if (text.len() as u64) <= limit {
        return None;
    }
    let tokens = estimate_tokens(text);
    (tokens > limit).then_some(tokens)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimates_tokens_with_tiktoken_o200k_base() {
        assert_eq!(estimate_tokens("hello world"), 2);
    }

    #[test]
    fn token_limit_uses_byte_count_as_fast_pass() {
        assert_eq!(exceeds_token_limit("hello world", 11), None);
    }

    #[test]
    fn token_limit_checks_tiktoken_when_character_count_exceeds_limit() {
        assert_eq!(exceeds_token_limit("hello world", 1), Some(2));
    }
}
