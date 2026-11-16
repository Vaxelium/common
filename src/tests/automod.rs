use super::*;

fn rules(words: &[&str], links: bool) -> AutoMod {
    AutoMod {
        blocked_words: words.iter().map(|w| w.to_string()).collect(),
        block_links: links,
        ..AutoMod::default()
    }
}

#[test]
fn blocked_words_match_whole_words_only() {
    let r = rules(&["ass", "bad phrase"], false);
    assert!(r.check("what an ASS").is_some(), "case does not matter");
    assert!(r.check("ass!").is_some(), "punctuation ends a word");
    assert!(r.check("a class act").is_none(), "not inside a longer word");
    assert!(r.check("this is a Bad Phrase here").is_some());
    assert!(r.check("bad phrases").is_none());
    assert!(r.check("hello").is_none());
}

#[test]
fn links_are_refused_when_blocked() {
    assert!(rules(&[], true).check("see https://example.com").is_some());
    assert!(rules(&[], true).check("go to www.example.com").is_some());
    assert!(rules(&[], true).check("no links here").is_none());
    assert!(rules(&[], false).check("see https://example.com").is_none());
}

#[test]
fn rules_are_tidied() {
    let r = rules(&["  Bad ", "bad", "", "x"], false).tidied();
    assert_eq!(r.blocked_words, vec!["bad".to_string(), "x".to_string()]);
    let many: Vec<String> = (0..MAX_BLOCKED_WORDS + 10).map(|i| format!("w{i}")).collect();
    let r = AutoMod {
        blocked_words: many,
        ..AutoMod::default()
    }
    .tidied();
    assert_eq!(r.blocked_words.len(), MAX_BLOCKED_WORDS);
}

#[test]
fn wildcards_widen_a_match() {
    assert!(matches("concatenate", "*cat*"), "anywhere");
    assert!(matches("catalog", "cat*"), "at the start of a word");
    assert!(!matches("concat", "cat*"));
    assert!(matches("bobcat", "*cat"), "at the end of a word");
    assert!(!matches("catalog", "*cat"));
    assert!(!matches("catalog", "cat"), "plain words are whole words");
    assert!(!matches("anything", "*"));
}

#[test]
fn names_are_flagged_only_when_on() {
    let mut rule = NameRule {
        enabled: false,
        words: vec!["*admin*".into()],
        ..NameRule::default()
    };
    assert_eq!(rule.flags("RealAdmin"), None, "the rule is off");
    rule.enabled = true;
    assert_eq!(rule.flags("RealAdmin"), Some("*admin*"));
    assert_eq!(rule.flags("bob"), None);
}

#[test]
fn word_lists_split_on_commas_and_lines() {
    assert_eq!(split_words("a, b\nc"), vec!["a", " b", "c"]);
    let r = AutoMod {
        names: NameRule {
            words: split_words("X*, x*\n,"),
            ..NameRule::default()
        },
        ..AutoMod::default()
    }
    .tidied();
    assert_eq!(r.names.words, vec!["x*".to_string()]);
}

#[test]
fn an_old_name_alert_channel_becomes_the_automod_channel() {
    let old: AutoMod = serde_json::from_str(r#"{"names":{"enabled":true,"alert_channel":7}}"#).unwrap();
    let rules = old.tidied();
    assert_eq!(rules.alert_channel, Some(7));
    assert!(rules.names.send_alert);
    // Saved again, the channel is only kept in its new place.
    let saved: serde_json::Value = serde_json::to_value(&rules).unwrap();
    assert!(saved["names"].get("alert_channel").is_none());
    assert_eq!(saved["alert_channel"], 7);
}
