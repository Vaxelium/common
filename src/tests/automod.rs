use super::*;

fn rules(words: &[&str], links: bool) -> AutoMod {
    AutoMod {
        words: WordRule {
            enabled: true,
            words: words.iter().map(|w| w.to_string()).collect(),
            ..WordRule::default()
        },
        block_links: links,
        ..AutoMod::default()
    }
}

#[test]
fn filtered_words_match_whole_words_only() {
    let r = rules(&["ass", "bad phrase"], false).words;
    assert!(r.find("what an ASS").is_some(), "case does not matter");
    assert!(r.find("ass!").is_some(), "punctuation ends a word");
    assert!(r.find("a class act").is_none(), "not inside a longer word");
    assert!(r.find("this is a Bad Phrase here").is_some());
    assert!(r.find("bad phrases").is_none());
    assert!(r.find("hello").is_none());
}

#[test]
fn filtered_words_do_nothing_when_the_rule_is_off() {
    let mut r = rules(&["ass"], false).words;
    r.enabled = false;
    assert!(r.find("what an ass").is_none());
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
    assert_eq!(r.words.words, vec!["bad".to_string(), "x".to_string()]);
    let many: Vec<String> = (0..MAX_BLOCKED_WORDS + 10).map(|i| format!("w{i}")).collect();
    let r = AutoMod {
        words: WordRule {
            words: many,
            ..WordRule::default()
        },
        ..AutoMod::default()
    }
    .tidied();
    assert_eq!(r.words.words.len(), MAX_BLOCKED_WORDS);
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

#[test]
fn mentions_are_counted_once_each() {
    let members = vec!["bob".to_string(), "bobby".to_string()];
    let roles = vec!["Admins".to_string()];
    assert_eq!(mentioned_count("hi @bob and @bob again", &members, &roles), 1);
    assert_eq!(
        mentioned_count("@bobby is not @bob", &members, &roles),
        2,
        "a longer name is its own mention"
    );
    assert_eq!(
        mentioned_count("@Admins and @bob", &members, &roles),
        2,
        "roles count too"
    );
    assert_eq!(
        mentioned_count("bob and @bobs", &members, &roles),
        0,
        "needs the @ and a whole name"
    );
}

#[test]
fn mention_rule_is_tidied_within_limits() {
    let r = AutoMod {
        mentions: MentionRule {
            max_unique: 0,
            timeout_secs: u64::MAX,
            ..MentionRule::default()
        },
        ..AutoMod::default()
    }
    .tidied();
    assert_eq!(r.mentions.max_unique, 1);
    assert_eq!(r.mentions.timeout_secs, MAX_TIMEOUT_SECS);
    assert_eq!(MentionRule::default().max_unique, 5);
    assert!(!MentionRule::default().enabled);
}

#[test]
fn mention_rule_defaults_block_and_alert() {
    let old: AutoMod = serde_json::from_str(r#"{"mentions":{"enabled":true}}"#).unwrap();
    assert!(old.mentions.block, "an older rule still blocks");
    assert!(old.mentions.send_alert, "and still alerts");
    assert!(old.mentions.allowed_roles.is_empty());
}

#[test]
fn mention_notice_is_trimmed_and_limited() {
    let r = AutoMod {
        mentions: MentionRule {
            notice: format!("  {}  ", "x".repeat(MAX_NOTICE_LEN + 50)),
            ..MentionRule::default()
        },
        ..AutoMod::default()
    }
    .tidied();
    assert_eq!(r.mentions.notice.len(), MAX_NOTICE_LEN);
    assert!(MentionRule::default().notice.is_empty());
}

#[test]
fn name_notice_is_trimmed_and_limited() {
    let r = AutoMod {
        names: NameRule {
            notice: format!("  {}  ", "n".repeat(MAX_NOTICE_LEN + 9)),
            ..NameRule::default()
        },
        ..AutoMod::default()
    }
    .tidied();
    assert_eq!(r.names.notice.len(), MAX_NOTICE_LEN);
}

/// A rule that is on, with the given categories switched on.
fn on(categories: &[ModerationCategory]) -> FlaggedWords {
    let mut f = FlaggedWords {
        enabled: true,
        ..FlaggedWords::default()
    };
    for c in categories {
        f.set(*c, true);
    }
    f
}

fn word_of(f: &FlaggedWords, text: &str) -> Option<String> {
    f.flags(text).map(|flag| flag.word)
}

#[test]
fn flagged_words_follow_the_chosen_categories() {
    let f = on(&[ModerationCategory::SevereProfanity]);
    let flag = f.flags("well, SHIT").expect("shit is listed");
    assert_eq!(flag.word, "shit");
    assert_eq!(flag.category, ModerationCategory::SevereProfanity);
    assert_eq!(flag.severity, ModerationSeverity::High);
    assert!(f.flags("you idiot").is_none(), "insults are not on");
    assert!(on(&[ModerationCategory::GeneralInsults]).flags("you idiot").is_some());
    assert!(on(&[ModerationCategory::SexualContent]).flags("nsfw stuff").is_some());
    assert!(!FlaggedWords::default().is_on(ModerationCategory::Spam));
}

#[test]
fn flagged_words_match_whole_words_only() {
    let f = on(&[ModerationCategory::SevereProfanity]);
    assert!(f.flags("a classy night").is_none(), "not inside a longer word");
    assert!(f.flags("a glass of water").is_none());
}

#[test]
fn allowed_words_and_off_rules_do_not_flag() {
    let mut f = on(&[ModerationCategory::SevereProfanity]);
    f.allow = vec!["Shit".into()];
    assert!(f.flags("shit happens").is_none(), "an allowed word is not flagged");
    let off = FlaggedWords {
        enabled: false,
        ..on(&[ModerationCategory::SevereProfanity, ModerationCategory::GeneralInsults])
    };
    assert!(off.flags("shit idiot").is_none());
}

#[test]
fn flagged_rule_is_tidied() {
    let r = AutoMod {
        flagged: FlaggedWords {
            allow: vec!["  Shit ".into(), "shit".into(), "".into()],
            allowed_roles: vec![3, 1, 3],
            allowed_channels: vec![9, 9],
            notice: format!("  {}  ", "x".repeat(MAX_NOTICE_LEN + 5)),
            ..FlaggedWords::default()
        },
        ..AutoMod::default()
    }
    .tidied();
    assert_eq!(r.flagged.allow, vec!["shit".to_string()]);
    assert_eq!(r.flagged.allowed_roles, vec![1, 3]);
    assert_eq!(r.flagged.allowed_channels, vec![9]);
    assert_eq!(r.flagged.notice.chars().count(), MAX_NOTICE_LEN);
}

#[test]
fn flagged_words_see_through_spelling_tricks() {
    let f = on(&[ModerationCategory::SevereProfanity]);
    assert!(f.flags("what the sh1t").is_some(), "leetspeak");
    assert!(f.flags("f.u.c.k off").is_some(), "separators between letters");
    assert!(f.flags("fuuuuck").is_some(), "repeated letters");
    assert!(f.flags("s h i t").is_some(), "letters spaced apart");
    assert!(f.flags("bullshit").is_some(), "a word with a double letter");
    assert!(f.flags("bulshit").is_some());
    assert!(f.flags("so many shits").is_some(), "plurals");
    assert!(f.flags("a clean sentence about cats").is_none());
}

#[test]
fn allowances_and_plurals_fold_too() {
    let mut f = on(&[ModerationCategory::GeneralInsults]);
    assert!(f.flags("stop being idiots").is_some());
    f.allow = vec!["Id1ot".into()];
    assert!(f.flags("you idiot").is_none(), "an allowance is folded the same way");
}

#[test]
fn phrases_match_word_by_word() {
    let f = on(&[ModerationCategory::SevereProfanity]);
    assert_eq!(word_of(&f, "I said up yours, mate").as_deref(), Some("up yours"));
    assert!(f.flags("look up at yours").is_none(), "the words must come together");
}

#[test]
fn context_words_need_someone_to_be_addressed() {
    let f = on(&[ModerationCategory::SexualContent]);
    assert!(f.flags("what a nice ass view").is_none(), "not addressed to anyone");
    assert_eq!(word_of(&f, "you ass").as_deref(), Some("ass"), "addressed with you");
    let g = on(&[ModerationCategory::MildProfanity]);
    assert!(g.flags("that was hell of a game").is_none());
    assert!(g.flags("your hell is showing").is_some());
}

#[test]
fn a_strong_word_flags_alongside_context_words_and_the_worst_wins() {
    let f = on(&[ModerationCategory::SevereProfanity, ModerationCategory::MildProfanity]);
    let flag = f.flags("hell, shit").expect("both are listed");
    assert_eq!(flag.word, "shit", "the more severe word is reported");
    assert_eq!(flag.severity, ModerationSeverity::High);
    assert!(f.flags("hell of a day").is_none(), "a context word alone is fine");
}

#[test]
fn threats_identity_slurs_harassment_and_spam_are_listed() {
    assert_eq!(
        on(&[ModerationCategory::Threats])
            .flags("I'll kill you tomorrow")
            .map(|f| f.severity),
        Some(ModerationSeverity::Critical)
    );
    assert!(on(&[ModerationCategory::IdentityBasedSlurs]).flags("you retards").is_some());
    assert!(on(&[ModerationCategory::SexualHarassment]).flags("send nudes").is_some());
    assert!(on(&[ModerationCategory::Spam]).flags("FREE NITRO!!").is_some());
    assert!(on(&[ModerationCategory::Spam]).flags("hello there").is_none());
}

#[test]
fn old_rules_read_insults_slurs_as_general_insults() {
    let old: FlaggedWords = serde_json::from_str(r#"{"enabled":true,"insults_slurs":true}"#).unwrap();
    assert!(old.general_insults && old.enabled);
    assert!(!old.identity_slurs, "identity slurs are a category of their own now");
}

fn filtered(patterns: &[&str]) -> FilteredWords {
    FilteredWords {
        enabled: true,
        patterns: patterns.iter().map(|p| p.to_string()).collect(),
        ..FilteredWords::default()
    }
}

#[test]
fn default_filters_are_the_presets() {
    let f = FilteredWords {
        enabled: true,
        ..FilteredWords::default()
    };
    assert_eq!(f.find("see https://example.com now").as_deref(), Some("https://example.com"));
    assert_eq!(f.find("hi @bob there").as_deref(), Some("@bob"));
    assert_eq!(f.find("join discord.gg/abc").as_deref(), Some("discord.gg/abc"));
    assert_eq!(f.find("LOUD SHOUTING").as_deref(), Some("SHOUTING"));
    assert!(f.find("quiet and tidy").is_none());
}

#[test]
fn case_follows_the_pattern() {
    assert!(filtered(&["(?i)https?://"]).find("HTTPS://X").is_some());
    assert!(filtered(&["[A-Z]{5,}"]).find("hello").is_none(), "no flag ignores case");
    assert!(filtered(&["[A-Z]{5,}"]).find("HELLO").is_some());
}

#[test]
fn repeated_characters_are_found_by_hand() {
    let f = FilteredWords {
        enabled: true,
        patterns: vec![],
        repeated_chars: true,
        ..FilteredWords::default()
    };
    assert_eq!(f.find("nooooooo").as_deref(), Some("ooooooo"));
    assert_eq!(f.find("AAAAAhh").as_deref(), Some("AAAAA"), "ignores case");
    assert!(f.find("noooo wait").is_none(), "four in a row is fine");
}

#[test]
fn off_rules_and_bad_patterns_match_nothing() {
    let off = FilteredWords {
        enabled: false,
        ..filtered(&["hello"])
    };
    assert!(off.find("hello").is_none());
    assert!(filtered(&["("]).find("hello").is_none(), "a pattern that does not compile matches nothing");
}

#[test]
fn filtered_rule_is_tidied() {
    let r = AutoMod {
        filtered: FilteredWords {
            patterns: vec!["  foo ".into(), "foo".into(), "(".into(), "".into()],
            allowed_roles: vec![2, 1, 2],
            ..FilteredWords::default()
        },
        ..AutoMod::default()
    }
    .tidied();
    assert_eq!(r.filtered.patterns, vec!["foo".to_string()]);
    assert_eq!(r.filtered.allowed_roles, vec![1, 2]);
}

#[test]
fn repeated_limit_is_the_rule_setting() {
    let f = FilteredWords {
        enabled: true,
        patterns: vec![],
        repeated_chars: true,
        repeated_limit: 3,
        ..FilteredWords::default()
    };
    assert_eq!(f.find("baaad").as_deref(), Some("aaa"), "three in a row is enough at 3");
    assert!(f.find("noo").is_none(), "two is not");
    let r = AutoMod {
        filtered: FilteredWords {
            repeated_limit: 500,
            ..FilteredWords::default()
        },
        ..AutoMod::default()
    }
    .tidied();
    assert_eq!(r.filtered.repeated_limit, MAX_REPEATED, "clamped to the most allowed");
}

#[test]
fn every_preset_compiles_and_matches_its_sample() {
    let samples = [
        ("URLs", "see https://example.com"),
        ("Mentions", "hi @bob"),
        ("Invite links", "join discord.gg/abc"),
        ("Caps spam", "LOUD SHOUTING"),
        ("Capitals", "THIS IS SHOUTING IN TEN"),
        ("Spoilers", "a ||hidden|| bit"),
        ("Emojis", "😀😀😀😀😀"),
        ("Headers", "# Big title"),
        ("Unicode", "zal̴̴̴go"),
        ("Code blocks", "use `code` here"),
        ("Bullet lists", "intro\n- first item"),
        ("Embedded links", "[click](https://example.com)"),
        ("Embedded links", "[click](HTTPS://EXAMPLE.COM)"),
        ("Emails", "mail bob@example.com today"),
    ];
    for (name, text) in samples {
        let (_, pattern) = PRESET_FILTERS.iter().find(|(n, _)| *n == name).expect(name);
        let re = regex::Regex::new(pattern).unwrap_or_else(|e| panic!("{name} does not compile: {e}"));
        assert!(re.is_match(text), "{name} should match {text:?}");
    }
    let mentions = PRESET_FILTERS.iter().find(|(n, _)| *n == "Mentions").unwrap().1;
    let re = regex::Regex::new(mentions).unwrap();
    assert!(!re.is_match("mail me at bob@example.com"), "an email address is not a mention");
    assert!(FilteredWords::default().patterns.len() == 4, "new filters start with the four defaults");
}

#[test]
fn every_listed_word_is_still_flagged() {
    // Plural forms and spelling variants are matched from the base word, so dropping a plural from a
    // list must not lose it. Context words are only flagged when addressed, so they are tested that way.
    for category in ModerationCategory::ALL {
        let mut f = FlaggedWords::default();
        f.enabled = true;
        f.set(category, true);
        for word in category.words() {
            let text = if AMBIGUOUS_WORDS.iter().any(|a| fold_phrase(a) == fold_phrase(word)) {
                format!("you {word}")
            } else {
                word.to_string()
            };
            assert!(f.flags(&text).is_some(), "{category:?}: {word:?} should be flagged");
        }
    }
}

#[test]
fn any_rule_on_follows_the_switches() {
    assert!(!AutoMod::default().any_rule_on(), "nothing is on at first");
    assert!(AutoMod { block_links: true, ..AutoMod::default() }.any_rule_on());
    let mut flagged = AutoMod::default();
    flagged.flagged.enabled = true;
    assert!(flagged.any_rule_on());
}
