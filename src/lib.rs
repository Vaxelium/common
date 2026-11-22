//! Wire protocol shared by the Vaxelium server and client.
//!
//! Every message is one JSON object per line (newline-delimited JSON) over TCP.

use serde::{Deserialize, Serialize};

pub mod env;
#[cfg(not(target_arch = "wasm32"))]
pub mod tls;

/// Default address of a chat server.
pub const DEFAULT_ADDR: &str = "127.0.0.1:7878";
/// Default address of the auth service that owns all accounts.
pub const DEFAULT_AUTH_ADDR: &str = "127.0.0.1:7900";
/// UDP port for finding servers on the local network (see the server's discovery module).
pub const DISCOVERY_PORT: u16 = 7879;
/// Longest server description, in characters.
pub const MAX_SERVER_DESCRIPTION_LEN: usize = 1000;
/// Largest server icon, as base64 text (a 128x128 PNG is far smaller than this).
pub const MAX_SERVER_ICON_LEN: usize = 256 * 1024;
/// Largest profile picture, as base64 text. Same limit as a server icon.
pub const MAX_AVATAR_LEN: usize = MAX_SERVER_ICON_LEN;

/// Requests sent to the auth service. One JSON line per request, one reply line back.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthRequest {
    Register {
        name: String,
        email: String,
        password: String,
    },
    Login {
        email: String,
        password: String,
    },
    /// Ask who a session token belongs to. Used by chat servers.
    Verify {
        token: String,
    },
    /// End a session so its token stops working.
    Logout {
        token: String,
    },
    /// Ask for the account's names and email. Needs a valid session.
    Profile {
        token: String,
    },
    /// Change the name shown in chat, the username, or both. Needs a valid session. A new username needs the
    /// account's current password, as a change of email does.
    UpdateProfile {
        token: String,
        name: Option<String>,
        username: Option<String>,
        #[serde(default)]
        password: Option<String>,
    },
    /// Ask for a code to confirm the account's email address. The code is emailed to it. Needs a session.
    RequestEmailCode {
        token: String,
    },
    /// Confirm the account's email address with the code that was emailed. Needs a session.
    VerifyEmail {
        token: String,
        code: String,
    },
    /// Change the account's email. Needs the session and the current password.
    ChangeEmail {
        token: String,
        password: String,
        new_email: String,
    },
    /// Find an account by its display name. Used to start a direct message with someone who is not
    /// on the same server.
    Lookup {
        name: String,
    },
    /// A chat server reports that the account of `token` was connected at `addr`.
    Seen {
        token: String,
        addr: String,
    },
    /// Ask which servers an account was last seen at, most recent first.
    Locate {
        id: String,
    },
    /// A chat server reports each member's mention total on it, so the auth service can show a count on the
    /// server's icon while the member is elsewhere. The server connects with its own certificate (see
    /// `tls::connect_async_with_identity`). The first certificate reported for a server is the one trusted after
    /// it. Replies `MentionsRecorded`.
    ReportMentions {
        server_id: String,
        totals: Vec<MentionTotal>,
    },
    /// Ask for the account's mention totals on each server that reported them. Needs a valid session.
    MentionTotals {
        token: String,
    },
    /// Ask for an account's public profile card, by its id. Needs no session.
    /// `token` is the viewer's session, when there is one. With it the card lists the servers the viewer
    /// and the member share.
    ProfileCard {
        id: String,
        #[serde(default)]
        token: String,
    },
    /// Report the servers this account is in, by address. The client sends it after connecting, so other
    /// people's cards can show the servers they share with the viewer. Needs a valid session.
    SetServers {
        token: String,
        servers: Vec<String>,
    },
    /// Change the account's bio and profile banner colour. Needs a valid session.
    SetAbout {
        token: String,
        bio: String,
        banner: String,
    },
    /// Set the account's status text, shown in a bubble on its profile card. Empty clears it.
    SetStatusText {
        token: String,
        text: String,
    },
    /// Set or remove (`None`) the account's profile picture, a PNG as base64. Needs a valid session.
    SetAvatar {
        token: String,
        png_base64: Option<String>,
    },
    /// Ask for the new ids of accounts that had their old id (their name) migrated to a random one.
    /// Used by chat servers to update what they stored under the old ids.
    Migrations {
        old_ids: Vec<String>,
    },
    /// Start a login with Discord, or, when `token` is a session, link a Discord account to that account.
    /// The reply is the Discord page to open and the `state` to pass to `DiscordPoll`.
    DiscordStart {
        #[serde(default)]
        token: String,
    },
    /// Ask whether the Discord login with this `state` has finished. Replies `DiscordPending` until the
    /// browser comes back. Then it completes: `Session` for a login, `DiscordLinked` for a link.
    DiscordPoll {
        state: String,
    },
    /// Set a password on an account that has none, such as one made with Discord. Needs a valid session.
    SetPassword {
        token: String,
        password: String,
    },
    /// Change the password of an account that has one. Needs a valid session and the current password.
    ChangePassword {
        token: String,
        current: String,
        password: String,
    },
    /// Permanently delete the session's account. Needs the current password, so an account without one
    /// must set one first. Needs a valid session.
    DeleteAccount {
        token: String,
        password: String,
    },
    /// Ask which outside accounts are linked to the session's account. Needs a valid session.
    LinkedAccounts {
        token: String,
    },
    /// Remove the link to the session's Discord account. Refused for accounts that have no password,
    /// since they could no longer log in. Needs a valid session.
    UnlinkDiscord {
        token: String,
    },
}

/// Replies from the auth service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthReply {
    /// Register or login succeeded. Keep `token` and send it to chat servers.
    Session {
        token: String,
        name: String,
    },
    /// The token is valid for this account.
    /// `id` identifies the account in chat; `name` is the name to show.
    Verified {
        id: String,
        name: String,
    },
    LoggedOut,
    /// The account's display name, username, and email if one is on record.
    /// `verified` is true once the account has confirmed its email address.
    Profile {
        name: String,
        username: String,
        email: Option<String>,
        #[serde(default)]
        verified: bool,
        /// True when this server can send email, so an address can be confirmed.
        #[serde(default)]
        can_verify: bool,
        /// The account's bio and profile banner colour (`#rrggbb`, or empty for the default).
        #[serde(default)]
        bio: String,
        #[serde(default)]
        banner: String,
        /// The profile picture as base64 PNG, or empty for none.
        #[serde(default)]
        avatar: String,
        /// False for an account made with Discord that has no password yet.
        #[serde(default)]
        has_password: bool,
    },
    /// An account's public profile card.
    ProfileCard {
        name: String,
        username: String,
        bio: String,
        banner: String,
        #[serde(default)]
        avatar: String,
        /// The status text in the bubble on the card. Empty when none is set.
        #[serde(default)]
        status: String,
        /// The servers (by address) that the viewer and this member are both in. Empty without a session.
        #[serde(default)]
        mutual: Vec<String>,
        /// When the account was created, in Unix seconds (0 when unknown).
        #[serde(default)]
        created: u64,
    },
    /// The profile picture was saved (empty when it was removed).
    AvatarSaved {
        avatar: String,
    },
    /// The bio and banner were saved.
    AboutSaved {
        bio: String,
        banner: String,
    },
    /// The status text was saved (empty when cleared).
    StatusTextSaved {
        text: String,
    },
    /// The servers were saved.
    ServersSaved,
    /// The confirmation code was emailed.
    CodeSent,
    /// The email address is confirmed.
    EmailVerified,
    /// The email was changed to this one.
    EmailChanged {
        email: String,
    },
    /// The account with the display name that was looked up.
    Account {
        id: String,
        name: String,
    },
    /// The servers an account was last seen at, most recent first.
    Locations {
        addrs: Vec<String>,
    },
    /// The (old id, new id) pairs for the old ids asked about that were migrated.
    Migrations {
        pairs: Vec<(String, String)>,
    },
    /// A sighting was recorded.
    Recorded,
    /// The mention totals were recorded.
    MentionsRecorded,
    /// The account's mention totals on each server that reported them.
    MentionTotals {
        totals: Vec<ServerMentions>,
    },
    /// The Discord page to open, and the state to poll with.
    DiscordUrl {
        url: String,
        state: String,
    },
    /// The Discord login has not finished yet. Poll again.
    DiscordPending,
    /// A Discord account was linked to the session's account. `discord` is its name.
    DiscordLinked {
        discord: String,
    },
    /// The password was set.
    PasswordSet,
    /// The password was changed.
    PasswordChanged,
    /// The account was deleted.
    AccountDeleted,
    /// The Discord account linked to the session's account, by its display name (None when not linked),
    /// and whether that link can be removed.
    LinkedAccounts {
        discord: Option<String>,
        can_unlink_discord: bool,
    },
    /// The Discord link was removed.
    DiscordUnlinked,
    Error {
        text: String,
    },
}

pub mod emoji_data;

/// The five skin tone variants of an emoji (light to dark), if it has them.
pub fn skin_tone_variants(emoji: &str) -> Option<&'static [&'static str; 5]> {
    emoji_data::SKIN_TONES
        .iter()
        .find(|(base, _)| *base == emoji)
        .map(|(_, variants)| variants)
}

/// The quick reactions on a message's toolbar.
pub const QUICK_REACTIONS: [&str; 3] = ["👍", "❤️", "😂"];

/// True for a reaction the server accepts: any emoji, as a short run of visible characters.
pub fn is_reaction(emoji: &str) -> bool {
    // A custom emoji's reaction is its name in colons, which can be longer than a picture emoji.
    let longest = if custom_emoji_name(emoji).is_some() { 34 } else { 16 };
    !emoji.is_empty() && emoji.chars().count() <= longest && emoji.chars().all(|c| !c.is_control() && !c.is_whitespace())
}

/// The name of a custom emoji, when `emoji` is one written as `:name:` (see `CustomEmoji`). None for any
/// other reaction, such as a picture emoji.
pub fn custom_emoji_name(emoji: &str) -> Option<&str> {
    let name = emoji.strip_prefix(':')?.strip_suffix(':')?;
    let valid = (2..=32).contains(&name.chars().count())
        && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    valid.then_some(name)
}
/// One emoji on a message, and who reacted with it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reaction {
    pub emoji: String,
    pub users: Vec<String>,
}

/// Why the message rules refused a message: the sentence for the member, the rule that caught it, and the word
/// it matched, if any.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Breach {
    pub reason: String,
    pub rule: &'static str,
    pub keyword: String,
}

/// What AutoMod's report of a caught message says: who sent it, where, which rule caught it, on what keyword,
/// and the message itself. Empty `content` means there was no message, such as a flagged name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoModReport {
    /// The member's account id, so the report can show their picture.
    pub user_id: String,
    pub display: String,
    /// The channel the message was sent in, and its name. Zero and empty for a name alert.
    #[serde(default)]
    pub channel_id: i64,
    pub channel: String,
    pub rule: String,
    pub keyword: String,
    pub content: String,
}

/// A single chat message as stored and broadcast by the server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    /// Unique id, given by the server when the message is saved. 0 until then.
    #[serde(default)]
    pub id: i64,
    /// The channel's permanent id. It does not change when the channel is renamed.
    #[serde(default)]
    pub channel_id: i64,
    pub channel: String,
    /// The author's name to show.
    pub author: String,
    /// The author's hidden account id. Stays the same when the name changes.
    #[serde(default)]
    pub author_id: String,
    pub text: String,
    /// Unix timestamp in seconds.
    pub timestamp: u64,
    /// True once the author has edited the message.
    #[serde(default)]
    pub edited: bool,
    /// Reactions on the message, in the order they were first added.
    #[serde(default)]
    pub reactions: Vec<Reaction>,
    /// The message this one answers, when it is a reply.
    #[serde(default)]
    pub reply: Option<ReplyRef>,
    /// True while the message is pinned in its channel.
    #[serde(default)]
    pub pinned: bool,
    /// For a message AutoMod posted about a caught message: the details the client shows in a card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<AutoModReport>,
    /// A picture the message shows, as base64 PNG. The server draws it for join notices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

/// The Filtered Words rule: words and phrases a message may not contain, with its own response.
/// Members with Administrator or Manage Server, and members holding one of the allowed roles or sitting in one
/// of the allowed channels, are left alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WordRule {
    #[serde(default)]
    pub enabled: bool,
    /// Words and phrases a message may not contain, matched without regard to case (see `matches`).
    #[serde(default)]
    pub words: Vec<String>,
    /// Refuse a message that matches. Off, the message goes through and only the alert applies.
    #[serde(default = "default_true")]
    pub block: bool,
    /// Post a report to AutoMod's channel when the rule catches a message.
    #[serde(default = "default_true")]
    pub send_alert: bool,
    /// The notice a member sees when their message is blocked. Empty means the standard reason.
    #[serde(default)]
    pub notice: String,
    #[serde(default)]
    pub allowed_roles: Vec<i64>,
    #[serde(default)]
    pub allowed_channels: Vec<i64>,
}

impl Default for WordRule {
    fn default() -> Self {
        Self {
            enabled: false,
            words: Vec::new(),
            block: true,
            send_alert: true,
            notice: String::new(),
            allowed_roles: Vec::new(),
            allowed_channels: Vec::new(),
        }
    }
}

impl WordRule {
    /// The listed word that `text` contains, or None when it does not (or the rule is off).
    pub fn find(&self, text: &str) -> Option<String> {
        if !self.enabled {
            return None;
        }
        let lower = text.to_lowercase();
        self.words.iter().find(|w| matches(&lower, w)).cloned()
    }
}

/// The messages a server posts on its own, such as "X connected", and the channel they go to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SystemMessages {
    /// Post "X connected" when a member connects. On by default.
    #[serde(default = "default_true")]
    pub connect_notice: bool,
    /// The channel system messages are posted to. None posts them to the channel the member connected in.
    #[serde(default)]
    pub channel_id: Option<i64>,
}

impl Default for SystemMessages {
    fn default() -> Self {
        Self {
            connect_notice: true,
            channel_id: None,
        }
    }
}

/// One ban on a server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BanInfo {
    /// The banned account's hidden id.
    pub user: String,
    /// Its display name, as far as the server knows it.
    pub name: String,
    /// The reason given, or empty.
    #[serde(default)]
    pub reason: String,
    /// The display name of the member who banned them.
    #[serde(default)]
    pub by: String,
    /// When the ban was made (Unix seconds).
    #[serde(default)]
    pub at: u64,
}

/// A server's automatic moderation rules. Members who may manage messages in a channel are not held to
/// the message rules there, and direct messages are never checked.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoMod {
    /// The Filtered Words rule.
    #[serde(default)]
    pub words: WordRule,
    /// Refuse messages with web links in them.
    #[serde(default)]
    pub block_links: bool,
    /// Refuse a member's message when they have sent `SPAM_LIMIT` in the last `SPAM_WINDOW_SECS`.
    #[serde(default)]
    pub spam_filter: bool,
    /// The rule for members' names.
    #[serde(default)]
    pub names: NameRule,
    /// The channel AutoMod reports to: every time it blocks something, and when it flags a name.
    #[serde(default)]
    pub alert_channel: Option<i64>,
    /// The rule for mentions: how many people and roles one message may ping.
    #[serde(default)]
    pub mentions: MentionRule,
    /// The rule for flagged words: built-in word lists, chosen by category, plus the server's own allowances.
    #[serde(default)]
    pub flagged: FlaggedWords,
    /// The rule for filtered words: regular expressions a message may not match, and repeated characters.
    #[serde(default)]
    pub filtered: FilteredWords,
}

/// Refuses messages that contain words from the chosen built-in lists, less any words the server allows.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlaggedWords {
    /// Whether the rule is on at all.
    #[serde(default)]
    pub enabled: bool,
    /// Which categories of built-in list the rule uses. A category is one of `ModerationCategory`.
    #[serde(default)]
    pub severe_profanity: bool,
    #[serde(default)]
    pub mild_profanity: bool,
    /// Older rules called this `insults_slurs`; it is read under that name too.
    #[serde(default, alias = "insults_slurs")]
    pub general_insults: bool,
    #[serde(default)]
    pub identity_slurs: bool,
    #[serde(default)]
    pub sexual_content: bool,
    #[serde(default)]
    pub sexual_harassment: bool,
    #[serde(default)]
    pub threats: bool,
    #[serde(default)]
    pub spam: bool,
    /// Words and phrases the server allows even though a list has them. Matched like the blocked words.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Refuse a message that contains a flagged word. Off, the message goes through and only the alert applies.
    #[serde(default = "default_true")]
    pub block: bool,
    /// Post a report to AutoMod's channel when the rule catches a message.
    #[serde(default = "default_true")]
    pub send_alert: bool,
    /// The notice a member sees when their message is blocked. Empty means the standard reason.
    #[serde(default)]
    pub notice: String,
    /// Roles and channels the rule leaves alone. Members with Manage Server are always left alone.
    #[serde(default)]
    pub allowed_roles: Vec<i64>,
    #[serde(default)]
    pub allowed_channels: Vec<i64>,
}

impl Default for FlaggedWords {
    fn default() -> Self {
        Self {
            enabled: false,
            severe_profanity: false,
            mild_profanity: false,
            general_insults: false,
            identity_slurs: false,
            sexual_content: false,
            sexual_harassment: false,
            threats: false,
            spam: false,
            allow: Vec::new(),
            block: true,
            send_alert: true,
            notice: String::new(),
            allowed_roles: Vec::new(),
            allowed_channels: Vec::new(),
        }
    }
}

/// The kinds of language the flagged words rule knows about. Each has its own list and a severity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationCategory {
    SevereProfanity,
    MildProfanity,
    GeneralInsults,
    IdentityBasedSlurs,
    SexualContent,
    SexualHarassment,
    Threats,
    Spam,
}

/// How serious a flagged word is. Higher is worse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModerationSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl ModerationCategory {
    /// Every category, in the order the rule's page shows them.
    pub const ALL: [ModerationCategory; 8] = [
        ModerationCategory::SevereProfanity,
        ModerationCategory::MildProfanity,
        ModerationCategory::GeneralInsults,
        ModerationCategory::IdentityBasedSlurs,
        ModerationCategory::SexualContent,
        ModerationCategory::SexualHarassment,
        ModerationCategory::Threats,
        ModerationCategory::Spam,
    ];

    /// The words this category's list holds.
    pub fn words(self) -> &'static [&'static str] {
        match self {
            ModerationCategory::SevereProfanity => SEVERE_PROFANITY_WORDS,
            ModerationCategory::MildProfanity => MILD_PROFANITY_WORDS,
            ModerationCategory::GeneralInsults => GENERAL_INSULTS_WORDS,
            ModerationCategory::IdentityBasedSlurs => IDENTITY_SLURS_WORDS,
            ModerationCategory::SexualContent => SEXUAL_CONTENT_WORDS,
            ModerationCategory::SexualHarassment => SEXUAL_HARASSMENT_WORDS,
            ModerationCategory::Threats => THREATS_WORDS,
            ModerationCategory::Spam => SPAM_WORDS,
        }
    }

    /// How serious a match in this category is.
    pub fn severity(self) -> ModerationSeverity {
        match self {
            ModerationCategory::MildProfanity | ModerationCategory::Spam => ModerationSeverity::Low,
            ModerationCategory::GeneralInsults | ModerationCategory::SexualContent => ModerationSeverity::Medium,
            ModerationCategory::SevereProfanity | ModerationCategory::SexualHarassment => ModerationSeverity::High,
            ModerationCategory::IdentityBasedSlurs | ModerationCategory::Threats => ModerationSeverity::Critical,
        }
    }

    /// The name shown for the category, lower-cased, as used in reports.
    pub fn name(self) -> &'static str {
        match self {
            ModerationCategory::SevereProfanity => "severe profanity",
            ModerationCategory::MildProfanity => "mild profanity",
            ModerationCategory::GeneralInsults => "insults",
            ModerationCategory::IdentityBasedSlurs => "identity-based slurs",
            ModerationCategory::SexualContent => "sexual content",
            ModerationCategory::SexualHarassment => "sexual harassment",
            ModerationCategory::Threats => "threats",
            ModerationCategory::Spam => "spam",
        }
    }
}

/// What the flagged words rule found in a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flag {
    /// The listed word or phrase that matched.
    pub word: String,
    pub category: ModerationCategory,
    pub severity: ModerationSeverity,
}

/// The built-in word lists, one for each `ModerationCategory` (see `ModerationCategory::words`). They are a
/// starting point, and a server can allow any word in them. An entry is a base word: its plural forms are
/// matched too, and the spelling tricks that `fold_word` undoes. A phrase matches its words in order.

/// Severe profanity: the strongest swear words.
pub const SEVERE_PROFANITY_WORDS: &[&str] = &[
    "fuck",
    "fucking",
    "fucked",
    "fucker",
    "fuckface",
    "fuckhead",
    "fuckwit",
    "motherfucker",
    "motherfucking",
    "shit",
    "shitty",
    "shithead",
    "shitface",
    "bullshit",
    "horseshit",
    "dipshit",
    "shitbag",
    "shitshow",
    "shitstorm",
    "shitstain",
    "cunt",
    "cunting",
    "asshole",
    "arsehole",
    "bastard",
    "bitch",
    "bitching",
    "sonofabitch",
    "dick",
    "dickhead",
    "dickwad",
    "dickweed",
    "prick",
    "wanker",
    "wank",
    "wanking",
    "twat",
    "tosser",
    "bellend",
    "knob",
    "knobhead",
    "pillock",
    "cocksucker",
    "cockhead",
    "cockwomble",
    "fuck off",
    "fuck you",
    "fuck this",
    "fuck that",
    "fuck sake",
    "for fuck sake",
    "what the fuck",
    "who the fuck",
    "holy shit",
    "piece of shit",
    "full of shit",
    "eat shit",
    "kiss my ass",
    "up yours",
    "shut the fuck up",
    "go fuck yourself",
    "son of a bitch",
];

/// Mild profanity: swearing that many communities allow.
pub const MILD_PROFANITY_WORDS: &[&str] = &[
    "bollocks",
    "bugger",
    "buggered",
    "git",
    "piss",
    "pissed",
    "pisser",
    "pisshead",
    "piss off",
    "pissflaps",
    "goddamn",
    "goddammit",
    "damn",
    "dammit",
    "hell",
    "crap",
    "crappy",
    "crapper",
    "bollocking",
    "buggery",
];

/// General insults and put-downs, not aimed at an identity.
pub const GENERAL_INSULTS_WORDS: &[&str] = &[
    "idiot",
    "idiotic",
    "moron",
    "moronic",
    "imbecile",
    "dumbass",
    "dumbfuck",
    "stupid",
    "stupidity",
    "loser",
    "clown",
    "jerk",
    "dork",
    "nitwit",
    "halfwit",
    "numbskull",
    "scumbag",
    "degenerate",
    "dipstick",
    "bonehead",
    "airhead",
    "blockhead",
    "meathead",
    "lowlife",
    "low life",
    "douche",
    "douchebag",
    "jackass",
    "asshat",
    "assclown",
    "tool",
    "buffoon",
    "fool",
    "creep",
    "weirdo",
    "psycho",
    "lunatic",
    "coward",
    "pathetic",
    "worthless",
    "disgusting",
    "vile",
    "garbage human",
    "waste of space",
    "piece of garbage",
    "piece of trash",
    "incompetent",
    "ignoramus",
    "twit",
    "cretin",
    "simpleton",
    "ugly",
    "fatass",
    "skinny freak",
    "failure",
    "nobody",
    "nuisance",
    "parasite",
    "leech",
    "attention seeker",
    "clueless idiot",
    "absolute moron",
    "complete idiot",
    "stupid prick",
    "worthless idiot",
    "pathetic loser",
];

/// Identity-based slurs, such as ableist terms.
pub const IDENTITY_SLURS_WORDS: &[&str] = &[
    "retard",
    "retarded",
    "spastic",
    "spaz",
    "spazzy",
];

/// Sexually explicit content: adult sites, nudity and sexual acts.
pub const SEXUAL_CONTENT_WORDS: &[&str] = &[
    "porn",
    "porno",
    "pornography",
    "pornographic",
    "pornhub",
    "xxx",
    "nsfw",
    "adult content",
    "adult video",
    "adult film",
    "hentai",
    "rule34",
    "r34",
    "onlyfans",
    "fansly",
    "erotica",
    "erotic",
    "sexually explicit",
    "nude",
    "nudity",
    "naked",
    "topless",
    "bottomless",
    "undressed",
    "striptease",
    "stripping",
    "flash me",
    "sexting",
    "horny",
    "aroused",
    "masturbation",
    "masturbate",
    "masturbating",
    "orgasm",
    "climax",
    "blowjob",
    "blow job",
    "handjob",
    "hand job",
    "footjob",
    "foot job",
    "rimjob",
    "rim job",
    "deepthroat",
    "deep throat",
    "fingering",
    "foreplay",
    "intercourse",
    "penetration",
    "ejaculation",
    "ejaculate",
    "cum",
    "cumming",
    "cumshot",
    "semen",
    "sperm",
    "dildo",
    "vibrator",
    "anal sex",
    "oral sex",
    "threesome",
    "orgy",
    "gangbang",
    "facial",
    "penis",
    "vagina",
    "vulva",
    "clitoris",
    "testicles",
    "ballsack",
    "scrotum",
    "breasts",
    "boobs",
    "tits",
    "nipples",
    "buttocks",
    "ass",
    "booty",
];

/// Sexual harassment: propositions and demands aimed at someone.
pub const SEXUAL_HARASSMENT_WORDS: &[&str] = &[
    "send nudes",
    "show me your body",
    "show me your tits",
    "show me your ass",
    "wanna fuck",
    "let's have sex",
    "come over and fuck",
    "send me pictures",
    "get naked",
    "take your clothes off",
];

/// Threats of harm to a person.
pub const THREATS_WORDS: &[&str] = &[
    "i will kill you",
    "i'll kill you",
    "kill yourself",
    "i will hurt you",
    "i'll hurt you",
    "i will find you",
    "i know where you live",
    "hope you die",
    "you should die",
    "go die",
    "shoot you",
    "stab you",
    "beat you up",
    "i will end you",
];

/// Spam: scams and giveaways.
pub const SPAM_WORDS: &[&str] = &[
    "free nitro",
    "free robux",
    "claim your prize",
    "claim your reward",
    "you have won",
    "limited time offer",
    "click this link",
    "crypto giveaway",
    "dm me for profit",
    "guaranteed profit",
];

/// Words that often appear innocently. These are flagged only when addressed to someone (`you ass`).
pub const AMBIGUOUS_WORDS: &[&str] = &[
    "ass",
    "cum",
    "hell",
    "nude",
    "xxx",
    "damn",
    "git",
    "tool",
    "fool",
    "nobody",
    "booty",
    "facial",
    "climax",
    "naked",
    "penetration",
    "intercourse",
    "foreplay",
    "bugger",
    "bollocks",
];

/// Words that address someone, for the context rule: `you ass` and `your hell` are addressed; `hell of a game`
/// is not.
const ADDRESSING_WORDS: &[&str] = &["you", "your", "u", "ur", "yo", "ya", "ye", "youre"];

/// How a word is folded before it is compared: lower-cased, leetspeak characters put back (`sh1t` is `shit`,
/// `@` is `a`), anything that is not a letter dropped (`f.u.c.k` is `fuck`), and each run of the same letter
/// shortened to one (`shiiit` is `shit`). Words in the lists and the text go through the same folding.
pub fn fold_word(word: &str) -> String {
    let mut out = String::new();
    for c in word.to_lowercase().chars() {
        let c = match c {
            '0' => 'o',
            '1' => 'i',
            '3' => 'e',
            '4' | '@' => 'a',
            '5' | '$' => 's',
            '7' | '+' => 't',
            other => other,
        };
        if c.is_alphabetic() && out.chars().last() != Some(c) {
            out.push(c);
        }
    }
    out
}

/// A phrase folded word by word, so the spaces between words are kept (`piss off` stays `piss off`).
pub fn fold_phrase(phrase: &str) -> String {
    phrase
        .split_whitespace()
        .map(fold_word)
        .filter(|w| !w.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
}

/// The words of a message, folded, with a run of single letters joined back into one word, so `s h i t` is
/// one word.
fn text_words(text: &str) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    let mut in_letter_run = false;
    for raw in text.split_whitespace() {
        let folded = fold_word(raw);
        if folded.is_empty() {
            continue;
        }
        let single = folded.chars().count() == 1;
        match words.last_mut() {
            Some(last) if single && in_letter_run => *last = fold_word(&format!("{last}{folded}")),
            _ => words.push(folded),
        }
        in_letter_run = single;
    }
    words
}

/// Whether a context word in `words` is addressed to someone: it follows a word such as `you` or `your`.
fn addressed(words: &[String], base: &str) -> bool {
    words.iter().enumerate().any(|(i, w)| {
        i > 0
            && ADDRESSING_WORDS.contains(&words[i - 1].as_str())
            && (w == base || *w == format!("{base}s") || *w == format!("{base}es"))
    })
}

impl FlaggedWords {
    /// Whether a category is switched on.
    pub fn is_on(&self, category: ModerationCategory) -> bool {
        match category {
            ModerationCategory::SevereProfanity => self.severe_profanity,
            ModerationCategory::MildProfanity => self.mild_profanity,
            ModerationCategory::GeneralInsults => self.general_insults,
            ModerationCategory::IdentityBasedSlurs => self.identity_slurs,
            ModerationCategory::SexualContent => self.sexual_content,
            ModerationCategory::SexualHarassment => self.sexual_harassment,
            ModerationCategory::Threats => self.threats,
            ModerationCategory::Spam => self.spam,
        }
    }

    /// Switches a category on or off.
    pub fn set(&mut self, category: ModerationCategory, on: bool) {
        match category {
            ModerationCategory::SevereProfanity => self.severe_profanity = on,
            ModerationCategory::MildProfanity => self.mild_profanity = on,
            ModerationCategory::GeneralInsults => self.general_insults = on,
            ModerationCategory::IdentityBasedSlurs => self.identity_slurs = on,
            ModerationCategory::SexualContent => self.sexual_content = on,
            ModerationCategory::SexualHarassment => self.sexual_harassment = on,
            ModerationCategory::Threats => self.threats = on,
            ModerationCategory::Spam => self.spam = on,
        }
    }

    /// The flag `text` raises, or None when it raises none, or the rule is off. A word that is on its own in a
    /// list is always flagged. A context word (see `AMBIGUOUS_WORDS`) is flagged only when it is addressed to
    /// someone. When several match, the most severe is returned.
    pub fn flags(&self, text: &str) -> Option<Flag> {
        if !self.enabled {
            return None;
        }
        let words = text_words(text);
        let joined = words.join(" ");
        let ambiguous: Vec<String> = AMBIGUOUS_WORDS.iter().map(|w| fold_phrase(w)).collect();
        let mut strong: Vec<Flag> = Vec::new();
        let mut context: Vec<Flag> = Vec::new();
        for category in ModerationCategory::ALL {
            if !self.is_on(category) {
                continue;
            }
            for word in category.words() {
                let base = fold_phrase(word);
                if base.is_empty() || self.allow.iter().any(|a| fold_phrase(a) == base) {
                    continue;
                }
                let found = [base.clone(), format!("{base}s"), format!("{base}es")]
                    .iter()
                    .any(|form| matches(&joined, form));
                if !found {
                    continue;
                }
                let flag = Flag {
                    word: (*word).to_string(),
                    category,
                    severity: category.severity(),
                };
                if ambiguous.contains(&base) {
                    if addressed(&words, &base) {
                        context.push(flag);
                    }
                } else {
                    strong.push(flag);
                }
            }
        }
        strong
            .into_iter()
            .chain(context)
            .max_by_key(|f| f.severity)
    }
}

/// Refuses messages that match one of the patterns, or that repeat a character too many times in a row.
/// Patterns are regular expressions. Add `(?i)` to a pattern to ignore case; without it, case matters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FilteredWords {
    /// Whether the rule is on at all.
    #[serde(default)]
    pub enabled: bool,
    /// The regular expressions a message may not match.
    #[serde(default = "default_patterns")]
    pub patterns: Vec<String>,
    /// Refuse a message with `repeated_limit` or more of the same character in a row, ignoring case.
    #[serde(default)]
    pub repeated_chars: bool,
    /// How many of the same character in a row count as repeated, from `MIN_REPEATED` to `MAX_REPEATED`.
    #[serde(default = "default_repeated_limit")]
    pub repeated_limit: u32,
    /// Refuse a message that matches. Off, the message goes through and only the alert applies.
    #[serde(default = "default_true")]
    pub block: bool,
    /// Post a report to AutoMod's channel when the rule catches a message.
    #[serde(default = "default_true")]
    pub send_alert: bool,
    /// The notice a member sees when their message is blocked. Empty means the standard reason.
    #[serde(default)]
    pub notice: String,
    /// Roles and channels the rule leaves alone. Members with Manage Server are always left alone.
    #[serde(default)]
    pub allowed_roles: Vec<i64>,
    #[serde(default)]
    pub allowed_channels: Vec<i64>,
}

/// Common patterns a server can add to its filter with one press. Each is a regular expression.
pub const PRESET_FILTERS: &[(&str, &str)] = &[
    ("URLs", r"(?i)https?://[^\s]+"),
    // An @ that starts a word, as the app writes mentions (`@name`). Email addresses are not mentions.
    ("Mentions", r"\B@\S+"),
    ("Invite links", r"(?i)(discord\.gg/[^\s]+|discord\.com/invite/[^\s]+)"),
    ("Caps spam", r"[A-Z]{5,}"),
    // The message formatting patterns of HoneyPot's AutoMod.
    ("Capitals", r"(?-i)(?:[A-Z]\s?){10,}"),
    ("Spoilers", r"(?s)\|\|.+?\|\|"),
    ("Emojis", r"((<a?:[a-z_0-9]+:[0-9]+>|\p{Extended_Pictographic})\s?){5,}"),
    ("Headers", r"(?m)^#{1,3}\s+\S"),
    ("Unicode", r"\p{M}{3,}"),
    ("Code blocks", r"(?s)`[^`]+`"),
    ("Bullet lists", r"(?m)^\s*(?:[-*+]|\d+\.)\s+\S"),
    ("Embedded links", r"(?i)\[[^\]]*\]\(\s*<?https?://[^)]+\)"),
    // An email address, such as name@example.com.
    ("Emails", r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),
];

/// The presets a new filter starts with. The others are added by hand, so a server does not get
/// formatting rules, such as bullet lists, that it did not choose.
const DEFAULT_FILTER_NAMES: &[&str] = &["URLs", "Mentions", "Invite links", "Caps spam"];

/// How many of the same character in a row count as repeated: the default, and the least and most a rule may use.
pub const REPEATED_CHARS: usize = 5;
pub const MIN_REPEATED: u32 = 2;
pub const MAX_REPEATED: u32 = 50;

fn default_repeated_limit() -> u32 {
    REPEATED_CHARS as u32
}
/// The most patterns a filter may have, and the longest one.
pub const MAX_FILTER_PATTERNS: usize = 50;
pub const MAX_FILTER_PATTERN_LEN: usize = 200;

fn default_patterns() -> Vec<String> {
    PRESET_FILTERS
        .iter()
        .filter(|(name, _)| DEFAULT_FILTER_NAMES.contains(name))
        .map(|(_, pattern)| (*pattern).to_string())
        .collect()
}

impl Default for FilteredWords {
    fn default() -> Self {
        Self {
            enabled: false,
            patterns: default_patterns(),
            repeated_chars: false,
            repeated_limit: default_repeated_limit(),
            block: true,
            send_alert: true,
            notice: String::new(),
            allowed_roles: Vec::new(),
            allowed_channels: Vec::new(),
        }
    }
}

impl FilteredWords {
    /// The text a message matched, or None when it matches nothing or the rule is off. A pattern that does not
    /// compile matches nothing.
    pub fn find(&self, text: &str) -> Option<String> {
        if !self.enabled {
            return None;
        }
        for pattern in &self.patterns {
            if let Ok(re) = regex::Regex::new(pattern) {
                if let Some(found) = re.find(text) {
                    return Some(found.as_str().to_string());
                }
            }
        }
        if self.repeated_chars {
            return repeated_run(text, self.repeated_limit as usize);
        }
        None
    }
}

/// The first run of `at_least` or more of one character in a row in `text`, ignoring case, or None.
pub fn repeated_run(text: &str, at_least: usize) -> Option<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut start = 0;
    while start < chars.len() {
        let first = chars[start].to_lowercase().next();
        let mut end = start + 1;
        while end < chars.len() && chars[end].to_lowercase().next() == first {
            end += 1;
        }
        if end - start >= at_least {
            return Some(chars[start..end].iter().collect());
        }
        start = end;
    }
    None
}

/// Whether `pattern` is a regular expression a filter can use.
pub fn valid_pattern(pattern: &str) -> bool {
    !pattern.trim().is_empty() && regex::Regex::new(pattern.trim()).is_ok()
}

/// Patterns as given, tidied: trimmed, without blanks or repeats, within the limits, and only those that compile.
fn tidy_patterns(list: Vec<String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for p in list {
        let p: String = p.trim().chars().take(MAX_FILTER_PATTERN_LEN).collect();
        if !p.is_empty() && !out.contains(&p) && regex::Regex::new(&p).is_ok() {
            out.push(p);
        }
    }
    out.truncate(MAX_FILTER_PATTERNS);
    out
}

/// Limits the people and roles a message may mention, and what happens to members who break it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MentionRule {
    /// Refuse messages that mention more than `max_unique` different members or roles.
    #[serde(default)]
    pub enabled: bool,
    /// The most different members and roles one message may mention.
    #[serde(default = "default_max_mentions")]
    pub max_unique: u32,
    /// Refuse a member who mentions `RAID_MENTIONS` or more people in `RAID_WINDOW_SECS`, across their messages.
    #[serde(default)]
    pub raid_detection: bool,
    /// How long a member who breaks this rule may not send messages, in seconds. Zero means no timeout.
    #[serde(default)]
    pub timeout_secs: u64,
    /// Refuse a message that breaks the rule. Off, the message goes through and only the alert and timeout apply.
    #[serde(default = "default_true")]
    pub block: bool,
    /// Post a report to AutoMod's channel when the rule catches a message.
    #[serde(default = "default_true")]
    pub send_alert: bool,
    /// Roles whose holders the rule leaves alone.
    #[serde(default)]
    pub allowed_roles: Vec<i64>,
    /// The notice a member sees when their message is blocked. Empty means the standard reason.
    #[serde(default)]
    pub notice: String,
}

/// The longest custom notice a blocked member may be shown.
pub const MAX_NOTICE_LEN: usize = 200;

fn default_true() -> bool {
    true
}

fn default_max_mentions() -> u32 {
    5
}

impl Default for MentionRule {
    fn default() -> Self {
        Self {
            enabled: false,
            max_unique: default_max_mentions(),
            raid_detection: false,
            timeout_secs: 0,
            block: true,
            send_alert: true,
            allowed_roles: Vec::new(),
            notice: String::new(),
        }
    }
}

/// The longest name in chat, the same as the auth service allows.
pub const MAX_DISPLAY_NAME_LEN: usize = 24;

/// The most mentions one message may be limited to, and the longest timeout AutoMod may give.
pub const MAX_MENTIONS_LIMIT: u32 = 50;
pub const MAX_TIMEOUT_SECS: u64 = 7 * 24 * 60 * 60;
/// Mentions across a member's messages that make a raid, and the window they must fall in.
pub const RAID_MENTIONS: usize = 20;
pub const RAID_WINDOW_SECS: u64 = 30;

/// The longest slow mode a channel can have, in seconds. Zero turns it off.
pub const MAX_SLOW_MODE_SECS: u64 = 6 * 60 * 60;

/// The longest a moderator can time a member out for, in seconds (28 days).
pub const MAX_MEMBER_TIMEOUT_SECS: u64 = 28 * 24 * 60 * 60;

/// Whether `text` mentions everyone (`@everyone`) or the members who are online (`@here`), as a word of its own.
/// `@here` reaches the same people for now: everyone who is connected to the channel, which is online.
pub fn everyone_mentioned(text: &str) -> bool {
    fn word_char(c: char) -> bool {
        c.is_alphanumeric() || c == '_'
    }
    ["@everyone", "@here"].iter().any(|token| {
        text.match_indices(token).any(|(at, _)| {
            let before = text[..at].chars().next_back();
            let after = text[at + token.len()..].chars().next();
            !before.is_some_and(word_char) && !after.is_some_and(word_char)
        })
    })
}

/// Whether `text` pings a role or member called `name`: `@name`, not run on into more of a name.
pub fn mentions_name(text: &str, name: &str) -> bool {
    let needle = format!("@{name}");
    let mut from = 0;
    while let Some(at) = text[from..].find(&needle) {
        let end = from + at + needle.len();
        let next = text[end..].chars().next();
        if !next.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '-') {
            return true;
        }
        from = end;
    }
    false
}

/// Whether a message pings someone who holds these roles: `@everyone` or `@here`, or the name of one of their
/// roles (`held_roles` are the names of the mentionable roles they hold).
pub fn pings_viewer(text: &str, held_roles: &[String]) -> bool {
    everyone_mentioned(text) || held_roles.iter().any(|name| mentions_name(text, name))
}

#[cfg(test)]
mod everyone_tests {
    use super::everyone_mentioned;

    #[test]
    fn everyone_and_here_count_only_as_words_of_their_own() {
        assert!(everyone_mentioned("hey @everyone look"));
        assert!(everyone_mentioned("@here"));
        assert!(everyone_mentioned("(@everyone)"));
        assert!(!everyone_mentioned("@everyones"), "a longer word is not the mention");
        assert!(!everyone_mentioned("x@everyone"), "a word that ends before the @ is not the mention");
        assert!(!everyone_mentioned("everyone here"), "no @ is not a mention");
    }

    #[test]
    fn a_viewer_is_pinged_by_everyone_or_by_a_role_they_hold() {
        use super::{mentions_name, pings_viewer};
        assert!(mentions_name("hey @Mods look", "Mods"));
        assert!(!mentions_name("hey @Mods-extra", "Mods"), "a longer name is not the mention");
        let held = vec!["Mods".to_string()];
        assert!(pings_viewer("@Mods", &held));
        assert!(pings_viewer("@here", &[]), "@here pings everyone");
        assert!(!pings_viewer("@Admins", &held), "a role they do not hold does not ping them");
    }
}

/// The members and roles `text` mentions, counted once each. A mention is `@` followed by a name
/// that ends the word, as the client shows them.
pub fn mentioned_count(text: &str, members: &[String], roles: &[String]) -> usize {
    let mut found: Vec<&str> = Vec::new();
    for name in members.iter().chain(roles.iter()) {
        if name.is_empty() {
            continue;
        }
        let needle = format!("@{name}");
        let mut from = 0;
        while let Some(at) = text[from..].find(&needle) {
            let end = from + at + needle.len();
            let next = text[end..].chars().next();
            let whole = !next.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '-');
            if whole && !found.contains(&name.as_str()) {
                found.push(name.as_str());
            }
            from = end;
        }
    }
    found.len()
}

/// Flags members whose names contain a listed word, and says what to do about them. Members with
/// Administrator or Manage Server, and members holding one of `allowed_roles`, are never flagged.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameRule {
    #[serde(default)]
    pub enabled: bool,
    /// Words and phrases a name may not contain (see `matches`).
    #[serde(default)]
    pub words: Vec<String>,
    /// A flagged member may not send, edit, react or pin until they change their name.
    #[serde(default)]
    pub block_interactions: bool,
    /// Post an alert to AutoMod's channel the first time a flagged member sends a message.
    #[serde(default)]
    pub send_alert: bool,
    /// Where alerts went before AutoMod had one channel for all its reports. Read from older rules and
    /// moved to `AutoMod::alert_channel` by `tidied`.
    #[serde(default, rename = "alert_channel", skip_serializing)]
    pub old_alert_channel: Option<i64>,
    /// Roles whose holders the rule leaves alone.
    #[serde(default)]
    pub allowed_roles: Vec<i64>,
    /// The notice a member sees when their name blocks them. Empty means the standard notice.
    #[serde(default)]
    pub notice: String,
}

impl NameRule {
    /// The listed word a name matches, or None when it is fine (or the rule is off).
    pub fn flags(&self, name: &str) -> Option<&str> {
        if !self.enabled {
            return None;
        }
        let lower = name.to_lowercase();
        self.words.iter().find(|w| matches(&lower, w)).map(String::as_str)
    }
}

/// The author id of messages the server's AutoMod posts, such as its alerts. No account can have it,
/// so clients show these messages as coming from the server itself.
pub const AUTOMOD_ID: &str = "system:automod";

/// Whether a message was posted by the server's AutoMod.
pub fn is_automod(author_id: &str) -> bool {
    author_id == AUTOMOD_ID
}

/// The author id prefix of the notices the server posts about members, such as "X joined the server".
/// The member's id follows it, so the notice can show their picture.
pub const NOTICE_PREFIX: &str = "system:notice:";

/// The author id of a notice about the member with this account id.
pub fn notice_author(member_id: &str) -> String {
    format!("{NOTICE_PREFIX}{member_id}")
}

/// Whether a message is a notice the server posted about a member.
pub fn is_notice(author_id: &str) -> bool {
    author_id.starts_with(NOTICE_PREFIX)
}

/// The account id of the member a notice is about.
pub fn notice_subject(author_id: &str) -> Option<&str> {
    author_id.strip_prefix(NOTICE_PREFIX)
}

/// Whether an id belongs to the server itself (AutoMod, the notices, and any other server author),
/// rather than to an account. Those ids all start with `system:`.
pub fn is_system_id(id: &str) -> bool {
    id.starts_with("system:")
}

/// How many messages a member may send within `SPAM_WINDOW_SECS` while the spam filter is on.
pub const SPAM_LIMIT: usize = 5;
pub const SPAM_WINDOW_SECS: u64 = 5;
/// The most words a word list can have, and the longest one.
pub const MAX_BLOCKED_WORDS: usize = 1000;
pub const MAX_BLOCKED_WORD_LEN: usize = 60;

impl AutoMod {
    /// Why `text` breaks the message rules, or None when it does not. The spam filter is checked
    /// separately, as it depends on what was sent before.
    pub fn check(&self, text: &str) -> Option<Breach> {
        let lower = text.to_lowercase();
        if self.block_links && has_link(&lower) {
            return Some(Breach {
                reason: "AutoMod: links are not allowed in this channel".into(),
                rule: "Block Links",
                keyword: String::new(),
            });
        }
        None
    }

    /// The rules as given, tidied: word lists trimmed, lower-cased, without blanks or repeats, and
    /// within the limits.
    /// Whether any rule is switched on.
    pub fn any_rule_on(&self) -> bool {
        self.block_links
            || self.spam_filter
            || self.names.enabled
            || self.mentions.enabled
            || self.flagged.enabled
            || self.filtered.enabled
            || self.words.enabled
    }

    pub fn tidied(mut self) -> Self {
        self.words.words = tidy_words(self.words.words);
        self.words.notice = self.words.notice.trim().chars().take(MAX_NOTICE_LEN).collect();
        self.words.allowed_roles.sort_unstable();
        self.words.allowed_roles.dedup();
        self.words.allowed_channels.sort_unstable();
        self.words.allowed_channels.dedup();
        self.names.words = tidy_words(self.names.words);
        self.names.notice = self.names.notice.trim().chars().take(MAX_NOTICE_LEN).collect();
        self.names.allowed_roles.sort_unstable();
        self.names.allowed_roles.dedup();
        self.mentions.max_unique = self.mentions.max_unique.clamp(1, MAX_MENTIONS_LIMIT);
        self.mentions.timeout_secs = self.mentions.timeout_secs.min(MAX_TIMEOUT_SECS);
        self.mentions.notice = self.mentions.notice.trim().chars().take(MAX_NOTICE_LEN).collect();
        self.mentions.allowed_roles.sort_unstable();
        self.mentions.allowed_roles.dedup();
        self.flagged.allow = tidy_words(self.flagged.allow);
        self.flagged.notice = self.flagged.notice.trim().chars().take(MAX_NOTICE_LEN).collect();
        self.flagged.allowed_roles.sort_unstable();
        self.flagged.allowed_roles.dedup();
        self.flagged.allowed_channels.sort_unstable();
        self.flagged.allowed_channels.dedup();
        self.filtered.patterns = tidy_patterns(self.filtered.patterns);
        self.filtered.repeated_limit = self.filtered.repeated_limit.clamp(MIN_REPEATED, MAX_REPEATED);
        self.filtered.notice = self.filtered.notice.trim().chars().take(MAX_NOTICE_LEN).collect();
        self.filtered.allowed_roles.sort_unstable();
        self.filtered.allowed_roles.dedup();
        self.filtered.allowed_channels.sort_unstable();
        self.filtered.allowed_channels.dedup();
        if let Some(channel) = self.names.old_alert_channel.take() {
            if self.alert_channel.is_none() {
                self.alert_channel = Some(channel);
                self.names.send_alert = true;
            }
        }
        self
    }
}

/// Splits a word list as typed, on commas and new lines.
pub fn split_words(typed: &str) -> Vec<String> {
    typed.split([',', '\n']).map(str::to_string).collect()
}

fn tidy_words(list: Vec<String>) -> Vec<String> {
    let mut words: Vec<String> = Vec::new();
    for w in list {
        let w: String = w.trim().to_lowercase().chars().take(MAX_BLOCKED_WORD_LEN).collect();
        if !w.is_empty() && w != "*" && !words.contains(&w) {
            words.push(w);
        }
    }
    words.truncate(MAX_BLOCKED_WORDS);
    words
}

/// Whether lower-cased `text` matches a listed word, as Discord does: `cat` only as a whole word,
/// `cat*` at the start of a word, `*cat` at the end of one, and `*cat*` anywhere.
pub fn matches(text: &str, pattern: &str) -> bool {
    let pattern = pattern.to_lowercase();
    let open_start = pattern.starts_with('*');
    let open_end = pattern.ends_with('*') && pattern.len() > 1;
    let needle = pattern.trim_matches('*');
    if needle.is_empty() {
        return false;
    }
    let is_word = |c: char| c.is_alphanumeric() || c == '_';
    let mut from = 0;
    while let Some(at) = text[from..].find(needle) {
        let start = from + at;
        let end = start + needle.len();
        let before_ok = open_start || !text[..start].chars().next_back().is_some_and(is_word);
        let after_ok = open_end || !text[end..].chars().next().is_some_and(is_word);
        if before_ok && after_ok {
            return true;
        }
        from = start + needle.chars().next().map_or(1, char::len_utf8);
    }
    false
}

/// Whether text has a web link in it: an address starting http://, https:// or www.
fn has_link(lower: &str) -> bool {
    lower.contains("http://") || lower.contains("https://") || lower.split_whitespace().any(|w| w.starts_with("www."))
}

/// The most messages a channel can have pinned at once.
pub const MAX_PINS: usize = 50;

/// The message a reply answers, as shown above the reply: who wrote it and how it starts. When the
/// original has been deleted, `author_id` and `text` are empty.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplyRef {
    pub id: i64,
    pub author: String,
    pub author_id: String,
    pub text: String,
}

/// How much of the original message a reply shows, in characters.
pub const REPLY_PREVIEW_LEN: usize = 120;

/// How a reply shows the start of the message it answers: on one line, cut to a set length.
pub fn reply_preview(text: &str) -> String {
    let one_line = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out: String = one_line.chars().take(REPLY_PREVIEW_LEN).collect();
    if one_line.chars().count() > REPLY_PREVIEW_LEN {
        out.push('…');
    }
    out
}

/// How a member wants to appear to others. Invisible members show as offline.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PresenceStatus {
    #[default]
    Online,
    Idle,
    DoNotDisturb,
    Invisible,
}

impl PresenceStatus {
    /// The name stored for a status in a server's database.
    pub fn key(self) -> &'static str {
        match self {
            PresenceStatus::Online => "online",
            PresenceStatus::Idle => "idle",
            PresenceStatus::DoNotDisturb => "do_not_disturb",
            PresenceStatus::Invisible => "invisible",
        }
    }

    /// The status with this stored name. Unknown names are online.
    pub fn from_key(key: &str) -> Self {
        match key {
            "idle" => PresenceStatus::Idle,
            "do_not_disturb" => PresenceStatus::DoNotDisturb,
            "invisible" => PresenceStatus::Invisible,
            _ => PresenceStatus::Online,
        }
    }
}

/// A member of a server and whether they are connected right now.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserStatus {
    /// The hidden account id.
    #[serde(default)]
    pub id: String,
    pub name: String,
    pub online: bool,
    /// True for the one member who owns this server (the first user to join it).
    pub owner: bool,
    /// The ids of the roles this member has, in no particular order.
    #[serde(default)]
    pub roles: Vec<i64>,
    /// When this member first joined this server, in Unix seconds (0 when unknown).
    #[serde(default)]
    pub joined: u64,
    /// How the member wants to appear. Invisible members are sent as offline.
    #[serde(default)]
    pub status: PresenceStatus,
    /// The ids of the badges this member has on this server.
    #[serde(default)]
    pub badges: Vec<i64>,
}

/// Permissions a role can grant, as bits in `RoleInfo::permissions`. The owner has all of them.
pub mod perm {
    /// Create, rename, move and delete channels and categories.
    pub const MANAGE_CHANNELS: u32 = 1 << 0;
    /// Create, edit, reorder and delete roles below one's own, and give them to members below one.
    pub const MANAGE_ROLES: u32 = 1 << 1;
    /// Delete other members' messages.
    pub const MANAGE_MESSAGES: u32 = 1 << 2;
    /// Members with this cannot be ignored or blocked by anyone. The owner always counts as having it.
    pub const BYPASS_IGNORE: u32 = 1 << 3;
    /// See the channels. A channel can allow or deny it for a role (see `ChannelOverride`).
    pub const VIEW_CHANNEL: u32 = 1 << 4;
    /// Send messages in the channels. A channel can allow or deny it for a role (see `ChannelOverride`).
    pub const SEND_MESSAGES: u32 = 1 << 5;
    /// Has every permission, including ones switched off elsewhere. Holders can still only manage
    /// roles below their own.
    pub const ADMINISTRATOR: u32 = 1 << 6;
    /// Change the server's name, description and picture. The owner always can.
    pub const MANAGE_SERVER: u32 = 1 << 7;
    /// Pin and unpin messages. Manage messages also allows it.
    pub const PIN_MESSAGES: u32 = 1 << 8;
    /// Remove members from the server. They may join again. Only members whose highest role is below one's own.
    pub const KICK_MEMBERS: u32 = 1 << 9;
    /// Ban members from the server, so they cannot join again until unbanned. Only members whose highest role
    /// is below one's own.
    pub const BAN_MEMBERS: u32 = 1 << 10;
    /// Send messages in a channel with slow mode without waiting between them. Manage messages there also allows it.
    pub const BYPASS_SLOW_MODE: u32 = 1 << 11;
    /// Stop members from sending messages for a set time. Only members whose highest role is below one's own.
    pub const TIMEOUT_MEMBERS: u32 = 1 << 12;
    /// Use `@everyone` and `@here` in a message, which notify everyone who can see the channel.
    pub const MENTION_EVERYONE: u32 = 1 << 13;
    /// Mention as many members and roles as one likes, past AutoMod's mention limit.
    pub const BYPASS_MENTION_LIMIT: u32 = 1 << 14;
    /// Add and remove the server's custom emoji.
    pub const MANAGE_EMOJI: u32 = 1 << 15;
    /// Every permission there is.
    pub const ALL: u32 = MANAGE_CHANNELS
        | MANAGE_ROLES
        | MANAGE_MESSAGES
        | BYPASS_IGNORE
        | VIEW_CHANNEL
        | SEND_MESSAGES
        | ADMINISTRATOR
        | MANAGE_SERVER
        | PIN_MESSAGES
        | KICK_MEMBERS
        | BAN_MEMBERS
        | BYPASS_SLOW_MODE
        | TIMEOUT_MEMBERS
        | MENTION_EVERYONE
        | BYPASS_MENTION_LIMIT
        | MANAGE_EMOJI;
}

/// Who a setting is for is decided by the caller. This picks the outcome for one permission: a member's
/// own setting first, then their roles' settings, where a denial wins over an allowance. `None` means
/// the server-wide permission decides.
pub fn grant(member: Option<Setting>, roles: &[Setting], bit: u32) -> Option<bool> {
    if let Some(value) = member.and_then(|s| s.get(bit)) {
        return Some(value);
    }
    let mut allowed = false;
    for setting in roles {
        match setting.get(bit) {
            Some(false) => return Some(false),
            Some(true) => allowed = true,
            None => {}
        }
    }
    allowed.then_some(true)
}

impl ChannelOverride {
    pub fn setting(&self) -> Setting {
        Setting {
            view: self.view,
            send: self.send,
            manage_channels: self.manage_channels,
            manage_messages: self.manage_messages,
        }
    }
}

impl CategoryOverride {
    pub fn setting(&self) -> Setting {
        Setting {
            view: self.view,
            send: self.send,
            manage_channels: self.manage_channels,
            manage_messages: self.manage_messages,
        }
    }
}

impl MemberChannelOverride {
    pub fn setting(&self) -> Setting {
        Setting {
            view: self.view,
            send: self.send,
            manage_channels: self.manage_channels,
            manage_messages: self.manage_messages,
        }
    }
}

impl MemberCategoryOverride {
    pub fn setting(&self) -> Setting {
        Setting {
            view: self.view,
            send: self.send,
            manage_channels: self.manage_channels,
            manage_messages: self.manage_messages,
        }
    }
}

/// The four settings a channel or category can give a role or member. `None` leaves the server-wide
/// setting in place; `Some(true)` allows and `Some(false)` denies.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Setting {
    pub view: Option<bool>,
    pub send: Option<bool>,
    pub manage_channels: Option<bool>,
    pub manage_messages: Option<bool>,
}

impl Setting {
    /// The setting for one permission bit, if this sets it.
    pub fn get(&self, bit: u32) -> Option<bool> {
        match bit {
            perm::VIEW_CHANNEL => self.view,
            perm::SEND_MESSAGES => self.send,
            perm::MANAGE_CHANNELS => self.manage_channels,
            perm::MANAGE_MESSAGES => self.manage_messages,
            _ => None,
        }
    }

    /// True when nothing is set, so the entry can be removed.
    pub fn is_empty(&self) -> bool {
        *self == Setting::default()
    }
}

/// One role's exception for one channel. `None` leaves the role's server-wide permission in place;
/// `Some(true)` allows the channel for the role and `Some(false)` denies it, whatever the role's
/// server-wide permission says. A denial from any of a member's roles wins.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelOverride {
    pub channel_id: i64,
    pub role: i64,
    #[serde(default)]
    pub view: Option<bool>,
    #[serde(default)]
    pub send: Option<bool>,
    #[serde(default)]
    pub manage_channels: Option<bool>,
    #[serde(default)]
    pub manage_messages: Option<bool>,
}

/// One role's permission for a category. Setting it sets the same permission on every channel in the
/// category, and a channel moved into the category takes it on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CategoryOverride {
    pub category_id: i64,
    pub role: i64,
    #[serde(default)]
    pub view: Option<bool>,
    #[serde(default)]
    pub send: Option<bool>,
    #[serde(default)]
    pub manage_channels: Option<bool>,
    #[serde(default)]
    pub manage_messages: Option<bool>,
}

/// Who a permission is for: a role, or one member by account id.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Subject {
    Role(i64),
    Member(String),
}

/// One member's permission for a channel. It beats the member's roles for that channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberChannelOverride {
    pub channel_id: i64,
    /// The member's account id.
    pub member: String,
    #[serde(default)]
    pub view: Option<bool>,
    #[serde(default)]
    pub send: Option<bool>,
    #[serde(default)]
    pub manage_channels: Option<bool>,
    #[serde(default)]
    pub manage_messages: Option<bool>,
}

/// One member's permission for a category. Like a role's, it is copied to every channel in the category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemberCategoryOverride {
    pub category_id: i64,
    /// The member's account id.
    pub member: String,
    #[serde(default)]
    pub view: Option<bool>,
    #[serde(default)]
    pub send: Option<bool>,
    #[serde(default)]
    pub manage_channels: Option<bool>,
    #[serde(default)]
    pub manage_messages: Option<bool>,
}

/// The longest status text, in characters.
pub const MAX_STATUS_TEXT_LEN: usize = 60;

/// Longest role name, in characters.
pub const MAX_ROLE_NAME_LEN: usize = 32;

/// The id of the `@everyone` role. Every member has it, it always sits at the bottom of the
/// hierarchy, and it cannot be deleted, moved or given out. Its colour and permissions apply to all.
pub const EVERYONE_ROLE: i64 = 0;

/// The id of the AutoMod role. It is made the first time an AutoMod rule is switched on. Its colour is the
/// colour of AutoMod's messages. It cannot be deleted or given to members, as it belongs to the bot.
pub const AUTOMOD_ROLE: i64 = -1;

/// The id of the System role, held by the server's own notices. Like the AutoMod role, it is made when the
/// server starts, is an administrator, and cannot be deleted, moved or given to members.
pub const SYSTEM_ROLE: i64 = -2;

/// A badge an admin gives a member on this server. It shows on the member's profile card.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Badge {
    pub id: i64,
    pub name: String,
    /// A hex colour like "#5865f2", or empty for the default.
    pub color: String,
}

/// A custom emoji of this server. Only members of the server can use it, in its messages and reactions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CustomEmoji {
    pub id: i64,
    /// Its name, without colons: `party` is used as `:party:`.
    pub name: String,
    /// The image as base64: a PNG, or an animated PNG.
    pub image: String,
}

/// A role members can be given. Members get the permissions of all their roles together.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleInfo {
    pub id: i64,
    pub name: String,
    /// `#rrggbb`, or empty for no colour.
    pub color: String,
    /// The permissions this role grants (see `perm`).
    pub permissions: u32,
    /// Higher means more power. Roles are listed highest first.
    pub position: i64,
    /// Anyone may write `@name` to ping the role's members.
    #[serde(default)]
    pub mentionable: bool,
    /// The role's members are listed in their own group in the member list, not under ONLINE.
    #[serde(default)]
    pub hoisted: bool,
}

/// Basic syntax check for an email address (not a full RFC 5322 parser).
pub fn is_valid_email(email: &str) -> bool {
    let email = email.trim();
    if email.len() > 254 || email.chars().any(char::is_whitespace) {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && !domain.contains('@')
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains("..")
}

/// Messages sent from client to server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMsg {
    /// First message on a connection: prove who you are with a session token from the auth service. An account
    /// that left the server is refused unless `join` asks to be a member again.
    Connect {
        token: String,
        #[serde(default)]
        join: bool,
    },
    /// Switch to a channel (created on demand). Receives its history.
    Join { channel: String },
    /// Send a message to the current channel, as a reply to the message `reply_to` when it is set. When `channel`
    /// is set, the message goes to that channel instead, and the current channel does not change.
    Say {
        text: String,
        #[serde(default)]
        reply_to: Option<i64>,
        #[serde(default)]
        channel: Option<i64>,
    },
    /// Change the text of one of your own messages.
    Edit { id: i64, text: String },
    /// Delete one of your own messages.
    Delete { id: i64 },
    /// Pin a message to its channel, or unpin it. Needs Pin messages or Manage messages, except in a
    /// direct message.
    Pin { id: i64, pinned: bool },
    /// Ask for a channel's pinned messages.
    ListPins { channel: i64 },
    /// Ask for the server's automatic moderation rules. Needs Manage Server.
    GetAutoMod,
    /// Make another member the owner of this server. Only the owner may. Needs a valid session.
    TransferOwnership { id: String },
    /// Delete this server and everything in it. Only the owner may. Every connection is closed and the server
    /// refuses new ones. Needs a valid session.
    DeleteServer,
    /// Leave this server: the account stops being a member, and its roles, badges and channel overrides
    /// here are removed. The owner cannot leave. Needs a valid session.
    LeaveServer,
    /// Ask for the server's system messages settings. Needs Manage Server.
    GetSystemMessages,
    /// Replace the server's system messages settings. Needs Manage Server.
    SetSystemMessages { settings: SystemMessages },
    /// Remove a member from the server. They can join again. Needs Kick Members. `reason` is optional.
    Kick { user: String, reason: Option<String> },
    /// Remove a member and stop them joining until unbanned. Needs Ban Members. `reason` is optional.
    Ban { user: String, reason: Option<String> },
    /// Let a banned account join again. Needs Ban Members.
    Unban { user: String },
    /// Stop a member from sending messages for `seconds`. `reason` is optional. Needs Timeout Members.
    Timeout { user: String, seconds: u64, reason: Option<String> },
    /// End a member's timeout early. Needs Timeout Members.
    RemoveTimeout { user: String },
    /// The viewer has read a channel up to its newest message, so what came before is no longer unread.
    MarkRead { channel_id: i64 },
    /// Ask for the server's bans. Needs Ban Members. Answered with `ServerMsg::Bans`.
    GetBans,
    /// Replace the server's automatic moderation rules. Needs Manage Server.
    SetAutoMod { rules: AutoMod },
    /// Add your reaction to a message, or take it off if it is already there.
    React { id: i64, emoji: String },
    /// Request the list of channels.
    ListChannels,
    /// Ask for the server-wide state again: roles, badges, custom emoji, and channel and category
    /// overrides. The server sends them all again, so a client that missed a change shows it.
    Resync,
    /// End this connection's session on this server, so its token stops working here even if
    /// the auth service cannot be reached. The server then closes the connection.
    Logout,
    /// Change the server's name and description. Only the owner may do this.
    UpdateServer { name: String, description: String },
    /// Set the server icon (a base64 PNG), or remove it with `None`. Only the owner may do this.
    SetServerIcon { png_base64: Option<String> },
    /// Public, no login: ask for this server's details. Answered with `ServerMsg::Info`.
    Info,
    /// Public, no login: exchange lists of servers. `known` are servers the sender knows, and
    /// the sender's own address. Answered with `ServerMsg::Peers`.
    Peers { known: Vec<String> },
    /// Create a category that channels can be grouped under. Any member may do this.
    CreateCategory { name: String },
    /// Delete a category. Its channels are kept: they become uncategorized.
    DeleteCategory { category: i64 },
    /// Rename a category. Its channels stay in it. Needs Manage channels.
    RenameCategory { category: i64, new_name: String },
    /// Switch to a channel by its id. Used when the channel is picked from a list.
    JoinChannel { id: i64 },
    /// Rename a channel. Its messages and its place in its category move with it.
    RenameChannel { channel: i64, new_name: String },
    /// Delete a channel and its messages. Only the server owner may do this.
    DeleteChannel { channel: i64 },
    /// Move a category so it comes before another one (or to the end, with `None`).
    MoveCategory { category: i64, before: Option<i64> },
    /// Put a channel in a category (or none) before another channel of that group. With `before`
    /// None it goes last in the group.
    PlaceChannel {
        channel: i64,
        category: Option<i64>,
        before: Option<i64>,
    },
    /// Put a channel in a category, or take it out of its category with `None`.
    MoveChannel { channel: i64, category: Option<i64> },
    /// Create a role at the bottom of the hierarchy. Needs Manage roles, and can only grant
    /// permissions the sender has.
    CreateRole {
        name: String,
        color: String,
        permissions: u32,
        #[serde(default)]
        mentionable: bool,
        #[serde(default)]
        hoisted: bool,
    },
    /// Change a role's name, colour and permissions. Needs Manage roles, and the role must be below
    /// the sender's highest role.
    UpdateRole {
        role: i64,
        name: String,
        color: String,
        permissions: u32,
        #[serde(default)]
        mentionable: bool,
        #[serde(default)]
        hoisted: bool,
    },
    /// Delete a role. Members who had it lose it. Same rules as `UpdateRole`.
    DeleteRole { role: i64 },
    /// Move a role so it sits just above another one (or at the bottom, with `None`). Same rules as
    /// `UpdateRole`.
    MoveRole { role: i64, before: Option<i64> },
    /// Give a member a role, or take it away with `on` false. Needs Manage roles, and both the role
    /// and the member's highest role must be below the sender's highest role.
    SetMemberRole { user: String, role: i64, on: bool },
    /// Add a custom emoji to this server. `image` is base64 for a PNG or animated PNG. Needs Manage emoji.
    AddEmoji { name: String, image: String },
    /// Remove a custom emoji. Needs Manage emoji.
    RemoveEmoji { emoji: i64 },
    /// Rename a custom emoji. Reactions that used its old name show the new one. Needs Manage emoji.
    RenameEmoji { emoji: i64, name: String },
    /// Create a badge on this server, shown on members' profile cards. Needs Manage roles.
    CreateBadge { name: String, color: String },
    /// Delete a badge. Members who had it lose it. Needs Manage roles.
    DeleteBadge { badge: i64 },
    /// Give a badge to a member, or take it away with `on` false. Needs Manage roles.
    SetMemberBadge { user: String, badge: i64, on: bool },
    /// Set how this member appears to others on this server.
    SetStatus { status: PresenceStatus },
    /// Set the status text shown on this member's card, sent live so everyone connected sees it.
    /// Empty clears it. The text is saved by the auth service.
    SetProfileStatus { text: String },
    /// Set the name shown in chat, after the auth service has changed it. Sent to every server this client is on.
    SetDisplayName { name: String },
    /// This member is typing in the open channel. Sent a few times while they type.
    Typing,
    /// Set how long each member must wait between messages in a channel. Zero turns slow mode off.
    /// Members who may manage messages there are not held to it. Needs Manage channels.
    SetSlowMode { channel: i64, seconds: u64 },
    /// Set a role's exception for a channel (see `ChannelOverride`). `None` for both `view` and `send`
    /// removes it. Needs Manage channels.
    SetChannelOverride {
        channel: i64,
        role: i64,
        #[serde(default)]
        view: Option<bool>,
        #[serde(default)]
        send: Option<bool>,
        #[serde(default)]
        manage_channels: Option<bool>,
        #[serde(default)]
        manage_messages: Option<bool>,
    },
    /// Set a role's permission for a category, and for every channel in it. `None` for both removes
    /// it. Needs Manage channels.
    SetCategoryOverride {
        category: i64,
        role: i64,
        #[serde(default)]
        view: Option<bool>,
        #[serde(default)]
        send: Option<bool>,
        #[serde(default)]
        manage_channels: Option<bool>,
        #[serde(default)]
        manage_messages: Option<bool>,
    },
    /// Set a member's permission for a category, and for every channel in it. Needs Manage channels.
    SetCategoryMemberOverride {
        category: i64,
        member: String,
        #[serde(default)]
        view: Option<bool>,
        #[serde(default)]
        send: Option<bool>,
        #[serde(default)]
        manage_channels: Option<bool>,
        #[serde(default)]
        manage_messages: Option<bool>,
    },
    /// Set a member's permission for a channel. Needs Manage channels.
    SetChannelMemberOverride {
        channel: i64,
        member: String,
        #[serde(default)]
        view: Option<bool>,
        #[serde(default)]
        send: Option<bool>,
        #[serde(default)]
        manage_channels: Option<bool>,
        #[serde(default)]
        manage_messages: Option<bool>,
    },
}

/// A member's mentions on one server: the unread messages that ping them, across its channels.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MentionTotal {
    pub account: String,
    pub total: u32,
}

/// A server's mention total for one account, as the auth service holds it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerMentions {
    pub server_id: String,
    pub total: u32,
}

/// What a member has not read in one channel: the messages since they last read it, and how many of those ping them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnreadCount {
    pub channel_id: i64,
    pub unread: u32,
    pub mentions: u32,
}

/// A channel's slow mode: the seconds a member must wait between their messages in it. Channels
/// without slow mode are left out of the list.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlowMode {
    pub channel_id: i64,
    pub seconds: u64,
}

/// A channel, by its permanent id and its current name. Only the name can change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ChannelRef {
    pub id: i64,
    pub name: String,
}

/// A category, by its permanent id, with the channels in it, in order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryInfo {
    pub id: i64,
    pub name: String,
    pub channels: Vec<ChannelRef>,
}

/// A direct message conversation, as the account that is part of it sees it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirectMessage {
    /// The channel's permanent id.
    #[serde(default)]
    pub channel_id: i64,
    /// The channel name to join. It does not show who the conversation is with.
    pub channel: String,
    /// The other member's display name.
    pub name: String,
    /// When the last message was sent (Unix seconds), or 0 when there is none. Lists are sorted by it.
    #[serde(default)]
    pub last_message: u64,
    /// The other member's hidden account id. The same person has the same id on every server.
    #[serde(default)]
    pub other_id: String,
}

/// Where the direct message service listens by default, over TLS like the auth service.
pub const DEFAULT_DM_ADDR: &str = "127.0.0.1:7910";

/// Longest message a direct message can hold, in characters. Same as a channel message.
pub const MAX_DM_TEXT_LEN: usize = 2000;

/// A request to the direct message service, one JSON line each. Every request carries the sender's session
/// `token`, which the service checks with the auth service. Conversations are named by `channel_id`, as
/// channels are on a chat server, and their channel name is `dm-<channel_id>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DmRequest {
    /// Open the conversation with the account `with`, creating it the first time. Answered with `Opened`.
    Open { token: String, with: String },
    /// The conversations the account is in, newest first. Answered with `Conversations`.
    List { token: String },
    /// The latest messages of a conversation the account is in, oldest first. Answered with `Messages`.
    History { token: String, channel_id: i64 },
    /// Send a message to the account `to`, optionally as a reply to message `reply_to`. Answered with `Changed`.
    Send {
        token: String,
        to: String,
        text: String,
        #[serde(default)]
        reply_to: Option<i64>,
    },
    /// Change your own message. Answered with `Changed`.
    Edit { token: String, id: i64, text: String },
    /// Delete your own message. Answered with `Deleted`.
    Delete { token: String, id: i64 },
    /// Add your reaction to a message, or take it off if you already reacted with that emoji. Answered with `Changed`.
    React { token: String, id: i64, emoji: String },
    /// Pin or unpin a message in its conversation. Answered with `Changed`.
    Pin { token: String, id: i64, pinned: bool },
    /// Mark a conversation read up to message `id`. Answered with `Read`.
    Read { token: String, channel_id: i64, id: i64 },
    /// Everything that changed after change number `after` in the account's conversations, and the number
    /// to ask from next time. Answered with `Updates`. Start with `after` of 0.
    Poll { token: String, after: i64 },
}

/// The last message the account read in a conversation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DmRead {
    pub channel_id: i64,
    pub id: i64,
}

/// A message that was deleted, so a client can take it away.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DmDeleted {
    pub channel_id: i64,
    pub id: i64,
}

/// Replies from the direct message service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DmReply {
    /// The conversation asked for by `Open`.
    Opened { conversation: DirectMessage },
    /// The conversations, and the account's read positions in them.
    Conversations {
        list: Vec<DirectMessage>,
        #[serde(default)]
        read: Vec<DmRead>,
    },
    /// The messages asked for by `History`, oldest first.
    Messages { messages: Vec<ChatMessage> },
    /// A message that was sent or changed.
    Changed { message: ChatMessage },
    /// A message that was deleted.
    Deleted { channel_id: i64, id: i64 },
    /// The read position was saved.
    Read,
    /// What changed since the `after` of the poll: messages that are new or changed, messages deleted, and the
    /// number to ask from next time.
    Updates {
        messages: Vec<ChatMessage>,
        deleted: Vec<DmDeleted>,
        seq: i64,
    },
    /// The request was refused, with the reason.
    Error { text: String },
}

/// Messages sent from server to client.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMsg {
    /// `name` is your own display name; `server_name` and `server_description` describe the server.
    Welcome {
        name: String,
        /// The server's own id. It stays the same when the server's address changes.
        #[serde(default)]
        server_id: String,
        /// Your hidden account id.
        #[serde(default)]
        user_id: String,
        server_name: String,
        server_description: String,
        server_icon: Option<String>,
        /// True once other servers know this one.
        server_public: bool,
    },
    /// The server's name or description changed (sent to everyone connected).
    ServerUpdated {
        name: String,
        description: String,
    },
    /// The server icon changed (`None` means it was removed).
    ServerIcon {
        png_base64: Option<String>,
    },
    /// This server's public details, for the server list.
    Info {
        /// The server's own id, as in `Welcome`.
        #[serde(default)]
        server_id: String,
        name: String,
        description: String,
        icon: Option<String>,
        /// How many connections are open to this server right now.
        online: u32,
        /// True once other servers know this one.
        public: bool,
        /// True when the server uses a certificate it made itself, not one from a certificate authority.
        #[serde(default)]
        self_signed: bool,
    },
    /// Addresses of servers this one knows about, including itself.
    Peers {
        addrs: Vec<String>,
    },
    Joined {
        channel: ChannelRef,
        history: Vec<ChatMessage>,
    },
    Message {
        message: ChatMessage,
    },
    /// A message in `channel` now has this text.
    MessageEdited {
        channel_id: i64,
        id: i64,
        text: String,
    },
    /// A message in `channel` was deleted.
    MessageDeleted {
        channel_id: i64,
        id: i64,
    },
    /// A message was pinned or unpinned.
    MessagePinned {
        channel_id: i64,
        id: i64,
        pinned: bool,
    },
    /// A channel's pinned messages, the most recently pinned first.
    Pins {
        channel_id: i64,
        messages: Vec<ChatMessage>,
    },
    /// The server's automatic moderation rules, for those who may change them.
    AutoMod {
        rules: AutoMod,
    },
    /// The server was deleted by its owner. Sent to every connection, which is then closed.
    ServerDeleted,
    /// The server's bans, as asked for with `ClientMsg::GetBans`.
    Bans { bans: Vec<BanInfo> },
    /// A member was removed from the server (kicked, or banned). Sent to everyone connected, and the member
    /// removed is told last and disconnected.
    Removed { user: String, banned: bool, reason: String },
    /// A member was timed out until `until` (Unix seconds). Sent to everyone connected.
    TimedOut { user: String, until: u64, reason: String },
    /// A member's timeout was ended early. Sent to everyone connected.
    TimeoutEnded { user: String },
    /// The account left this server, so it is not let back in until it asks to join again. Sent before the
    /// server closes the connection.
    NotJoined,
    /// The account was kicked from this server, so it is not a member until it asks to join again. Sent before the
    /// server closes the connection. `reason` is empty when none was given.
    Kicked { reason: String },
    /// The account is no longer a member of this server. Sent in reply to `LeaveServer`, before the server closes
    /// the connection.
    Left,
    /// The server's system messages settings, for those who may change them.
    SystemMessages {
        settings: SystemMessages,
    },
    /// The reactions on a message in `channel` now look like this.
    Reactions {
        channel_id: i64,
        id: i64,
        reactions: Vec<Reaction>,
    },
    Channels {
        channels: Vec<ChannelRef>,
    },
    /// A channel was deleted. Anyone who had it open moves to another channel.
    ChannelDeleted {
        id: i64,
    },
    /// A channel was renamed. Everyone connected switches to the new name.
    ChannelRenamed {
        id: i64,
        name: String,
    },
    /// The categories of this server, in order, each with its channels. Sent after every change to
    /// them, and in reply to `ClientMsg::ListChannels`. Channels in no category are not listed.
    /// `uncategorized` lists the channels in no category, in order.
    Categories {
        categories: Vec<CategoryInfo>,
        #[serde(default)]
        uncategorized: Vec<ChannelRef>,
    },
    System {
        channel_id: i64,
        text: String,
    },
    /// Every member of this server, online or not, with their roles (sent to everyone on change).
    Presence {
        users: Vec<UserStatus>,
    },
    /// The roles of this server, highest first. Sent on connect and after every change to them.
    Roles {
        roles: Vec<RoleInfo>,
    },
    /// The badges of this server. Sent on connect and after every change to them.
    Badges {
        badges: Vec<Badge>,
    },
    /// The custom emoji of this server. Sent on connect and after every change to them.
    CustomEmoji {
        emoji: Vec<CustomEmoji>,
    },
    /// Someone else is typing in a channel. Only sent to members who may view it.
    Typing {
        channel_id: i64,
        user: String,
        name: String,
    },
    /// A member changed their status text. Sent to everyone connected to this server.
    ProfileStatus {
        user: String,
        text: String,
    },
    /// A member's name in chat changed. Sent to everyone connected to this server, so their messages show it.
    MemberRenamed {
        id: String,
        name: String,
    },
    /// Every channel that has slow mode. Sent on connect and after every change to it.
    SlowModes { modes: Vec<SlowMode> },
    /// What the viewer has not read in each channel, as of connecting. Only channels they have read before are
    /// counted, and only channels with something unread are listed.
    Unread { counts: Vec<UnreadCount> },
    /// Every channel's exceptions for roles. Sent on connect and after every change to them.
    ChannelOverrides {
        overrides: Vec<ChannelOverride>,
    },
    /// Every category's permissions for roles (see `CategoryOverride`).
    CategoryOverrides {
        overrides: Vec<CategoryOverride>,
    },
    /// Every member's permissions for channels and categories.
    MemberOverrides {
        channels: Vec<MemberChannelOverride>,
        categories: Vec<MemberCategoryOverride>,
    },
    /// A new message arrived in a channel other than the one you are viewing. It comes with its content, so the
    /// client can count a mention and raise a notification; only members who may view the channel are sent it.
    Activity {
        message: ChatMessage,
    },
    Error {
        text: String,
    },
}

#[cfg(test)]
#[path = "tests/automod.rs"]
mod automod_tests;

#[cfg(test)]
mod custom_reaction_tests {
    use super::*;

    #[test]
    fn a_custom_emoji_reaction_is_its_name_in_colons() {
        assert_eq!(custom_emoji_name(":party:"), Some("party"));
        assert_eq!(custom_emoji_name(":cat_2:"), Some("cat_2"));
        assert_eq!(custom_emoji_name("party"), None, "no colons");
        assert_eq!(custom_emoji_name(":Party:"), None, "capitals are not allowed");
        assert_eq!(custom_emoji_name("👍"), None, "a picture emoji is not custom");
        assert_eq!(custom_emoji_name(":a:"), None, "too short");
    }

    #[test]
    fn a_custom_emoji_reaction_may_be_longer_than_a_picture_emoji() {
        let long = format!(":{}:", "a".repeat(32));
        assert!(is_reaction(&long));
        assert!(!is_reaction(&"a".repeat(17)), "a picture-style reaction stays short");
    }
}
