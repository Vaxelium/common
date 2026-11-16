//! Wire protocol shared by the Vaxelium server and client.
//!
//! Every message is one JSON object per line (newline-delimited JSON) over TCP.

use serde::{Deserialize, Serialize};

pub mod env;
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
    /// Change the name shown in chat, the username, or both. Needs a valid session.
    UpdateProfile {
        token: String,
        name: Option<String>,
        username: Option<String>,
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
    !emoji.is_empty() && emoji.chars().count() <= 16 && emoji.chars().all(|c| !c.is_control() && !c.is_whitespace())
}
/// One emoji on a message, and who reacted with it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Reaction {
    pub emoji: String,
    pub users: Vec<String>,
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
    /// Every permission there is.
    pub const ALL: u32 = MANAGE_CHANNELS
        | MANAGE_ROLES
        | MANAGE_MESSAGES
        | BYPASS_IGNORE
        | VIEW_CHANNEL
        | SEND_MESSAGES
        | ADMINISTRATOR
        | MANAGE_SERVER;
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

/// A badge an admin gives a member on this server. It shows on the member's profile card.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Badge {
    pub id: i64,
    pub name: String,
    /// A hex colour like "#5865f2", or empty for the default.
    pub color: String,
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
    /// First message on a connection: prove who you are with a session token from the auth service.
    Connect { token: String },
    /// Switch to a channel (created on demand). Receives its history.
    Join { channel: String },
    /// Send a message to the current channel.
    Say { text: String },
    /// Change the text of one of your own messages.
    Edit { id: i64, text: String },
    /// Delete one of your own messages.
    Delete { id: i64 },
    /// Add your reaction to a message, or take it off if it is already there.
    React { id: i64, emoji: String },
    /// Request the list of channels.
    ListChannels,
    /// Open a direct message with the member whose display name is `name`, creating it the first
    /// time. Answered with `ServerMsg::Joined` for the conversation.
    OpenDm { name: String },
    /// Ask for the direct messages you are part of. Answered with `ServerMsg::DirectMessages`.
    ListDirectMessages,
    /// Ask for the history of one direct message you are part of, without joining it. Answered
    /// with `ServerMsg::DmHistory`.
    FetchDm { channel: String },
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
    /// This member is typing in the open channel. Sent a few times while they type.
    Typing,
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
    /// Server to server: deliver a direct message from the account of `token` to the account `to`,
    /// which this server stores as its own copy. Answered with `ServerMsg::RelayAck`.
    RelayDm { token: String, to: String, text: String },
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
    /// The direct messages this account is part of. `name` is the other member's display name.
    DirectMessages {
        list: Vec<DirectMessage>,
    },
    /// The history of a direct message, as asked for with `ClientMsg::FetchDm`.
    DmHistory {
        channel: String,
        messages: Vec<ChatMessage>,
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
    /// A new message arrived in a channel other than the one you are viewing.
    Activity {
        channel_id: i64,
    },
    /// Answer to `ClientMsg::RelayDm`. `error` says why the message was not stored.
    RelayAck {
        error: Option<String>,
    },
    Error {
        text: String,
    },
}
