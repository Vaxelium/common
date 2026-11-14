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

/// Requests sent to the auth service. One JSON line per request, one reply line back.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthRequest {
    Register { name: String, email: String, password: String },
    Login { email: String, password: String },
    /// Ask who a session token belongs to. Used by chat servers.
    Verify { token: String },
    /// End a session so its token stops working.
    Logout { token: String },
    /// Ask for the account's names and email. Needs a valid session.
    Profile { token: String },
    /// Change the name shown in chat, the username, or both. Needs a valid session.
    UpdateProfile { token: String, name: Option<String>, username: Option<String> },
    /// Change the account's email. Needs the session and the current password.
    ChangeEmail { token: String, password: String, new_email: String },
    /// Find an account by its display name. Used to start a direct message with someone who is not
    /// on the same server.
    Lookup { name: String },
    /// A chat server reports that the account of `token` was connected at `addr`.
    Seen { token: String, addr: String },
    /// Ask which servers an account was last seen at, most recent first.
    Locate { id: String },
    /// Ask for the new ids of accounts that had their old id (their name) migrated to a random one.
    /// Used by chat servers to update what they stored under the old ids.
    Migrations { old_ids: Vec<String> },
}

/// Replies from the auth service.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthReply {
    /// Register or login succeeded. Keep `token` and send it to chat servers.
    Session { token: String, name: String },
    /// The token is valid for this account.
    /// `id` identifies the account in chat; `name` is the name to show.
    Verified { id: String, name: String },
    LoggedOut,
    /// The account's display name, username, and email if one is on record.
    Profile { name: String, username: String, email: Option<String> },
    /// The email was changed to this one.
    EmailChanged { email: String },
    /// The account with the display name that was looked up.
    Account { id: String, name: String },
    /// The servers an account was last seen at, most recent first.
    Locations { addrs: Vec<String> },
    /// The (old id, new id) pairs for the old ids asked about that were migrated.
    Migrations { pairs: Vec<(String, String)> },
    /// A sighting was recorded.
    Recorded,
    Error { text: String },
}

pub mod emoji_data;

/// The five skin tone variants of an emoji (light to dark), if it has them.
pub fn skin_tone_variants(emoji: &str) -> Option<&'static [&'static str; 5]> {
    emoji_data::SKIN_TONES.iter().find(|(base, _)| *base == emoji).map(|(_, variants)| variants)
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
    /// Every permission there is.
    pub const ALL: u32 = MANAGE_CHANNELS | MANAGE_ROLES | MANAGE_MESSAGES | BYPASS_IGNORE;
}

/// Longest role name, in characters.
pub const MAX_ROLE_NAME_LEN: usize = 32;

/// The id of the `@everyone` role. Every member has it, it always sits at the bottom of the
/// hierarchy, and it cannot be deleted, moved or given out. Its colour and permissions apply to all.
pub const EVERYONE_ROLE: i64 = 0;

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
    PlaceChannel { channel: i64, category: Option<i64>, before: Option<i64> },
    /// Put a channel in a category, or take it out of its category with `None`.
    MoveChannel { channel: i64, category: Option<i64> },
    /// Create a role at the bottom of the hierarchy. Needs Manage roles, and can only grant
    /// permissions the sender has.
    CreateRole { name: String, color: String, permissions: u32 },
    /// Change a role's name, colour and permissions. Needs Manage roles, and the role must be below
    /// the sender's highest role.
    UpdateRole { role: i64, name: String, color: String, permissions: u32 },
    /// Delete a role. Members who had it lose it. Same rules as `UpdateRole`.
    DeleteRole { role: i64 },
    /// Move a role so it sits just above another one (or at the bottom, with `None`). Same rules as
    /// `UpdateRole`.
    MoveRole { role: i64, before: Option<i64> },
    /// Give a member a role, or take it away with `on` false. Needs Manage roles, and both the role
    /// and the member's highest role must be below the sender's highest role.
    SetMemberRole { user: String, role: i64, on: bool },
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
    ServerUpdated { name: String, description: String },
    /// The server icon changed (`None` means it was removed).
    ServerIcon { png_base64: Option<String> },
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
    },
    /// Addresses of servers this one knows about, including itself.
    Peers { addrs: Vec<String> },
    Joined { channel: ChannelRef, history: Vec<ChatMessage> },
    Message { message: ChatMessage },
    /// A message in `channel` now has this text.
    MessageEdited { channel_id: i64, id: i64, text: String },
    /// A message in `channel` was deleted.
    MessageDeleted { channel_id: i64, id: i64 },
    /// The reactions on a message in `channel` now look like this.
    Reactions { channel_id: i64, id: i64, reactions: Vec<Reaction> },
    Channels { channels: Vec<ChannelRef> },
    /// A channel was deleted. Anyone who had it open moves to another channel.
    ChannelDeleted { id: i64 },
    /// A channel was renamed. Everyone connected switches to the new name.
    ChannelRenamed { id: i64, name: String },
    /// The categories of this server, in order, each with its channels. Sent after every change to
    /// them, and in reply to `ClientMsg::ListChannels`. Channels in no category are not listed.
    /// `uncategorized` lists the channels in no category, in order.
    Categories {
        categories: Vec<CategoryInfo>,
        #[serde(default)]
        uncategorized: Vec<ChannelRef>,
    },
    /// The direct messages this account is part of. `name` is the other member's display name.
    DirectMessages { list: Vec<DirectMessage> },
    /// The history of a direct message, as asked for with `ClientMsg::FetchDm`.
    DmHistory { channel: String, messages: Vec<ChatMessage> },
    System { channel_id: i64, text: String },
    /// Every member of this server, online or not, with their roles (sent to everyone on change).
    Presence { users: Vec<UserStatus> },
    /// The roles of this server, highest first. Sent on connect and after every change to them.
    Roles { roles: Vec<RoleInfo> },
    /// A new message arrived in a channel other than the one you are viewing.
    Activity { channel_id: i64 },
    /// Answer to `ClientMsg::RelayDm`. `error` says why the message was not stored.
    RelayAck { error: Option<String> },
    Error { text: String },
}
