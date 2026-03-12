//! # ForgeDB TUI
//!
//! This module implements the interactive terminal interface for ForgeDB.
//! It's built on top of `ratatui` because, let's face it, sometimes you just
//! want to poke around your data without leaving the shell. It handles
//! everything from initial setup and login to document CRUD operations.
//!
//! We're using a fairly standard state-machine approach here with `AppScreen`
//! driving the layout. It's not the fanciest concurrent UI design, but it's
//! robust and easy to reason about when things go sideways.

use std::io;

use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{
    Frame, Terminal,
    backend::{Backend, CrosstermBackend},
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap},
};
use reqwest::Client;
use serde_json::Value;

/// Current navigation focus in the dashboard
#[derive(PartialEq)]
enum Focus {
    Collections,
    Documents,
}

/// The overall screen state of the app
#[derive(PartialEq)]
enum AppScreen {
    Initializing,
    Setup,
    Login,
    Dashboard,
    Editor,
    NewCollection,
    NewUser, // Screen for adding a new user
}

struct AuthForm {
    token: String,
    username: String,
    password: String,
    confirm: String,
    focused: usize,
}

struct EditorState {
    buffer: String,
    cursor_pos: usize,
    collection: String,
    doc_id: Option<String>, // None if new
}

struct App {
    url: String,
    client: Client,

    screen: AppScreen,
    status_msg: String,

    // Form data
    auth_form: AuthForm,
    bearer_token: Option<String>,

    // Dashboard Data
    focus: Focus,
    collections: Vec<String>,
    collections_state: ListState,

    // Document List Data
    docs: Vec<Value>,
    docs_state: ListState,

    // Editor State
    editor: Option<EditorState>,

    // New Collection Name
    new_col_name: String,

    // New Collection Tracking
    last_action_collection: Option<String>,
    is_deleting: bool,
}

use std::path::PathBuf;

impl App {
    fn new(url: String, token: Option<String>, cert_path: Option<PathBuf>) -> App {
        let mut builder = Client::builder();

        if let Some(path) = cert_path
            && let Ok(cert_bytes) = std::fs::read(&path)
            && let Ok(cert) = reqwest::Certificate::from_pem(&cert_bytes)
        {
            builder = builder.add_root_certificate(cert);
        }

        let client = builder.build().unwrap_or_else(|_| Client::new());

        App {
            url,
            client,
            screen: AppScreen::Initializing,
            status_msg: "Press 'r' to initialize connection...".into(),

            auth_form: AuthForm {
                token: token.unwrap_or_default(),
                username: String::new(),
                password: String::new(),
                confirm: String::new(),
                focused: 0,
            },
            bearer_token: None,

            focus: Focus::Collections,
            collections: vec![],
            collections_state: ListState::default(),
            docs: vec![],
            docs_state: ListState::default(),

            editor: None,
            new_col_name: String::new(),
            last_action_collection: None,
            is_deleting: false,
        }
    }

    async fn check_auth_status(&mut self) {
        self.status_msg = format!("Checking server at {}...", self.url);
        match self
            .client
            .get(format!("{}/_/auth/status", self.url))
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    let json: Value = resp.json().await.unwrap_or_default();
                    let setup_req = json
                        .get("setup_required")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    if setup_req {
                        self.screen = AppScreen::Setup;
                        self.status_msg = "Admin setup required. Please enter details.".to_string();
                        if !self.auth_form.token.is_empty() {
                            self.auth_form.focused = 1;
                        }
                    } else {
                        self.screen = AppScreen::Login;
                        self.status_msg = "Please log in.".to_string();
                        self.auth_form.focused = 1;
                    }
                } else {
                    self.status_msg = format!("Server error: {}", resp.status());
                }
            }
            Err(e) => self.status_msg = format!("Connection failed: {}", e),
        }
    }

    async fn submit_setup(&mut self) {
        if self.auth_form.password != self.auth_form.confirm {
            self.status_msg = "Passwords do not match!".to_string();
            return;
        }
        let body = serde_json::json!({ "token": self.auth_form.token, "password": self.auth_form.password });
        match self
            .client
            .post(format!("{}/_/auth/setup", self.url))
            .json(&body)
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    self.status_msg = "Setup successful! Proceed to Login...".to_string();
                    self.screen = AppScreen::Login;
                    self.auth_form.username = "admin".into();
                    self.auth_form.password.clear();
                    self.auth_form.confirm.clear();
                    self.auth_form.focused = 1;
                } else {
                    self.status_msg = format!("Setup failed: {}", resp.status());
                }
            }
            Err(e) => self.status_msg = format!("Request failed: {}", e),
        }
    }

    async fn submit_login(&mut self) {
        let body = serde_json::json!({ "username": self.auth_form.username, "password": self.auth_form.password });
        match self
            .client
            .post(format!("{}/_/auth/login", self.url))
            .json(&body)
            .send()
            .await
        {
            Ok(resp) => {
                if resp.status().is_success() {
                    let json: Value = resp.json().await.unwrap_or_default();
                    if let Some(t) = json.get("token").and_then(|v| v.as_str()) {
                        self.bearer_token = Some(t.to_string());
                        self.screen = AppScreen::Dashboard;
                        self.status_msg = "Logged in successfully!".to_string();
                        self.fetch_schema().await;
                    }
                } else {
                    self.status_msg = "Login failed: Unauthorized.".to_string();
                }
            }
            Err(e) => self.status_msg = format!("Request failed: {}", e),
        }
    }

    async fn submit_new_user(&mut self) {
        if self.auth_form.password != self.auth_form.confirm {
            self.status_msg = "Passwords do not match!".to_string();
            return;
        }
        let body = serde_json::json!({
            "username": self.auth_form.username,
            "password": self.auth_form.password
        });
        let req = self.client.post(format!("{}/_/auth/users", self.url));
        let req = if let Some(t) = &self.bearer_token {
            req.bearer_auth(t)
        } else {
            req
        };
        match req.json(&body).send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    self.status_msg = format!("User '{}' created.", self.auth_form.username);
                    self.screen = AppScreen::Dashboard;
                } else if resp.status() == 403 {
                    self.status_msg = "Forbidden: Need admin role to create users.".to_string();
                } else {
                    self.status_msg = format!("Failed to create user: {}", resp.status());
                }
            }
            Err(e) => self.status_msg = format!("Request failed: {}", e),
        }
    }

    async fn fetch_schema(&mut self) {
        let req = self.client.get(format!("{}/_/schema", self.url));
        let req = if let Some(t) = &self.bearer_token {
            req.bearer_auth(t)
        } else {
            req
        };
        match req.send().await {
            Ok(resp) => {
                if resp.status().is_success() {
                    let json: Value = resp.json().await.unwrap_or_default();
                    self.collections.clear();
                    if let Some(colls) = json.get("entity_types").and_then(|c| c.as_array()) {
                        for c in colls {
                            if let Some(name) = c.get("name").and_then(|n| n.as_str()) {
                                self.collections.push(name.to_string());
                            }
                        }
                    }
                    if !self.collections.is_empty() {
                        if let Some(target) = &self.last_action_collection {
                            if let Some(idx) = self.collections.iter().position(|c| c == target) {
                                self.collections_state.select(Some(idx));
                            }
                            self.last_action_collection = None;
                        } else if self.collections_state.selected().is_none() {
                            self.collections_state.select(Some(0));
                        }
                        self.fetch_collection().await;
                    }
                }
            }
            Err(_) => {
                self.status_msg = "Failed to fetch schema.".into();
            }
        }
    }

    async fn fetch_collection(&mut self) {
        if let Some(i) = self.collections_state.selected() {
            let col = &self.collections[i];
            // Explicitly ask for JSON — without this header, the server defaults
            // to application/msgpack, which reqwest's .json() can't decode.
            let req = self.client
                .get(format!("{}/v1/{}?limit=50", self.url, col))
                .header(reqwest::header::ACCEPT, "application/json");
            let req = if let Some(t) = &self.bearer_token {
                req.bearer_auth(t)
            } else {
                req
            };
            match req.send().await {
                Ok(resp) => {
                    let json: Value = resp.json().await.unwrap_or_default();
                    if let Some(data) = json.get("data").and_then(|d| d.as_array()) {
                        self.docs = data.clone();
                        // Reset doc selection if we switched collections or the index is now out of range.
                        if self.docs_state.selected().is_none_or(|s| s >= self.docs.len()) {
                            self.docs_state.select(if !self.docs.is_empty() {
                                Some(0)
                            } else {
                                None
                            });
                        }
                        self.status_msg =
                            format!("Loaded {} records from {}", self.docs.len(), col);
                    }
                }
                Err(_) => {
                    self.status_msg = "Failed to fetch collection data.".into();
                }
            }
        }
    }

    async fn delete_document(&mut self) {
        if let (Some(col_idx), Some(doc_idx)) = (
            self.collections_state.selected(),
            self.docs_state.selected(),
        ) {
            let col = &self.collections[col_idx];
            let doc = &self.docs[doc_idx];
            if let Some(id) = doc.get("id").and_then(|v| v.as_str()) {
                let req = self
                    .client
                    .delete(format!("{}/v1/{}/{}", self.url, col, id));
                let req = if let Some(t) = &self.bearer_token {
                    req.bearer_auth(t)
                } else {
                    req
                };
                if let Ok(resp) = req.send().await {
                    if resp.status().is_success() {
                        self.status_msg = "Document deleted.".into();
                        self.fetch_collection().await;
                    } else {
                        self.status_msg = format!("Delete failed: {}", resp.status());
                    }
                }
            }
        }
        self.is_deleting = false;
    }

    async fn save_editor(&mut self) {
        if let Some(editor) = &self.editor {
            let payload: Value = match serde_json::from_str(&editor.buffer) {
                Ok(v) => v,
                Err(e) => {
                    self.status_msg = format!("Invalid JSON: {}", e);
                    return;
                }
            };

            if !self.collections.contains(&editor.collection) {
                // New collection — patch the Cedar schema dynamically so the server
                // accepts documents for it. We fetch the raw schema, inject the new
                // entity type + resource type entries, then PUT it back.
                let schema_req = self.client.get(format!("{}/_/schema?raw=true", self.url));
                let schema_req = if let Some(t) = &self.bearer_token {
                    schema_req.bearer_auth(t)
                } else {
                    schema_req
                };

                if let Ok(resp) = schema_req.send().await
                    && resp.status().is_success()
                    && let Ok(mut schema) = resp.json::<Value>().await
                {
                    let coll_name_cap = {
                        let mut c = editor.collection.chars();
                        match c.next() {
                            None => String::new(),
                            Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
                        }
                    };

                    let mut modified = false;

                    if let Some(ns) = schema.get_mut("ForgeDB").and_then(|n| n.as_object_mut()) {
                        if let Some(et) = ns.get_mut("entityTypes").and_then(|e| e.as_object_mut())
                            && !et.contains_key(&coll_name_cap)
                        {
                            et.insert(
                                coll_name_cap.clone(),
                                serde_json::json!({
                                    "shape": { "type": "Record", "attributes": {} }
                                }),
                            );
                            modified = true;
                        }

                        if let Some(actions) =
                            ns.get_mut("actions").and_then(|a| a.as_object_mut())
                        {
                            for action in ["Read", "Write", "Delete"] {
                                if let Some(act) = actions.get_mut(action).and_then(|a| a.as_object_mut())
                                    && let Some(applies) = act.get_mut("appliesTo").and_then(|ap| ap.as_object_mut())
                                    && let Some(rt) = applies.get_mut("resourceTypes").and_then(|r| r.as_array_mut())
                                {
                                    let val = serde_json::Value::String(coll_name_cap.clone());
                                    if !rt.contains(&val) {
                                        rt.push(val);
                                        modified = true;
                                    }
                                }
                            }
                        }
                    }

                    if modified {
                        let put_req = self.client.put(format!("{}/_/schema", self.url));
                        let put_req = if let Some(t) = &self.bearer_token {
                            put_req.bearer_auth(t)
                        } else {
                            put_req
                        };
                        let _ = put_req.json(&schema).send().await;
                    }
                }
            }

            let res = if let Some(id) = &editor.doc_id {
                // PATCH
                let req = self
                    .client
                    .patch(format!("{}/v1/{}/{}", self.url, editor.collection, id));
                let req = if let Some(t) = &self.bearer_token {
                    req.bearer_auth(t)
                } else {
                    req
                };
                req.json(&payload).send().await
            } else {
                // POST
                let req = self
                    .client
                    .post(format!("{}/v1/{}", self.url, editor.collection));
                let req = if let Some(t) = &self.bearer_token {
                    req.bearer_auth(t)
                } else {
                    req
                };
                req.json(&payload).send().await
            };

            match res {
                Ok(resp) => {
                    if resp.status().is_success() {
                        self.status_msg = "Saved successfully.".into();
                        self.last_action_collection = Some(editor.collection.clone());
                        self.screen = AppScreen::Dashboard;
                        self.fetch_schema().await;
                    } else {
                        self.status_msg = format!("Save failed: {}", resp.status());
                    }
                }
                Err(e) => self.status_msg = format!("Request failed: {}", e),
            }
        }
    }

    fn handle_input(&mut self, code: KeyCode) {
        match self.screen {
            AppScreen::Setup => self.handle_setup_input(code),
            AppScreen::Login => self.handle_login_input(code),
            AppScreen::Editor => self.handle_editor_input(code),
            AppScreen::NewCollection => self.handle_new_col_input(code),
            AppScreen::NewUser => self.handle_new_user_input(code),
            _ => {}
        }
    }

    fn handle_setup_input(&mut self, code: KeyCode) {
        match code {
            KeyCode::Tab => self.auth_form.focused = (self.auth_form.focused + 1) % 3,
            KeyCode::BackTab => self.auth_form.focused = (self.auth_form.focused + 2) % 3,
            KeyCode::Backspace => match self.auth_form.focused {
                0 => {
                    self.auth_form.token.pop();
                }
                1 => {
                    self.auth_form.password.pop();
                }
                2 => {
                    self.auth_form.confirm.pop();
                }
                _ => {}
            },
            KeyCode::Char(c) => match self.auth_form.focused {
                0 => self.auth_form.token.push(c),
                1 => self.auth_form.password.push(c),
                2 => self.auth_form.confirm.push(c),
                _ => {}
            },
            _ => {}
        }
    }

    fn handle_login_input(&mut self, code: KeyCode) {
        match code {
            KeyCode::Tab => self.auth_form.focused = (self.auth_form.focused + 1) % 2,
            KeyCode::BackTab => self.auth_form.focused = (self.auth_form.focused + 1) % 2,
            KeyCode::Backspace => match self.auth_form.focused {
                0 => {
                    self.auth_form.username.pop();
                }
                1 => {
                    self.auth_form.password.pop();
                }
                _ => {}
            },
            KeyCode::Char(c) => match self.auth_form.focused {
                0 => self.auth_form.username.push(c),
                1 => self.auth_form.password.push(c),
                _ => {}
            },
            _ => {}
        }
    }

    fn handle_new_user_input(&mut self, code: KeyCode) {
        match code {
            KeyCode::Tab => self.auth_form.focused = (self.auth_form.focused + 1) % 3,
            KeyCode::BackTab => self.auth_form.focused = (self.auth_form.focused + 2) % 3,
            KeyCode::Backspace => match self.auth_form.focused {
                0 => {
                    self.auth_form.username.pop();
                }
                1 => {
                    self.auth_form.password.pop();
                }
                2 => {
                    self.auth_form.confirm.pop();
                }
                _ => {}
            },
            KeyCode::Char(c) => match self.auth_form.focused {
                0 => self.auth_form.username.push(c),
                1 => self.auth_form.password.push(c),
                2 => self.auth_form.confirm.push(c),
                _ => {}
            },
            _ => {}
        }
    }

    fn handle_editor_input(&mut self, code: KeyCode) {
        if let Some(editor) = &mut self.editor {
            match code {
                KeyCode::Char(c) => {
                    editor.buffer.insert(editor.cursor_pos, c);
                    editor.cursor_pos += 1;
                }
                KeyCode::Backspace => {
                    if editor.cursor_pos > 0 {
                        editor.buffer.remove(editor.cursor_pos - 1);
                        editor.cursor_pos -= 1;
                    }
                }
                KeyCode::Left => {
                    if editor.cursor_pos > 0 {
                        editor.cursor_pos -= 1;
                    }
                }
                KeyCode::Right => {
                    if editor.cursor_pos < editor.buffer.len() {
                        editor.cursor_pos += 1;
                    }
                }
                KeyCode::Enter => {
                    editor.buffer.insert(editor.cursor_pos, '\n');
                    editor.cursor_pos += 1;
                }
                _ => {}
            }
        }
    }

    fn handle_new_col_input(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char(c) => self.new_col_name.push(c),
            KeyCode::Backspace => {
                self.new_col_name.pop();
            }
            _ => {}
        }
    }
}
/// Entry point for the ForgeDB TUI application.
///
/// This function kicks off the terminal loop, handles raw mode switching,
/// and manages the overall lifecycle. If something blows up, we try to
/// restore the terminal state before exiting so the user isn't left with
/// a borked shell.
///
/// # Examples
///
/// ```no_run
/// use forge_cli::tui;
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// tui::run("https://localhost:5826".to_string(), None, None)?;
/// # Ok(())
/// # }
/// ```
///
/// # Errors
///
/// Returns a `forge_types::Result` if terminal initialization or restoration fails.
pub fn run(
    url: String,
    token: Option<String>,
    cert_path: Option<PathBuf>,
) -> forge_types::Result<()> {
    let mut terminal = setup_terminal()?;
    let mut app = App::new(url, token, cert_path);
    let rt = tokio::runtime::Runtime::new().unwrap();

    rt.block_on(async {
        app.check_auth_status().await;
        if let Err(e) = run_app(&mut terminal, &mut app).await {
            eprintln!("TUI Error: {:?}", e);
        }
    });

    restore_terminal(&mut terminal)?;
    Ok(())
}

fn setup_terminal() -> forge_types::Result<Terminal<CrosstermBackend<io::Stdout>>> {
    enable_raw_mode().unwrap();
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture).unwrap();
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend).map_err(|e| forge_types::ForgeError::Config(e.to_string()))
}

fn restore_terminal(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> forge_types::Result<()> {
    disable_raw_mode().unwrap();
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture,
    )
    .unwrap();
    terminal.show_cursor().unwrap();
    Ok(())
}

async fn run_app<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> io::Result<()> {
    loop {
        terminal
            .draw(|f| ui(f, app))
            .map_err(|e| io::Error::other(e.to_string()))?;

        if let Ok(true) = crossterm::event::poll(std::time::Duration::from_millis(100))
            && let Event::Key(key) = event::read()?
        {
            if key.code == KeyCode::Esc {
                if app.is_deleting {
                    app.is_deleting = false;
                    continue;
                }
                if app.screen == AppScreen::Dashboard {
                    return Ok(());
                }
                app.screen = AppScreen::Dashboard;
                continue;
            }
            if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('c') {
                return Ok(());
            }

            match app.screen {
                AppScreen::Initializing => {
                    if key.code == KeyCode::Char('r') {
                        app.check_auth_status().await;
                    }
                }
                AppScreen::Setup => {
                    if key.code == KeyCode::Enter {
                        if app.auth_form.focused < 2 {
                            app.auth_form.focused += 1;
                        } else {
                            app.submit_setup().await;
                        }
                    } else {
                        app.handle_input(key.code);
                    }
                }
                AppScreen::Login => {
                    if key.code == KeyCode::Enter {
                        if app.auth_form.focused < 1 {
                            app.auth_form.focused += 1;
                        } else {
                            app.submit_login().await;
                        }
                    } else {
                        app.handle_input(key.code);
                    }
                }
                AppScreen::NewUser => {
                    if key.code == KeyCode::Enter {
                        if app.auth_form.focused < 2 {
                            app.auth_form.focused += 1;
                        } else {
                            app.submit_new_user().await;
                        }
                    } else {
                        app.handle_input(key.code);
                    }
                }
                AppScreen::Dashboard => {
                    if app.is_deleting {
                        if key.code == KeyCode::Char('y') {
                            app.delete_document().await;
                        } else {
                            app.is_deleting = false;
                        }
                        continue;
                    }
                    match key.code {
                        KeyCode::Tab => {
                            app.focus = if app.focus == Focus::Collections {
                                Focus::Documents
                            } else {
                                Focus::Collections
                            };
                        }
                        KeyCode::Down | KeyCode::Char('j') => {
                            if app.focus == Focus::Collections {
                                let len = app.collections.len();
                                if len > 0 {
                                    let i = match app.collections_state.selected() {
                                        Some(i) => {
                                            if i >= len - 1 {
                                                0
                                            } else {
                                                i + 1
                                            }
                                        }
                                        None => 0,
                                    };
                                    app.collections_state.select(Some(i));
                                    app.fetch_collection().await;
                                }
                            } else {
                                let len = app.docs.len();
                                if len > 0 {
                                    let i = match app.docs_state.selected() {
                                        Some(i) => {
                                            if i >= len - 1 {
                                                0
                                            } else {
                                                i + 1
                                            }
                                        }
                                        None => 0,
                                    };
                                    app.docs_state.select(Some(i));
                                }
                            }
                        }
                        KeyCode::Up | KeyCode::Char('k') => {
                            if app.focus == Focus::Collections {
                                let len = app.collections.len();
                                if len > 0 {
                                    let i = match app.collections_state.selected() {
                                        Some(i) => {
                                            if i == 0 {
                                                len - 1
                                            } else {
                                                i - 1
                                            }
                                        }
                                        None => 0,
                                    };
                                    app.collections_state.select(Some(i));
                                    app.fetch_collection().await;
                                }
                            } else {
                                let len = app.docs.len();
                                if len > 0 {
                                    let i = match app.docs_state.selected() {
                                        Some(i) => {
                                            if i == 0 {
                                                len - 1
                                            } else {
                                                i - 1
                                            }
                                        }
                                        None => 0,
                                    };
                                    app.docs_state.select(Some(i));
                                }
                            }
                        }
                        KeyCode::Char('n') => {
                            app.new_col_name.clear();
                            app.screen = AppScreen::NewCollection;
                        }
                        KeyCode::Char('u') => {
                            app.auth_form.username.clear();
                            app.auth_form.password.clear();
                            app.auth_form.confirm.clear();
                            app.auth_form.focused = 0;
                            app.screen = AppScreen::NewUser;
                        }
                        KeyCode::Char('e') => {
                            // Gotta make sure we actually have a document and a collection selected.
                            // It's a bit defensive, sure, but I've seen too many TUIs blow up because
                            // they assumed state that wasn't there. Trust but verify.
                            if let (Some(i), Some(col_idx)) =
                                (app.docs_state.selected(), app.collections_state.selected())
                                && let Some(doc) = app.docs.get(i)
                            {
                                let id = doc
                                    .get("id")
                                    .and_then(|v| v.as_str())
                                    .map(|s| s.to_string());
                                let col = app.collections[col_idx].clone();
                                let buf = serde_json::to_string_pretty(doc).unwrap_or_default();

                                app.editor = Some(EditorState {
                                    buffer: buf,
                                    cursor_pos: 0,
                                    collection: col,
                                    doc_id: id,
                                });
                                app.screen = AppScreen::Editor;
                            }
                        }
                        KeyCode::Char('a') => {
                            if let Some(i) = app.collections_state.selected() {
                                let col = app.collections[i].clone();
                                app.editor = Some(EditorState {
                                    buffer: "{\n  \"name\": \"new item\"\n}".into(),
                                    cursor_pos: 15,
                                    collection: col,
                                    doc_id: None,
                                });
                                app.screen = AppScreen::Editor;
                            }
                        }
                        KeyCode::Char('d') => {
                            if app.docs_state.selected().is_some() {
                                app.is_deleting = true;
                            }
                        }
                        KeyCode::Char('r') => {
                            app.fetch_schema().await;
                        }
                        _ => {}
                    }
                }
                AppScreen::Editor => {
                    if key.modifiers == KeyModifiers::CONTROL && key.code == KeyCode::Char('s') {
                        app.save_editor().await;
                    } else {
                        app.handle_input(key.code);
                    }
                }
                AppScreen::NewCollection => {
                    if key.code == KeyCode::Enter && !app.new_col_name.is_empty() {
                        let col = app.new_col_name.clone();
                        app.editor = Some(EditorState {
                            buffer: "{\n  \"init\": true\n}".into(),
                            cursor_pos: 15,
                            collection: col,
                            doc_id: None,
                        });
                        app.screen = AppScreen::Editor;
                    } else {
                        app.handle_input(key.code);
                    }
                }
            }
        }
    }
}

fn ui(f: &mut Frame, app: &mut App) {
    let size = f.area();
    f.render_widget(
        Block::default().style(Style::default().bg(Color::White).fg(Color::Black)),
        size,
    );

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(1)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(0),
            Constraint::Length(1),
        ])
        .split(size);

    draw_header(f, app, chunks[0]);
    match app.screen {
        AppScreen::Initializing => draw_initializing(f, app, chunks[1]),
        AppScreen::Setup => draw_auth_form(f, app, chunks[1]),
        AppScreen::Login => draw_auth_form(f, app, chunks[1]),
        AppScreen::NewUser => draw_auth_form(f, app, chunks[1]),
        AppScreen::Dashboard => draw_dashboard(f, app, chunks[1]),
        AppScreen::Editor => draw_editor(f, app, chunks[1]),
        AppScreen::NewCollection => draw_new_col_dialog(f, app, chunks[1]),
    }
    draw_footer(f, app, chunks[2]);

    if app.is_deleting {
        draw_delete_confirmation(f, chunks[1]);
    }
}

fn draw_header(f: &mut Frame, _app: &mut App, area: Rect) {
    let text = Line::from(vec![
        Span::styled(
            " Forge",
            Style::default()
                .fg(Color::Rgb(15, 23, 42))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "DB",
            Style::default()
                .fg(Color::Rgb(2, 132, 199))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" Terminal", Style::default().fg(Color::Rgb(100, 116, 139))),
    ]);
    f.render_widget(
        Paragraph::new(text).block(
            Block::default()
                .borders(Borders::BOTTOM)
                .border_style(Style::default().fg(Color::Rgb(226, 232, 240))),
        ),
        area,
    );
}

fn draw_footer(f: &mut Frame, app: &mut App, area: Rect) {
    let help = match app.screen {
        AppScreen::Dashboard => {
            " [N] New Col  [A] Add  [E] Edit  [D] Del  [R] Sync  [U] New User  [TAB] Swap Focus  [Esc] Quit "
        }
        AppScreen::Editor => " [Ctrl+S] Store  [Esc] Back  Type to edit JSON directly ",
        AppScreen::NewCollection => " [Enter] Confirm  [Esc] Cancel ",
        _ => " [Esc] Exit ",
    };
    let footer = Paragraph::new(Line::from(vec![
        Span::styled(
            format!(" STATUS: {} ", app.status_msg),
            Style::default()
                .fg(Color::Rgb(15, 23, 42))
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            format!("  {}", help),
            Style::default().fg(Color::Rgb(148, 163, 184)),
        ),
    ]));
    f.render_widget(footer, area);
}

fn draw_initializing(f: &mut Frame, app: &mut App, area: Rect) {
    f.render_widget(
        Paragraph::new(app.status_msg.clone()).alignment(Alignment::Center),
        area,
    );
}

fn draw_auth_form(f: &mut Frame, app: &mut App, area: Rect) {
    // Just use the center rect directly. Nested splits can collapse the height entirely on smaller terminals.
    let form_area = center_rect(60, 80, area);

    let title = match app.screen {
        AppScreen::Setup => " SETUP ",
        AppScreen::Login => " LOGIN ",
        AppScreen::NewUser => " ADD DB USER ",
        _ => " FORM ",
    };

    let block = Block::default()
        .title(title)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Rgb(56, 189, 248)))
        .style(Style::default());

    f.render_widget(block.clone(), form_area);

    let inputs = Layout::default()
        .direction(Direction::Vertical)
        .margin(2)
        .spacing(2)
        .constraints([
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(block.inner(form_area));

    let render_input = |f: &mut Frame, text: String, is_active: bool, area: Rect| {
        let active = Style::default()
            .fg(Color::Black)
            .add_modifier(Modifier::BOLD);
        let inactive = Style::default().fg(Color::DarkGray);

        f.render_widget(
            Paragraph::new(text).style(if is_active { active } else { inactive }),
            area,
        );
    };

    match app.screen {
        AppScreen::Setup => {
            render_input(
                f,
                format!("PASETO: {}", app.auth_form.token),
                app.auth_form.focused == 0,
                inputs[0],
            );
            render_input(
                f,
                format!("Password: {}", "*".repeat(app.auth_form.password.len())),
                app.auth_form.focused == 1,
                inputs[1],
            );
            render_input(
                f,
                format!("Confirm:  {}", "*".repeat(app.auth_form.confirm.len())),
                app.auth_form.focused == 2,
                inputs[2],
            );
        }
        AppScreen::Login => {
            render_input(
                f,
                format!("Username: {}", app.auth_form.username),
                app.auth_form.focused == 0,
                inputs[0],
            );
            render_input(
                f,
                format!("Password: {}", "*".repeat(app.auth_form.password.len())),
                app.auth_form.focused == 1,
                inputs[1],
            );
        }
        AppScreen::NewUser => {
            render_input(
                f,
                format!("Username: {}", app.auth_form.username),
                app.auth_form.focused == 0,
                inputs[0],
            );
            render_input(
                f,
                format!("Password: {}", "*".repeat(app.auth_form.password.len())),
                app.auth_form.focused == 1,
                inputs[1],
            );
            render_input(
                f,
                format!("Confirm:  {}", "*".repeat(app.auth_form.confirm.len())),
                app.auth_form.focused == 2,
                inputs[2],
            );
        }
        _ => {}
    }
}

fn draw_dashboard(f: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(15), // Tables
            Constraint::Percentage(85), // Records + Preview
        ])
        .split(area);

    let active_style = Style::default()
        .fg(Color::Rgb(2, 132, 199))
        .add_modifier(Modifier::BOLD);
    let inactive_style = Style::default().fg(Color::Rgb(226, 232, 240));

    let items: Vec<ListItem> = app
        .collections
        .iter()
        .map(|c| {
            ListItem::new(format!("  {}  ", c)).style(Style::default().fg(Color::Rgb(71, 85, 105)))
        })
        .collect();

    f.render_stateful_widget(
        List::new(items)
            .block(
                Block::default()
                    .title(" TABLES ")
                    .borders(Borders::ALL)
                    .border_style(if app.focus == Focus::Collections {
                        active_style
                    } else {
                        inactive_style
                    }),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Rgb(2, 132, 199))
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(" "),
        chunks[0],
        &mut app.collections_state,
    );

    // Records & Preview split
    let has_selection = app.docs_state.selected().is_some();
    let data_parts = Layout::default()
        .direction(Direction::Horizontal)
        .constraints(if has_selection {
            [Constraint::Percentage(40), Constraint::Percentage(60)]
        } else {
            [Constraint::Percentage(100), Constraint::Min(0)]
        })
        .split(chunks[1]);

    let doc_items: Vec<ListItem> = app
        .docs
        .iter()
        .map(|d| {
            let id = d.get("id").and_then(|v| v.as_str()).unwrap_or("?");
            ListItem::new(format!("  {}   ", id)).style(Style::default().fg(Color::Rgb(30, 41, 59)))
        })
        .collect();

    f.render_stateful_widget(
        List::new(doc_items)
            .block(
                Block::default()
                    .title(" RECORDS ")
                    .borders(Borders::ALL)
                    .border_style(if app.focus == Focus::Documents {
                        active_style
                    } else {
                        inactive_style
                    }),
            )
            .highlight_style(
                Style::default()
                    .fg(Color::Rgb(2, 132, 199))
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(" "),
        data_parts[0],
        &mut app.docs_state,
    );

    // Preview
    if let Some(doc) = app.docs_state.selected().and_then(|i| app.docs.get(i)) {
        f.render_widget(
            Paragraph::new(serde_json::to_string_pretty(doc).unwrap_or_default())
                .block(
                    Block::default()
                        .title(" PREVIEW ")
                        .borders(Borders::ALL)
                        .border_style(inactive_style),
                )
                .style(Style::default().fg(Color::Rgb(71, 85, 105)))
                .wrap(Wrap { trim: false }),
            data_parts[1],
        );
    }
}

fn draw_editor(f: &mut Frame, app: &mut App, area: Rect) {
    if let Some(editor) = &app.editor {
        let title = match &editor.doc_id {
            Some(id) => format!(" UPDATING {} / {} ", editor.collection, id),
            None => format!(" CREATING IN {} ", editor.collection),
        };
        f.render_widget(Clear, area);
        f.render_widget(
            Paragraph::new(editor.buffer.as_str())
                .block(
                    Block::default()
                        .title(title)
                        .borders(Borders::ALL)
                        .border_style(Style::default().fg(Color::Rgb(2, 132, 199)))
                        .style(Style::default().bg(Color::White).fg(Color::Black)),
                )
                .style(Style::default().bg(Color::White).fg(Color::Black)),
            area,
        );
    }
}

fn draw_new_col_dialog(f: &mut Frame, app: &mut App, area: Rect) {
    let popup = center_rect(60, 20, area);
    f.render_widget(Clear, popup);
    f.render_widget(
        Paragraph::new(format!("Name: {}", app.new_col_name))
            .block(
                Block::default()
                    .title(" NEW COLLECTION ")
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Rgb(2, 132, 199)))
                    .style(Style::default().bg(Color::White).fg(Color::Black)),
            )
            .style(Style::default().bg(Color::White).fg(Color::Black))
            .alignment(Alignment::Center),
        popup,
    );
}

fn draw_delete_confirmation(f: &mut Frame, area: Rect) {
    let popup = center_rect(40, 10, area);
    f.render_widget(Clear, popup);
    f.render_widget(
        Paragraph::new("DELETE THIS RECORD?\n[Y] Yes  [Esc] No")
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(Style::default().fg(Color::Red))
                    .style(Style::default().bg(Color::White).fg(Color::Red)),
            )
            .style(Style::default().fg(Color::Red).bg(Color::White))
            .alignment(Alignment::Center),
        popup,
    );
}

fn center_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}
