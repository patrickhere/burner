//! the TUI's state and what each key does to it. no terminal or processes in here

use std::collections::HashMap;

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use crate::burner::{Burner, Launch, Ls, Mode};

pub const NETS: [Option<&str>; 4] = [None, Some("none"), Some("web"), Some("open")];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Launcher,
    Running,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Image,
    Net,
    Cpus,
    Mem,
    Ttl,
    Mode,
    Command,
}

pub const FIELDS: [Field; 7] = [
    Field::Image,
    Field::Net,
    Field::Cpus,
    Field::Mem,
    Field::Ttl,
    Field::Mode,
    Field::Command,
];

/// what the main loop has to do after a key
#[derive(Debug, PartialEq)]
pub enum Action {
    Nothing,
    Quit,
    /// switch to this host: local, or a name from hosts.toml
    Host(String),
    Launch(Vec<String>, Mode),
    Kill(String),
    Refresh,
}

pub struct App {
    pub burner: Burner,
    pub screen: Screen,
    pub field: usize,
    pub images: Vec<String>,
    pub image: usize,
    pub net: usize,
    pub cpus: String,
    pub mem: String,
    pub ttl: String,
    pub mode: Mode,
    pub cmd: String,
    pub ls: Option<Ls>,
    pub ls_err: Option<String>,
    pub selected: usize,
    pub confirm: Option<String>,
    pub killing: Option<String>,
    pub help: bool,
    pub status: String,
    pub users: HashMap<u32, String>,
    /// local and the hosts in hosts.toml, for h
    pub hosts: Vec<String>,
}

impl App {
    pub fn new(burner: Burner, images: Vec<String>) -> App {
        App {
            burner,
            screen: Screen::Launcher,
            field: 0,
            images,
            image: 0,
            net: 0,
            cpus: String::new(),
            mem: String::new(),
            ttl: String::new(),
            mode: Mode::Shell,
            cmd: String::new(),
            ls: None,
            ls_err: None,
            selected: 0,
            confirm: None,
            killing: None,
            help: false,
            status: String::new(),
            users: HashMap::new(),
            hosts: Vec::new(),
        }
    }

    /// h: the next host after the one in use, local first
    pub fn next_host(&self) -> Option<String> {
        let all: Vec<&str> = std::iter::once("local")
            .chain(self.hosts.iter().map(String::as_str))
            .collect();
        if all.len() < 2 {
            return None;
        }
        let now = self.burner.host.as_deref().unwrap_or("local");
        let i = all.iter().position(|h| *h == now).map_or(0, |i| i + 1);
        Some(all[i % all.len()].to_string())
    }

    pub fn launch(&self) -> Launch {
        Launch {
            image: self
                .images
                .get(self.image)
                .cloned()
                .unwrap_or_else(|| "alpine".into()),
            net: NETS[self.net].map(String::from),
            cpus: self.cpus.clone(),
            mem: self.mem.clone(),
            ttl: self.ttl.clone(),
            mode: self.mode,
            cmd: self.cmd.clone(),
        }
    }

    pub fn argv(&self) -> Vec<String> {
        self.burner.interactive(&self.launch().args())
    }

    pub fn focused(&self) -> Field {
        FIELDS[self.field]
    }

    pub fn set_ls(&mut self, r: Result<Ls, String>) {
        match r {
            Ok(ls) => {
                self.selected = self.selected.min(ls.vms.len().saturating_sub(1));
                // the VM being asked about is gone, nothing left to confirm
                if let Some(id) = &self.confirm
                    && !ls.vms.iter().any(|v| &v.id == id)
                {
                    self.confirm = None;
                }
                self.ls = Some(ls);
                self.ls_err = None;
            }
            Err(e) => self.ls_err = Some(e),
        }
    }

    pub fn key(&mut self, k: KeyEvent) -> Action {
        let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
        if ctrl && k.code == KeyCode::Char('c') {
            return Action::Quit;
        }
        if self.help {
            self.help = false;
            return Action::Nothing;
        }
        if let Some(id) = self.confirm.take() {
            if matches!(k.code, KeyCode::Char('y') | KeyCode::Char('Y')) {
                self.killing = Some(id.clone());
                self.status = format!("stopping {id}");
                return Action::Kill(id);
            }
            self.status = "left it running".into();
            return Action::Nothing;
        }
        match k.code {
            KeyCode::Tab | KeyCode::BackTab => {
                self.screen = match self.screen {
                    Screen::Launcher => Screen::Running,
                    Screen::Running => Screen::Launcher,
                };
                return if self.screen == Screen::Running {
                    Action::Refresh
                } else {
                    Action::Nothing
                };
            }
            KeyCode::Esc if !self.status.is_empty() => {
                self.status.clear();
                return Action::Nothing;
            }
            _ => {}
        }
        match self.screen {
            Screen::Launcher => self.launcher_key(k, ctrl),
            Screen::Running => self.running_key(k),
        }
    }

    fn global(&mut self, c: char) -> Action {
        match c {
            'q' => Action::Quit,
            '?' => {
                self.help = true;
                Action::Nothing
            }
            'h' => match self.next_host() {
                Some(h) => Action::Host(h),
                None => {
                    self.status = "no hosts in ~/.config/burner/hosts.toml".into();
                    Action::Nothing
                }
            },
            _ => Action::Nothing,
        }
    }

    fn text(&mut self) -> Option<&mut String> {
        match self.focused() {
            Field::Cpus => Some(&mut self.cpus),
            Field::Mem => Some(&mut self.mem),
            Field::Ttl => Some(&mut self.ttl),
            Field::Command => Some(&mut self.cmd),
            _ => None,
        }
    }

    fn accepts(&self, c: char) -> bool {
        match self.focused() {
            Field::Cpus | Field::Mem => c.is_ascii_digit(),
            Field::Ttl => c.is_ascii_digit() || matches!(c, 's' | 'm' | 'h'),
            Field::Command => !c.is_control(),
            _ => false,
        }
    }

    fn step(&mut self, down: bool) {
        let n = FIELDS.len();
        loop {
            self.field = if down {
                (self.field + 1) % n
            } else {
                (self.field + n - 1) % n
            };
            // the command line only matters for run
            if !(self.focused() == Field::Command && self.mode == Mode::Shell) {
                break;
            }
        }
    }

    fn cycle(&mut self, right: bool) {
        let turn = |i: usize, n: usize| {
            if n == 0 {
                0
            } else if right {
                (i + 1) % n
            } else {
                (i + n - 1) % n
            }
        };
        match self.focused() {
            Field::Image => self.image = turn(self.image, self.images.len()),
            Field::Net => self.net = turn(self.net, NETS.len()),
            Field::Mode => {
                self.mode = match self.mode {
                    Mode::Shell => Mode::Run,
                    Mode::Run => Mode::Shell,
                }
            }
            _ => {}
        }
    }

    fn launcher_key(&mut self, k: KeyEvent, ctrl: bool) -> Action {
        match k.code {
            KeyCode::Up => self.step(false),
            KeyCode::Down => self.step(true),
            KeyCode::Left => self.cycle(false),
            KeyCode::Right => self.cycle(true),
            KeyCode::Char(' ') if self.focused() == Field::Mode => self.cycle(true),
            KeyCode::Backspace => {
                if let Some(t) = self.text() {
                    t.pop();
                }
            }
            KeyCode::Char('u') if ctrl => {
                if let Some(t) = self.text() {
                    t.clear();
                }
            }
            KeyCode::Enter => {
                let l = self.launch();
                if let Some(why) = l.problem() {
                    self.status = why;
                    return Action::Nothing;
                }
                return Action::Launch(self.argv(), l.mode);
            }
            KeyCode::Char(c) if !ctrl && self.accepts(c) => {
                if let Some(t) = self.text() {
                    t.push(c);
                }
            }
            KeyCode::Char(c) if !ctrl => return self.global(c),
            _ => {}
        }
        Action::Nothing
    }

    fn running_key(&mut self, k: KeyEvent) -> Action {
        let n = self.ls.as_ref().map_or(0, |l| l.vms.len());
        match k.code {
            KeyCode::Up => self.selected = self.selected.saturating_sub(1),
            KeyCode::Down => self.selected = (self.selected + 1).min(n.saturating_sub(1)),
            KeyCode::Char('r') => return Action::Refresh,
            KeyCode::Char('k') => {
                if self.killing.is_some() {
                    self.status = "still stopping the last one".into();
                } else if let Some(vm) = self.ls.as_ref().and_then(|l| l.vms.get(self.selected)) {
                    self.confirm = Some(vm.id.clone());
                }
            }
            KeyCode::Char(c) => return self.global(c),
            _ => {}
        }
        Action::Nothing
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::burner::{Vm, parse_ls};

    #[test]
    fn h_cycles_hosts() {
        let mut a = app();
        assert_eq!(a.next_host(), None);
        a.hosts = vec!["mini".into(), "vps".into()];
        assert_eq!(a.next_host().as_deref(), Some("mini"));
        a.burner.host = Some("mini".into());
        assert_eq!(a.next_host().as_deref(), Some("vps"));
        a.burner.host = Some("vps".into());
        assert_eq!(a.next_host().as_deref(), Some("local"));
        // a -H host that isn't in hosts.toml: on to the first
        a.burner.host = Some("box".into());
        assert_eq!(a.next_host().as_deref(), Some("local"));
    }

    fn app() -> App {
        App::new(
            Burner {
                bin: "burner".into(),
                root: false,
                host: None,
            },
            vec!["alpine".into(), "node".into()],
        )
    }

    fn press(a: &mut App, keys: &[KeyCode]) -> Action {
        let mut last = Action::Nothing;
        for k in keys {
            last = a.key(KeyEvent::new(*k, KeyModifiers::NONE));
        }
        last
    }

    fn typed(a: &mut App, s: &str) {
        for c in s.chars() {
            press(a, &[KeyCode::Char(c)]);
        }
    }

    #[test]
    fn fill_in_a_run() {
        let mut a = app();
        press(&mut a, &[KeyCode::Right, KeyCode::Down, KeyCode::Right]);
        assert_eq!(a.launch().image, "node");
        assert_eq!(a.launch().net.as_deref(), Some("none"));
        press(&mut a, &[KeyCode::Down]);
        typed(&mut a, "2x");
        assert_eq!(a.cpus, "2");
        press(&mut a, &[KeyCode::Down, KeyCode::Down]);
        typed(&mut a, "90s");
        press(&mut a, &[KeyCode::Down, KeyCode::Right, KeyCode::Down]);
        assert_eq!(a.focused(), Field::Command);
        typed(&mut a, "echo q?");
        assert_eq!(a.cmd, "echo q?");
        let act = press(&mut a, &[KeyCode::Enter]);
        assert_eq!(
            act,
            Action::Launch(
                [
                    "sudo", "burner", "run", "--img", "node", "--net", "none", "--cpus", "2",
                    "--ttl", "90s", "--", "echo q?"
                ]
                .map(String::from)
                .to_vec(),
                Mode::Run
            )
        );
    }

    #[test]
    fn shell_skips_the_command_field() {
        let mut a = app();
        press(&mut a, &[KeyCode::Up]);
        assert_eq!(a.focused(), Field::Mode);
        press(&mut a, &[KeyCode::Down]);
        assert_eq!(a.focused(), Field::Image);
    }

    #[test]
    fn q_quits_unless_it_is_typed() {
        let mut a = app();
        assert_eq!(press(&mut a, &[KeyCode::Char('q')]), Action::Quit);
        a.mode = Mode::Run;
        a.field = 6;
        assert_eq!(press(&mut a, &[KeyCode::Char('q')]), Action::Nothing);
        assert_eq!(a.cmd, "q");
        assert_eq!(
            a.key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            Action::Quit
        );
    }

    #[test]
    fn a_bad_launch_says_why() {
        let mut a = app();
        a.mode = Mode::Run;
        assert_eq!(press(&mut a, &[KeyCode::Enter]), Action::Nothing);
        assert_eq!(a.status, "type a command to run");
    }

    #[test]
    fn kill_asks_first() {
        let mut a = app();
        assert_eq!(press(&mut a, &[KeyCode::Tab]), Action::Refresh);
        a.set_ls(Ok(Ls {
            vms: vec![
                Vm {
                    id: "burner-000000000001".into(),
                    ..Vm::default()
                },
                Vm {
                    id: "burner-000000000002".into(),
                    ..Vm::default()
                },
            ],
            ..Ls::default()
        }));
        press(&mut a, &[KeyCode::Down, KeyCode::Down, KeyCode::Char('k')]);
        assert_eq!(a.confirm.as_deref(), Some("burner-000000000002"));
        assert_eq!(press(&mut a, &[KeyCode::Char('n')]), Action::Nothing);
        assert_eq!(a.confirm, None);
        press(&mut a, &[KeyCode::Char('k')]);
        assert_eq!(
            press(&mut a, &[KeyCode::Char('y')]),
            Action::Kill("burner-000000000002".into())
        );
        // one at a time
        press(&mut a, &[KeyCode::Char('k')]);
        assert_eq!(a.confirm, None);
    }

    #[test]
    fn selection_follows_the_list() {
        let mut a = app();
        a.screen = Screen::Running;
        a.selected = 5;
        a.set_ls(parse_ls(r#"{"vms":[{"id":"burner-000000000001"}]}"#));
        assert_eq!(a.selected, 0);
        a.set_ls(Err("sudo: a password is required".into()));
        assert!(a.ls.is_some());
        assert!(a.ls_err.is_some());
    }
}
