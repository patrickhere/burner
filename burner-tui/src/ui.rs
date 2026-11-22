use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Clear, Paragraph, Row, Table, TableState, Wrap};

use crate::app::{App, FIELDS, Field, NETS, Screen};
use crate::burner::{Mode, dur, join};

pub fn draw(f: &mut Frame, app: &App) {
    let [top, body, status, keys] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(0),
        Constraint::Length(1),
        Constraint::Length(1),
    ])
    .areas(f.area());
    tabs(f, app, top);
    match app.screen {
        Screen::Launcher => launcher(f, app, body),
        Screen::Running => running(f, app, body),
    }
    f.render_widget(Paragraph::new(app.status.as_str()).yellow(), status);
    let hint = match app.screen {
        Screen::Launcher => {
            " up/down pick a field  left/right change it  enter launch  tab running VMs  ? help  q quit"
        }
        Screen::Running => " up/down pick a VM  k kill  r refresh  tab launcher  ? help  q quit",
    };
    f.render_widget(Paragraph::new(hint).dim(), keys);
    if let Some(id) = &app.confirm {
        confirm(f, id);
    }
    if app.help {
        help(f);
    }
}

fn tabs(f: &mut Frame, app: &App, area: Rect) {
    let count = app
        .ls
        .as_ref()
        .map(|l| format!(" ({})", l.vms.len()))
        .unwrap_or_default();
    let tab = |name: String, on: bool| {
        let s = Span::raw(format!(" {name} "));
        if on { s.reversed().bold() } else { s }
    };
    let host = app.burner.host.as_deref().unwrap_or("local");
    let line = Line::from(vec![
        Span::raw(" burner ").bold(),
        Span::raw(" "),
        tab("launcher".into(), app.screen == Screen::Launcher),
        Span::raw(" "),
        tab(format!("running{count}"), app.screen == Screen::Running),
        Span::raw(format!("   host: {host}")).dim(),
    ]);
    f.render_widget(Paragraph::new(line), area);
}

fn launcher(f: &mut Frame, app: &App, area: Rect) {
    let launch = app.launch();
    let mut lines = Vec::new();
    for (i, field) in FIELDS.iter().enumerate() {
        let on = i == app.field;
        let off = *field == Field::Command && app.mode == Mode::Shell;
        let (label, value, hint) = match field {
            Field::Image => ("image", choice(&launch.image), ""),
            Field::Net => ("net", choice(NETS[app.net].unwrap_or("default")), ""),
            Field::Cpus => ("cpus", input(&app.cpus, on), ""),
            Field::Mem => ("memory", input(&app.mem, on), "MiB"),
            Field::Ttl => ("ttl", input(&app.ttl, on), "90s, 10m, 1h"),
            Field::Mode => (
                "mode",
                choice(match app.mode {
                    Mode::Shell => "shell",
                    Mode::Run => "run",
                }),
                "",
            ),
            Field::Command => (
                "command",
                match (on, off) {
                    (true, _) => format!("{}_", app.cmd),
                    (false, true) => "only for run".into(),
                    (false, false) => app.cmd.clone(),
                },
                "",
            ),
        };
        let mut l = Line::from(vec![
            Span::raw(if on { " > " } else { "   " }),
            Span::raw(format!("{label:<9}")),
            Span::raw(format!("{value:<16} ")),
            Span::raw(hint).dim(),
        ]);
        if on {
            l = l.bold();
        }
        if off {
            l = l.dim();
        }
        lines.push(l);
    }
    lines.push(Line::raw(""));
    lines.push(Line::raw(" will run:").dim());
    lines.push(Line::raw(format!(" {}", join(&app.argv()))).cyan());
    if let Some(why) = launch.problem() {
        lines.push(Line::raw(format!(" {why}")).red());
    }
    if app.images.is_empty() {
        lines.push(Line::raw(" burner images found nothing, so this is a guess").red());
    }
    f.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::bordered().title(" launch a VM ")),
        area,
    );
}

fn choice(v: &str) -> String {
    format!("< {v} >")
}

fn input(v: &str, on: bool) -> String {
    match (v.is_empty(), on) {
        (true, false) => "default".into(),
        (_, true) => format!("{v}_"),
        (false, false) => v.into(),
    }
}

fn running(f: &mut Frame, app: &App, area: Rect) {
    let block = Block::bordered().title(" running VMs ");
    let inner = block.inner(area);
    f.render_widget(block, area);
    let [head, table] = Layout::vertical([Constraint::Length(1), Constraint::Min(0)]).areas(inner);

    let Some(ls) = &app.ls else {
        let msg = app.ls_err.as_deref().unwrap_or("asking burner ls");
        f.render_widget(
            Paragraph::new(format!(" {msg}")).wrap(Wrap { trim: false }),
            inner,
        );
        return;
    };
    let summary = match &app.ls_err {
        Some(e) => Line::raw(format!(" {e}")).red(),
        None => Line::raw(format!(
            " {} of {} VMs, {}M of {}M memory",
            ls.vms.len(),
            ls.max_vms,
            ls.used_mem,
            ls.total_mem
        ))
        .dim(),
    };
    f.render_widget(Paragraph::new(summary), head);
    if ls.vms.is_empty() {
        f.render_widget(Paragraph::new(" no VMs running"), table);
        return;
    }
    let rows = ls.vms.iter().map(|v| {
        // this machine's /etc/passwd says nothing about a remote host's users
        let owner = match v.owner {
            Some(uid) if app.burner.host.is_some() => uid.to_string(),
            Some(uid) => app.users.get(&uid).cloned().unwrap_or(uid.to_string()),
            None => "-".into(),
        };
        let mut status = v.status.clone();
        if app.killing.as_deref() == Some(v.id.as_str()) {
            status = "stopping".into();
        }
        Row::new(vec![
            v.id.clone(),
            v.tag.clone(),
            v.img.clone(),
            v.vcpus.to_string(),
            format!("{}M", v.mem),
            v.net.clone(),
            status,
            dur(v.age),
            v.ttl_left.map_or("-".into(), dur),
            owner,
        ])
    });
    let widths = [
        Constraint::Length(19),
        Constraint::Min(4),
        Constraint::Min(6),
        Constraint::Length(4),
        Constraint::Length(6),
        Constraint::Length(4),
        Constraint::Length(14),
        Constraint::Length(6),
        Constraint::Length(8),
        Constraint::Min(5),
    ];
    let header = Row::new([
        "id", "tag", "image", "cpus", "mem", "net", "status", "age", "ttl left", "owner",
    ])
    .style(Style::new().add_modifier(Modifier::BOLD));
    let t = Table::new(rows, widths)
        .header(header)
        .column_spacing(1)
        .row_highlight_style(Style::new().add_modifier(Modifier::REVERSED))
        .highlight_symbol("> ");
    let mut state = TableState::default().with_selected(Some(app.selected));
    f.render_stateful_widget(t, table, &mut state);
}

fn popup(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

fn confirm(f: &mut Frame, id: &str) {
    let area = popup(f.area(), 44, 5);
    f.render_widget(Clear, area);
    let text = vec![
        Line::raw(format!(" stop {id}?")),
        Line::raw(""),
        Line::raw(" y stops it, anything else leaves it").dim(),
    ];
    f.render_widget(
        Paragraph::new(text).block(Block::bordered().title(" kill ").red()),
        area,
    );
}

const HELP: &[(&str, &str)] = &[
    ("tab", "launcher / running VMs"),
    ("q, ctrl-c", "quit (in the command field q types a q)"),
    ("?", "this help, any key closes it"),
    ("esc", "clear the message line"),
    ("h", "next host: local, then the ones in hosts.toml"),
    ("", ""),
    ("launcher", ""),
    ("up/down", "pick a field"),
    ("left/right", "change image, net or mode"),
    ("backspace", "delete, ctrl-u clears the field"),
    ("enter", "run the command shown under will run"),
    ("", ""),
    ("running VMs", ""),
    ("up/down", "pick a VM"),
    ("k", "kill it, asks first"),
    (
        "r",
        "refresh now (it does every 2s anyway, 5s on a remote host)",
    ),
];

fn help(f: &mut Frame) {
    let area = popup(f.area(), 64, HELP.len() as u16 + 4);
    f.render_widget(Clear, area);
    let mut lines = vec![Line::raw("")];
    for (k, v) in HELP {
        if v.is_empty() {
            lines.push(Line::raw(format!(" {k}")).bold());
        } else {
            lines.push(Line::raw(format!(" {k:<12} {v}")));
        }
    }
    f.render_widget(
        Paragraph::new(lines).block(Block::bordered().title(" keys ")),
        area,
    );
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::burner::{Burner, parse_ls};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    pub fn render(app: &App, w: u16, h: u16) -> String {
        let mut t = Terminal::new(TestBackend::new(w, h)).unwrap();
        t.draw(|f| draw(f, app)).unwrap();
        let buf = t.backend().buffer();
        let mut out = String::new();
        for y in 0..buf.area.height {
            let line: String = (0..buf.area.width)
                .map(|x| buf[(x, y)].symbol().to_string())
                .collect();
            out.push_str(line.trim_end());
            out.push('\n');
        }
        out
    }

    fn app() -> App {
        let mut a = App::new(
            Burner {
                bin: "burner".into(),
                root: false,
                host: None,
            },
            vec!["alpine".into(), "node".into()],
        );
        a.users.insert(1000, "alice".into());
        a
    }

    const LS: &str = r#"{"max_vms":2,"total_mem":3072,"used_mem":1024,"vms":[
        {"id":"burner-0123456789ab","tag":"ci","img":"alpine","vcpus":2,"mem":512,"net":"web",
         "status":"running","owner":1000,"age":75,"ttl":600,"ttl_left":525},
        {"id":"burner-ba9876543210","tag":"","img":"node","vcpus":1,"mem":512,"net":"none",
         "status":"preparing","owner":null,"age":1,"ttl":3600,"ttl_left":3599}]}"#;

    #[test]
    fn launcher_shows_the_command() {
        let mut a = app();
        a.net = 2;
        a.ttl = "30m".into();
        let s = render(&a, 100, 20);
        println!("{s}");
        assert!(s.contains(" > image    < alpine >"));
        assert!(s.contains("net      < web >"));
        assert!(s.contains("cpus     default"));
        assert!(s.contains(" sudo burner shell --net web --ttl 30m alpine"));
    }

    #[test]
    fn launcher_run_mode() {
        let mut a = app();
        a.mode = Mode::Run;
        a.field = 6;
        a.cmd = "uname -a; exit 3".into();
        let s = render(&a, 100, 20);
        println!("{s}");
        assert!(s.contains(" > command  uname -a; exit 3_"));
        assert!(s.contains(" sudo burner run --img alpine -- 'uname -a; exit 3'"));
    }

    #[test]
    fn running_table() {
        let mut a = app();
        a.screen = Screen::Running;
        a.set_ls(parse_ls(LS));
        let s = render(&a, 100, 12);
        println!("{s}");
        assert!(s.contains("running (2)"));
        assert!(s.contains("2 of 2 VMs, 1024M of 3072M memory"));
        assert!(s.contains("> burner-0123456789ab ci"));
        assert!(s.contains("alice"));
        assert!(s.contains("8m45s"));
        assert!(s.contains("59m59s"));
    }

    #[test]
    fn kill_confirm_and_help() {
        let mut a = app();
        a.screen = Screen::Running;
        a.set_ls(parse_ls(LS));
        a.confirm = Some("burner-0123456789ab".into());
        let s = render(&a, 100, 12);
        println!("{s}");
        assert!(s.contains("stop burner-0123456789ab?"));
        a.confirm = None;
        a.help = true;
        let s = render(&a, 100, 24);
        println!("{s}");
        assert!(s.contains("kill it, asks first"));
    }

    #[test]
    fn errors_show_up() {
        let mut a = app();
        a.screen = Screen::Running;
        a.set_ls(Err("sudo: a password is required".into()));
        assert!(render(&a, 80, 10).contains("sudo: a password is required"));
        let a = App::new(
            Burner {
                bin: "burner".into(),
                root: true,
                host: None,
            },
            vec![],
        );
        let s = render(&a, 80, 20);
        assert!(s.contains("burner images found nothing"));
        assert!(s.contains(" burner shell alpine"));
    }

    #[test]
    fn tiny_terminal_does_not_panic() {
        let mut a = app();
        render(&a, 10, 3);
        a.screen = Screen::Running;
        a.set_ls(parse_ls(LS));
        a.help = true;
        render(&a, 5, 2);
        render(&a, 1, 1);
    }
}
