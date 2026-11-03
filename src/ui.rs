//! The window (iced 0.14). Scans run on a worker thread.

use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use iced::futures::channel::oneshot;
use iced::widget::{Column, button, column, container, row, rule, scrollable, space, text};
use iced::{Background, Color, Element, Font, Length, Task, Theme, border, font};

use crate::report;
use crate::scan::{self, Finding, ScanResult, Severity, Verdict};

pub fn run() -> iced::Result {
    iced::application(App::default, App::update, App::view)
        .title(report::APP_NAME)
        .theme(Theme::Dark)
        .window_size((980.0, 760.0))
        .run()
}

#[derive(Debug, Clone)]
enum Request {
    Computer,
    Folder(PathBuf),
}

#[derive(Debug, Default)]
enum Phase {
    #[default]
    Idle,
    Scanning(String),
    Done(Arc<ScanResult>, String),
    Failed,
}

#[derive(Debug, Default)]
struct App {
    phase: Phase,
    last: Option<Request>,
    copied: u32,
    copied_shown: Option<Clip>,
    /// Id of the scan whose result the window waits for. Older results are dropped.
    scan_id: u32,
    /// The folder dialog is open (it does not block the window).
    picking: bool,
}

/// What a copy button puts on the clipboard.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Clip {
    Report,
    HostsLines,
    Link,
}

#[derive(Debug, Clone)]
enum Message {
    ScanComputer,
    PickFolder,
    FolderPicked(Option<PathBuf>),
    ScanAgain,
    Finished(u32, Option<Arc<ScanResult>>),
    Copy(Clip),
    CopiedDone(u32),
}

/// Runs `job` on its own thread and delivers the result as a message.
fn background<T: Send + 'static>(job: impl FnOnce() -> T + Send + 'static, done: impl Fn(Option<T>) -> Message + Send + 'static) -> Task<Message> {
    let (tx, rx) = oneshot::channel();
    thread::spawn(move || {
        let _ = tx.send(job());
    });
    Task::perform(rx, move |r| done(r.ok()))
}

impl App {
    fn scanning(&self) -> bool {
        matches!(self.phase, Phase::Scanning(_))
    }

    fn busy(&self) -> bool {
        self.scanning() || self.picking
    }

    fn start(&mut self, request: Request) -> Task<Message> {
        let label = match &request {
            Request::Computer => "this computer".to_string(),
            Request::Folder(p) => p.display().to_string(),
        };
        self.phase = Phase::Scanning(label);
        self.last = Some(request.clone());
        self.copied_shown = None;
        self.scan_id += 1;
        let id = self.scan_id;
        background(
            move || match request {
                Request::Computer => scan::scan_computer(),
                Request::Folder(p) => scan::scan_folders(&[p]),
            },
            move |r| Message::Finished(id, r.map(Arc::new)),
        )
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::ScanComputer | Message::PickFolder | Message::ScanAgain if self.busy() => Task::none(),
            Message::ScanComputer => self.start(Request::Computer),
            Message::PickFolder => {
                self.picking = true;
                Task::perform(
                    rfd::AsyncFileDialog::new().set_title("Choose a folder to scan").pick_folder(),
                    |h| Message::FolderPicked(h.map(|h| h.path().to_path_buf())),
                )
            }
            Message::FolderPicked(path) => {
                self.picking = false;
                match path {
                    Some(path) if !self.scanning() => self.start(Request::Folder(path)),
                    _ => Task::none(),
                }
            }
            Message::ScanAgain => match self.last.clone() {
                Some(request) => self.start(request),
                None => Task::none(),
            },
            Message::Finished(id, _) if id != self.scan_id => Task::none(),
            Message::Finished(_, result) => {
                self.phase = match result {
                    Some(r) => {
                        let text = report::render(&r);
                        Phase::Done(r, text)
                    }
                    None => Phase::Failed,
                };
                Task::none()
            }
            Message::Copy(what) => {
                let text = match (&self.phase, what) {
                    (_, Clip::Link) => report::GIST_URL.to_string(),
                    (Phase::Done(_, text), Clip::Report) => text.clone(),
                    (Phase::Done(r, _), Clip::HostsLines) => match &r.hosts {
                        Some(h) => report::block_lines(h).join("\n"),
                        None => return Task::none(),
                    },
                    _ => return Task::none(),
                };
                self.copied += 1;
                self.copied_shown = Some(what);
                let id = self.copied;
                Task::batch([
                    iced::clipboard::write(text),
                    background(move || thread::sleep(Duration::from_secs(2)), move |_| Message::CopiedDone(id)),
                ])
            }
            Message::CopiedDone(id) => {
                if id == self.copied {
                    self.copied_shown = None;
                }
                Task::none()
            }
        }
    }

    fn copy_button(&self, what: Clip, label: &'static str) -> Element<'static, Message> {
        let label = if self.copied_shown == Some(what) { "Copied" } else { label };
        button(text(label)).padding([6, 14]).on_press(Message::Copy(what)).into()
    }

    fn view(&self) -> Element<'_, Message> {
        let busy = self.busy();
        let header = column![
            text(report::APP_NAME).size(28).font(bold()),
            text(report::ABOUT).size(15),
            text(report::READ_ONLY).size(14).color(muted()),
            row![
                button(text("Scan this computer")).padding([8, 16]).on_press_maybe((!busy).then_some(Message::ScanComputer)),
                button(text("Scan a folder..."))
                    .padding([8, 16])
                    .style(button::secondary)
                    .on_press_maybe((!busy).then_some(Message::PickFolder)),
            ]
            .spacing(12),
        ]
        .spacing(10);

        let body: Element<'_, Message> = match &self.phase {
            Phase::Idle => {
                let mut idle = column![text("Choose what to scan. A scan of the whole computer can take a few minutes.")].spacing(6);
                // rfd needs an XDG portal file chooser or zenity, and returns nothing without them.
                if cfg!(all(unix, not(target_os = "macos"))) {
                    idle = idle.push(
                        text("If no folder dialog opens, run nikke-check --cli <folder> in a terminal.").color(muted()),
                    );
                }
                idle.into()
            }
            Phase::Scanning(what) => text(format!("Scanning {what}...")).size(18).into(),
            Phase::Failed => text("The scan stopped with an internal error. Try again, or run nikke-check --cli to see the report in a terminal.")
                .color(severity_color(Severity::Critical))
                .into(),
            Phase::Done(r, _) => self.results(r),
        };

        scrollable(column![header, rule::horizontal(1), body].spacing(18).padding(24).width(Length::Fill)).into()
    }

    fn results<'a>(&self, r: &'a ScanResult) -> Element<'a, Message> {
        let banner = container(
            column![
                text(report::headline(r.verdict)).size(24).font(bold()),
                text(report::summary(r.verdict)).size(15),
            ]
            .spacing(6),
        )
        .padding(16)
        .width(Length::Fill)
        .style(move |_| filled(verdict_color(r.verdict)));

        let actions = row![
            self.copy_button(Clip::Report, "Copy report"),
            button(text("Scan again"))
                .padding([6, 14])
                .style(button::secondary)
                .on_press_maybe((!self.busy()).then_some(Message::ScanAgain)),
        ]
        .spacing(12);

        let mut col = Column::new()
            .spacing(14)
            .push(banner)
            .push(actions)
            .push(text(format!("Checked: {}. Scan of {}.", report::checked_summary(r), r.scope)).color(muted()));

        col = col.push(heading("Findings"));
        if r.groups.is_empty() {
            col = col.push(text("None."));
        }
        for g in &r.groups {
            let label = match &g.path {
                Some(p) => format!("{}: {}", g.label, p.display()),
                None => g.label.clone(),
            };
            col = col.push(text(label).size(16).font(bold()).wrapping(text::Wrapping::WordOrGlyph));
            for f in &g.findings {
                col = col.push(finding_card(f));
            }
        }

        if let Some(h) = &r.hosts {
            let mut p = Column::new()
                .spacing(6)
                .push(text(format!("Hosts file: {}. This is not an infection check: it shows whether the domains are blocked.", h.path.display())));
            if let Some(note) = h.note {
                p = p.push(text(note));
            }
            for (domain, blocked) in &h.domains {
                let color = match blocked {
                    Some(true) => verdict_color(Verdict::NoTraces),
                    Some(false) => severity_color(Severity::Warning),
                    None => muted(),
                };
                p = p.push(
                    row![text(format!("{domain}:")).font(Font::MONOSPACE), text(report::block_state(*blocked)).color(color)]
                        .spacing(8),
                );
            }
            let lines = report::block_lines(h);
            if !lines.is_empty() {
                p = p.push(text(report::BLOCK_LINES_INTRO));
                p = p.push(mono_box(lines.join("\n")));
                p = p.push(self.copy_button(Clip::HostsLines, "Copy these lines"));
            }
            p = p.push(text(report::HOSTS_NOTE).color(muted()));
            p = p.push(text(report::ip_note()).color(muted()));
            col = col.push(heading("Protection")).push(p);
        }

        col = col.push(heading("What to do"));
        for a in report::advice(r.verdict) {
            col = col.push(text(format!("- {a}")));
        }
        col = col.push(heading("Limits of this check"));
        for c in report::CAVEATS {
            col = col.push(text(format!("- {c}")));
        }
        col = col
            .push(
                row![
                    text(format!("Details: {}", report::GIST_URL)).font(Font::MONOSPACE).size(13),
                    self.copy_button(Clip::Link, "Copy link"),
                ]
                .spacing(12)
                .align_y(iced::Alignment::Center),
            )
            .push(text(format!("Scan stats: {}", report::stats_line(r))).size(13).color(muted()));
        col.into()
    }
}

fn finding_card(f: &Finding) -> Element<'_, Message> {
    let color = severity_color(f.severity);
    let badge = container(text(f.severity.tag()).size(12).font(bold()))
        .padding([2, 8])
        .style(move |_| filled(color));
    let mut c = Column::new()
        .spacing(6)
        .push(row![badge, text(&f.title).size(16).font(bold())].spacing(10))
        .push(text(&f.detail));
    if let Some(p) = &f.path {
        c = c.push(text(format!("Path: {}", p.display())).font(Font::MONOSPACE).size(13).wrapping(text::Wrapping::WordOrGlyph));
    }
    if let Some(t) = &f.time {
        c = c.push(text(format!("Time: {t}")).size(13).color(muted()));
    }
    if !f.evidence.is_empty() {
        c = c.push(mono_box(f.evidence.join("\n")));
    }
    container(c)
        .padding(12)
        .width(Length::Fill)
        .style(move |_| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x24, 0x26, 0x2b))),
            border: border::rounded(6).color(color).width(1),
            ..container::Style::default()
        })
        .into()
}

fn mono_box<'a>(content: String) -> Element<'a, Message> {
    container(text(content).font(Font::MONOSPACE).size(13).wrapping(text::Wrapping::WordOrGlyph))
        .padding(8)
        .width(Length::Fill)
        .style(|_| container::Style {
            background: Some(Background::Color(Color::from_rgb8(0x16, 0x17, 0x1a))),
            border: border::rounded(4),
            ..container::Style::default()
        })
        .into()
}

fn heading<'a>(label: &'a str) -> Element<'a, Message> {
    column![space().height(4), text(label).size(20).font(bold())].into()
}

fn bold() -> Font {
    Font { weight: font::Weight::Bold, ..Font::DEFAULT }
}

fn muted() -> Color {
    Color::from_rgb8(0xa0, 0xa4, 0xab)
}

fn filled(color: Color) -> container::Style {
    container::Style {
        text_color: Some(Color::WHITE),
        background: Some(Background::Color(color)),
        border: border::rounded(6),
        ..container::Style::default()
    }
}

fn verdict_color(verdict: Verdict) -> Color {
    match verdict {
        Verdict::Infected => Color::from_rgb8(0xb3, 0x26, 0x1e),
        // White text on it needs 4.5:1 contrast (WCAG AA): #a85500 gives 5.3:1.
        Verdict::Exposed => Color::from_rgb8(0xa8, 0x55, 0x00),
        Verdict::NoTraces => Color::from_rgb8(0x2e, 0x7d, 0x4f),
        Verdict::NotFound => Color::from_rgb8(0x5a, 0x5f, 0x66),
    }
}

fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Critical => verdict_color(Verdict::Infected),
        Severity::Warning => verdict_color(Verdict::Exposed),
        Severity::Info => Color::from_rgb8(0x3d, 0x6f, 0xb0),
    }
}
