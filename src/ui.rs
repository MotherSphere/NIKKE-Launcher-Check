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
    copied_shown: bool,
}

#[derive(Debug, Clone)]
enum Message {
    ScanComputer,
    PickFolder,
    FolderPicked(Option<PathBuf>),
    ScanAgain,
    Finished(Option<Arc<ScanResult>>),
    CopyReport,
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

    fn start(&mut self, request: Request) -> Task<Message> {
        let label = match &request {
            Request::Computer => "this computer".to_string(),
            Request::Folder(p) => p.display().to_string(),
        };
        self.phase = Phase::Scanning(label);
        self.last = Some(request.clone());
        self.copied_shown = false;
        background(
            move || match request {
                Request::Computer => scan::scan_computer(),
                Request::Folder(p) => scan::scan_folders(&[p]),
            },
            |r| Message::Finished(r.map(Arc::new)),
        )
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::ScanComputer => self.start(Request::Computer),
            Message::PickFolder => Task::perform(
                rfd::AsyncFileDialog::new().set_title("Choose a folder to scan").pick_folder(),
                |h| Message::FolderPicked(h.map(|h| h.path().to_path_buf())),
            ),
            Message::FolderPicked(Some(path)) => self.start(Request::Folder(path)),
            Message::FolderPicked(None) => Task::none(),
            Message::ScanAgain => match self.last.clone() {
                Some(request) => self.start(request),
                None => Task::none(),
            },
            Message::Finished(result) => {
                self.phase = match result {
                    Some(r) => {
                        let text = report::render(&r);
                        Phase::Done(r, text)
                    }
                    None => Phase::Failed,
                };
                Task::none()
            }
            Message::CopyReport => {
                let Phase::Done(_, text) = &self.phase else {
                    return Task::none();
                };
                self.copied += 1;
                self.copied_shown = true;
                let id = self.copied;
                Task::batch([
                    iced::clipboard::write(text.clone()),
                    background(move || thread::sleep(Duration::from_secs(2)), move |_| Message::CopiedDone(id)),
                ])
            }
            Message::CopiedDone(id) => {
                if id == self.copied {
                    self.copied_shown = false;
                }
                Task::none()
            }
        }
    }

    fn view(&self) -> Element<'_, Message> {
        let busy = self.scanning();
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
            Phase::Idle => text("Choose what to scan. A scan of the whole computer can take a few minutes.").into(),
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
            button(text(if self.copied_shown { "Copied" } else { "Copy report" })).padding([6, 14]).on_press(Message::CopyReport),
            button(text("Scan again")).padding([6, 14]).style(button::secondary).on_press(Message::ScanAgain),
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
            if !h.readable {
                p = p.push(text("The hosts file could not be read."));
            }
            for (domain, blocked) in &h.domains {
                let (state, color) = if *blocked {
                    ("blocked", verdict_color(Verdict::NoTraces))
                } else {
                    ("not blocked", severity_color(Severity::Warning))
                };
                p = p.push(row![text(format!("{domain}:")).font(Font::MONOSPACE), text(state).color(color)].spacing(8));
            }
            if h.domains.iter().any(|(_, blocked)| !blocked) {
                p = p.push(text("To block them, add these lines to the hosts file:"));
                p = p.push(mono_box(report::block_lines().join("\n")));
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
            .push(text(format!("Details: {}", report::GIST_URL)).font(Font::MONOSPACE).size(13))
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
        Verdict::Exposed => Color::from_rgb8(0xc7, 0x6a, 0x10),
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
