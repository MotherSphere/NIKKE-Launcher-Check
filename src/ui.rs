//! The window (iced 0.14). Scans run on a worker thread and report through a
//! shared `Progress`, which the scanning screen reads on each frame. The result
//! has three tabs: What happened, What to do and Details. The language menu at
//! the bottom left redraws every text, the result included, without a new scan.

use std::cmp::Ordering;
use std::collections::HashSet;
use std::f32::consts::{PI, TAU};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering::Relaxed;
use std::thread;
use std::time::{Duration, Instant};

use iced::futures::channel::oneshot;
use iced::theme::Palette;
use iced::widget::{
    Column, button, canvas, center, checkbox, column, container, grid, image, opaque, pick_list, responsive, row, scrollable, space,
    stack, text, toggler,
};
use iced::{
    Alignment, Background, Color, Element, Fill, Font, Length, Point, Radians, Rectangle, Renderer, Shrink, Size,
    Subscription, Task, Theme, border, font, mouse, window,
};

use crate::exposure::Exposure;
use crate::guide::{self, Action, Answer, Part, Section, Step, Tone};
use crate::i18n::{Lang, Text, msg, tr};
use crate::locate::{Progress, Stage};
use crate::open::{self, Target};
use crate::redact::Secrets;
use crate::report::{self, thousands};
use crate::scan::{self, Finding, FindingKind, Group, ScanResult, Severity, Verdict};

pub fn run(folder: Option<PathBuf>, lang: Lang) -> iced::Result {
    iced::application(move || App::boot(folder.clone(), lang), App::update, App::view)
        .title(report::APP_NAME)
        .theme(App::theme)
        .subscription(App::subscription)
        .window(window::Settings {
            size: Size::new(1040.0, 780.0),
            min_size: Some(Size::new(720.0, 560.0)),
            icon: window::icon::from_rgba(icon_rgba(), ICON_PX, ICON_PX).ok(),
            // The window asks first when the steps of an infected result were not opened.
            exit_on_close_request: false,
            ..window::Settings::default()
        })
        .run()
}

#[derive(Debug, Clone)]
enum Request {
    /// True for the full scan.
    Computer(bool),
    Folder(PathBuf),
}

#[derive(Debug)]
struct Scan {
    request: Request,
    progress: Arc<Progress>,
    started: Instant,
    /// Time of the last frame, for the clock and the ring.
    now: Instant,
}

/// A finished scan and what the result tabs show of it. `report` and `steps`
/// are in the window's language and are built again when it changes.
#[derive(Debug)]
struct Done {
    result: Arc<ScanResult>,
    report: String,
    steps: Vec<Step>,
    secrets: Secrets,
}

impl Done {
    fn new(result: Arc<ScanResult>, lang: Lang) -> Self {
        Done { report: report::render(&result, lang), steps: guide::steps(&result, lang), secrets: Secrets::of(&result), result }
    }
}

#[derive(Debug, Default)]
enum Phase {
    #[default]
    Idle,
    Scanning(Scan),
    Done(Box<Done>),
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Tab {
    #[default]
    Happened,
    Todo,
    Details,
}

impl Tab {
    const ALL: [Tab; 3] = [Tab::Happened, Tab::Todo, Tab::Details];

    fn label(self, lang: Lang) -> &'static str {
        tr(
            lang,
            match self {
                Tab::Happened => "ui.tab.happened",
                Tab::Todo => "ui.tab.todo",
                Tab::Details => "ui.tab.details",
            },
        )
    }
}

#[derive(Debug)]
struct App {
    phase: Phase,
    last: Option<Request>,
    copied: u32,
    copied_shown: Option<Clip>,
    /// Id of the scan whose result the window waits for. Older results are dropped.
    scan_id: u32,
    /// The folder dialog is open (it does not block the window).
    picking: bool,
    /// The save dialog is open, or the report is being written.
    saving: bool,
    /// One line shown above the home or results screen.
    notice: Option<Text>,
    /// The language of every text. Not saved: the tool writes nothing but a report.
    lang: Lang,
    theme: Theme,
    tab: Tab,
    /// "Hide my info": Copy report and Save report replace personal values.
    hide: bool,
    /// Steps marked done, by index. Window state only.
    checked: HashSet<usize>,
    /// Findings with their evidence shown, by group and finding index.
    evidence: HashSet<(usize, usize)>,
    /// The Information section of Details is open.
    info_open: bool,
    /// The What to do tab was shown for this result.
    todo_seen: bool,
    /// The window was asked to close before the steps were seen: the warning shows.
    close_warning: bool,
}

/// What a copy button puts on the clipboard.
#[derive(Debug, Clone, PartialEq)]
enum Clip {
    Report,
    Text(String),
}

#[derive(Debug, Clone)]
enum Message {
    /// True for the full scan.
    ScanComputer(bool),
    PickFolder,
    FolderPicked(Option<PathBuf>),
    Dropped(PathBuf),
    ScanAgain,
    NewScan,
    Stop,
    Tick(Instant),
    Finished(u32, Option<Arc<ScanResult>>),
    Copy(Clip),
    CopiedDone(u32),
    Tab(Tab),
    StepDone(usize, bool),
    Evidence(usize, usize),
    ToggleInfo,
    Hide(bool),
    SaveReport,
    SaveTo(Option<PathBuf>),
    Saved(Option<Result<PathBuf, String>>),
    Open(Target),
    Opened(Option<Result<(), Text>>),
    Lang(Lang),
    CloseRequested,
    Exit,
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
    fn boot(folder: Option<PathBuf>, lang: Lang) -> (Self, Task<Message>) {
        let palette = Palette {
            background: BG,
            text: TEXT,
            primary: INFO,
            success: NO_TRACES,
            warning: EXPOSED,
            danger: INFECTED,
        };
        let mut app = App {
            phase: Phase::Idle,
            last: None,
            copied: 0,
            copied_shown: None,
            scan_id: 0,
            picking: false,
            saving: false,
            notice: None,
            lang,
            theme: Theme::custom(report::APP_NAME, palette),
            tab: Tab::default(),
            hide: false,
            checked: HashSet::new(),
            evidence: HashSet::new(),
            info_open: false,
            todo_seen: false,
            close_warning: false,
        };
        // Same path as a drop on the window, so a file gets the "only folders" notice.
        let task = match folder {
            Some(path) => app.update(Message::Dropped(path)),
            None => Task::none(),
        };
        (app, task)
    }

    fn theme(&self) -> Theme {
        self.theme.clone()
    }

    fn subscription(&self) -> Subscription<Message> {
        let drops = iced::event::listen_with(|event, _, _| match event {
            iced::Event::Window(window::Event::FileDropped(path)) => Some(Message::Dropped(path)),
            _ => None,
        });
        let close = window::close_requests().map(|_| Message::CloseRequested);
        if self.scanning() {
            // Frames only while scanning: an idle window does not redraw.
            Subscription::batch([drops, close, window::frames().map(Message::Tick)])
        } else {
            Subscription::batch([drops, close])
        }
    }

    fn scanning(&self) -> bool {
        matches!(self.phase, Phase::Scanning(_))
    }

    fn busy(&self) -> bool {
        self.scanning() || self.picking
    }

    /// An infected or exposed result whose steps were never shown.
    fn steps_unseen(&self) -> bool {
        !self.todo_seen && matches!(&self.phase, Phase::Done(d) if matches!(d.result.verdict, Verdict::Infected | Verdict::Exposed))
    }

    fn start(&mut self, request: Request) -> Task<Message> {
        let progress = Arc::new(Progress::default());
        let now = Instant::now();
        self.phase = Phase::Scanning(Scan { request: request.clone(), progress: progress.clone(), started: now, now });
        self.last = Some(request.clone());
        self.copied_shown = None;
        self.notice = None;
        self.scan_id += 1;
        let id = self.scan_id;
        background(
            move || match request {
                Request::Computer(full) => scan::scan_computer(full, &progress),
                Request::Folder(p) => scan::scan_folders(&[p], &progress),
            },
            move |r| Message::Finished(id, r.map(Arc::new)),
        )
    }

    /// The report as Copy report and Save report give it.
    fn report_text(&self) -> Option<String> {
        match &self.phase {
            Phase::Done(d) if self.hide => Some(d.secrets.apply(&d.report)),
            Phase::Done(d) => Some(d.report.clone()),
            _ => None,
        }
    }

    fn update(&mut self, message: Message) -> Task<Message> {
        match message {
            Message::ScanComputer(_) | Message::PickFolder | Message::ScanAgain | Message::Dropped(_) if self.busy() => {
                Task::none()
            }
            Message::ScanComputer(full) => self.start(Request::Computer(full)),
            Message::PickFolder => {
                self.picking = true;
                Task::perform(
                    rfd::AsyncFileDialog::new().set_title(tr(self.lang, "ui.dialog.pick_folder")).pick_folder(),
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
            Message::Dropped(path) if path.is_dir() => self.start(Request::Folder(path)),
            Message::Dropped(_) => {
                self.notice = Some(msg("ui.notice.only_folders"));
                Task::none()
            }
            Message::ScanAgain => match self.last.clone() {
                Some(request) => self.start(request),
                None => Task::none(),
            },
            Message::NewScan => {
                if !self.scanning() {
                    self.phase = Phase::Idle;
                    self.notice = None;
                }
                Task::none()
            }
            Message::Stop => {
                if let Phase::Scanning(scan) = &self.phase {
                    scan.progress.cancel();
                    // The cancelled scan still delivers a result; the new id drops it.
                    self.scan_id += 1;
                    self.phase = Phase::Idle;
                    self.notice = Some(msg("ui.notice.stopped"));
                }
                Task::none()
            }
            Message::Tick(now) => {
                if let Phase::Scanning(scan) = &mut self.phase {
                    scan.now = now;
                }
                Task::none()
            }
            Message::Finished(id, _) if id != self.scan_id => Task::none(),
            Message::Finished(_, result) => {
                self.phase = match result {
                    Some(r) => Phase::Done(Box::new(Done::new(r, self.lang))),
                    None => Phase::Failed,
                };
                // The launcher is running or a program has the DLL loaded: the steps come first.
                self.tab = match &self.phase {
                    Phase::Done(d) if guide::act_now(&d.result) => Tab::Todo,
                    _ => Tab::default(),
                };
                self.checked.clear();
                self.evidence.clear();
                self.info_open = false;
                self.todo_seen = self.tab == Tab::Todo;
                self.close_warning = false;
                Task::none()
            }
            Message::Copy(what) => {
                let text = match &what {
                    Clip::Report => match self.report_text() {
                        Some(text) => text,
                        None => return Task::none(),
                    },
                    Clip::Text(text) => text.clone(),
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
            Message::Tab(tab) => {
                self.tab = tab;
                if tab == Tab::Todo {
                    self.todo_seen = true;
                    self.close_warning = false;
                }
                Task::none()
            }
            Message::StepDone(i, done) => {
                if done {
                    self.checked.insert(i);
                } else {
                    self.checked.remove(&i);
                }
                Task::none()
            }
            Message::Evidence(g, f) => {
                if !self.evidence.remove(&(g, f)) {
                    self.evidence.insert((g, f));
                }
                Task::none()
            }
            Message::ToggleInfo => {
                self.info_open = !self.info_open;
                Task::none()
            }
            Message::Hide(hide) => {
                self.hide = hide;
                Task::none()
            }
            Message::SaveReport => {
                let Phase::Done(d) = &self.phase else {
                    return Task::none();
                };
                if self.saving {
                    return Task::none();
                }
                self.saving = true;
                // "2026-11-03 23:05:42 UTC" gives the date of the file name.
                let date = d.result.started.get(..10).unwrap_or("scan");
                Task::perform(
                    rfd::AsyncFileDialog::new()
                        .set_title(tr(self.lang, "ui.dialog.save"))
                        .set_file_name(format!("nikke-check-report-{date}.txt"))
                        .add_filter(tr(self.lang, "ui.dialog.text_files"), &["txt"])
                        .save_file(),
                    |h| Message::SaveTo(h.map(|h| h.path().to_path_buf())),
                )
            }
            Message::SaveTo(path) => match (path, self.report_text()) {
                // The only file this program writes: the one the user picked in the save dialog.
                (Some(path), Some(text)) => background(move || std::fs::write(&path, text).map(|_| path).map_err(|e| e.to_string()), Message::Saved),
                _ => {
                    self.saving = false;
                    Task::none()
                }
            },
            Message::Saved(result) => {
                self.saving = false;
                self.notice = Some(match result {
                    Some(Ok(path)) => msg("ui.notice.saved").arg("path", path.display().to_string()),
                    Some(Err(err)) => msg("ui.notice.save_failed").arg("error", err),
                    None => msg("ui.notice.save_failed_plain"),
                });
                Task::none()
            }
            Message::Open(target) => background(move || open::open(&target), Message::Opened),
            Message::Opened(result) => {
                match result {
                    Some(Ok(())) => {}
                    Some(Err(err)) => self.notice = Some(msg("ui.notice.open_failed").arg("error", err)),
                    None => self.notice = Some(msg("ui.notice.open_failed_plain")),
                }
                Task::none()
            }
            // The Done marks, the open tab and the shown details stay: the steps keep their order.
            Message::Lang(lang) => {
                self.lang = lang;
                if let Phase::Done(d) = &mut self.phase {
                    **d = Done::new(d.result.clone(), lang);
                }
                Task::none()
            }
            Message::CloseRequested if self.steps_unseen() => {
                self.close_warning = true;
                Task::none()
            }
            Message::CloseRequested | Message::Exit => iced::exit(),
        }
    }

    fn t(&self, key: &'static str) -> &'static str {
        tr(self.lang, key)
    }

    fn copy_button(&self, what: Clip, label: &str, primary: bool) -> Element<'static, Message> {
        let label = if self.copied_shown.as_ref() == Some(&what) { self.t("ui.copied") } else { label };
        action(label.to_string(), Some(Message::Copy(what)), primary)
    }

    fn view(&self) -> Element<'_, Message> {
        let body = match &self.phase {
            Phase::Idle => self.home(),
            Phase::Scanning(scan) => scanning(scan, self.lang),
            Phase::Done(d) => self.results(d),
            Phase::Failed => self.failed(),
        };
        let mut page = Column::new().spacing(20).width(Fill).max_width(1080);
        if let Some(notice) = self.notice.as_ref().filter(|_| !self.scanning()) {
            page = page.push(
                container(text(notice.render(self.lang)).color(INFO_TEXT).wrapping(text::Wrapping::WordOrGlyph))
                    .padding([10, 16])
                    .width(Fill)
                    .style(|_| surface(CARD, 8).border(border::rounded(8).color(INFO).width(1))),
            );
        }
        page = page.push(body);
        let window = column![top_bar(self.lang), scrollable(container(page).padding(24).center_x(Fill)).height(Fill), bottom_bar(self.lang)];
        if !self.close_warning {
            return window.into();
        }
        let dialog = container(
            column![
                text(self.t("ui.close.title")).size(22).font(bold()).wrapping(text::Wrapping::WordOrGlyph),
                text(self.t("ui.close.text")).wrapping(text::Wrapping::WordOrGlyph),
                row![
                    action(self.t("ui.button.see_todo"), Some(Message::Tab(Tab::Todo)), true),
                    action(self.t("ui.close.anyway"), Some(Message::Exit), false),
                ]
                .spacing(12)
                .wrap()
                .vertical_spacing(12),
            ]
            .spacing(14),
        )
        .padding(24)
        .max_width(520)
        .style(|_| surface(CARD, 12).border(border::rounded(12).color(LINE).width(1)));
        let shade = center(opaque(dialog)).padding(24).style(|_| surface(Color { a: 0.75, ..Color::BLACK }, 0));
        stack![window, opaque(shade)].into()
    }

    fn home(&self) -> Element<'_, Message> {
        let idle = !self.busy();
        let hero = card(
            row![
                glyph(Glyph::Shield, 88.0),
                column![text(self.t("ui.home.title")).size(26).font(bold()), text(self.t("report.about")).size(15)]
                    .spacing(8)
                    .width(Fill),
            ]
            .spacing(24)
            .align_y(Alignment::Center),
        )
        .padding(24);

        let mut folder = column![
            text(self.t("ui.home.folder")).size(20).font(bold()),
            text(self.t("ui.home.folder_text")),
            action(self.t("ui.button.scan_folder"), idle.then_some(Message::PickFolder), false),
        ]
        .spacing(10);
        if drop_works() {
            folder = folder.push(text(self.t("ui.home.drop")).size(13).color(MUTED));
        }
        // rfd needs an XDG portal file chooser or zenity, and returns nothing without them.
        if cfg!(all(unix, not(target_os = "macos"))) {
            folder = folder.push(text(self.t("ui.home.no_dialog")).size(13).color(MUTED));
        }
        let options = grid![
            card(
                column![
                    text(self.t("ui.home.computer")).size(20).font(bold()),
                    text(self.t(QUICK_SCAN)),
                    action(self.t("ui.button.scan_computer"), idle.then_some(Message::ScanComputer(false)), true),
                    text(self.t("ui.home.full")).size(13).color(MUTED),
                    action(self.t("ui.button.full_scan"), idle.then_some(Message::ScanComputer(true)), false),
                ]
                .spacing(10)
            ),
            card(folder),
        ]
        // Two columns up to the 1080 px page width, one below 560 px.
        .fluid(560)
        .spacing(16)
        .height(Shrink);

        column![helper(self.t("ui.home.hint")), hero, options].spacing(16).into()
    }

    fn failed(&self) -> Element<'_, Message> {
        card(
            column![
                text(if cfg!(windows) {
                    msg("ui.failed.windows").arg("command", guide::powershell_cli("")).render(self.lang)
                } else {
                    self.t("ui.failed.other").into()
                })
                .color(CRITICAL_TEXT),
                row![
                    action(self.t("ui.button.scan_again"), (!self.busy()).then_some(Message::ScanAgain), true),
                    action(self.t("ui.button.new_scan"), Some(Message::NewScan), false),
                ]
                .spacing(12),
            ]
            .spacing(14),
        )
        .into()
    }

    fn results<'a>(&'a self, d: &'a Done) -> Element<'a, Message> {
        let idle = !self.busy();
        let actions = row![
            self.copy_button(Clip::Report, self.t("ui.button.copy_report"), true),
            action(self.t("ui.button.save_report"), (!self.saving).then_some(Message::SaveReport), false),
            toggler(self.hide).label(self.t("ui.hide_info")).on_toggle(Message::Hide).style(switch_style),
            action(self.t("ui.button.scan_again"), idle.then_some(Message::ScanAgain), false),
            action(self.t("ui.button.new_scan"), idle.then_some(Message::NewScan), false),
        ]
        .spacing(12)
        .align_y(Alignment::Center)
        .wrap()
        .vertical_spacing(12);
        let tabs = row(Tab::ALL.map(|t| {
            let label = match t {
                Tab::Todo => msg("ui.details.section_count").arg("title", t.label(self.lang)).arg("n", d.steps.len().to_string()).render(self.lang),
                _ => t.label(self.lang).to_string(),
            };
            tab_button(t, label, t == self.tab)
        }))
        .spacing(8)
        .wrap()
        .vertical_spacing(8);
        let hidden = self.hide.then(|| text(self.t("ui.hide_info_note")).size(13).color(MUTED));
        let body = match self.tab {
            Tab::Happened => self.happened(d),
            Tab::Todo => self.todo(&d.steps),
            Tab::Details => self.details(&d.result),
        };
        column![actions].push(hidden).push(tabs).push(body).spacing(16).into()
    }

    fn happened<'a>(&'a self, d: &'a Done) -> Element<'a, Message> {
        let r = &d.result;
        let color = verdict_color(r.verdict);
        let hero = container(
            row![
                glyph(Glyph::Verdict(r.verdict), 96.0),
                column![
                    text(report::headline(r.verdict, self.lang)).size(30).font(bold()),
                    text(report::summary(r.verdict, self.lang)).size(16),
                ]
                .spacing(8)
                .width(Fill),
            ]
            .spacing(24)
            .align_y(Alignment::Center),
        )
        .padding(24)
        .width(Fill)
        .style(move |_| container::Style { border: border::rounded(12), ..filled(color) });

        // Right under the verdict, in its color: the steps are what to do next.
        let see = msg("ui.button.see_todo_count").arg("n", d.steps.len().to_string()).render(self.lang);
        let see = button(text(see).size(20).font(bold()).width(Fill).align_x(Alignment::Center).wrapping(text::Wrapping::WordOrGlyph))
            .padding([14, 24])
            .width(Fill)
            .style(move |_, status| {
                let pressed = matches!(status, button::Status::Hovered | button::Status::Pressed);
                let shade = |c: f32| if pressed { c * 0.82 } else { c };
                button::Style {
                    background: Some(Background::Color(Color { r: shade(color.r), g: shade(color.g), b: shade(color.b), a: 1.0 })),
                    text_color: Color::WHITE,
                    border: border::rounded(10),
                    ..button::Style::default()
                }
            })
            .on_press(Message::Tab(Tab::Todo));
        let mut col = Column::new().spacing(14).push(hero).push(see);
        for a in guide::answers(r, self.lang) {
            col = col.push(answer_card(a, self.lang));
        }
        if !r.builds.is_empty() {
            let mut c = Column::new().spacing(6).push(text(self.t("ui.happened.payload_build")).size(16).font(bold()));
            for b in &r.builds {
                c = c.push(bullet(guide::build_line(b, self.lang)));
            }
            col = col.push(card(c));
        }
        col.into()
    }

    fn todo<'a>(&'a self, steps: &'a [Step]) -> Element<'a, Message> {
        let mut col = Column::new().spacing(14).push(helper(self.t("ui.todo.hint"))).push(text(self.t("ui.todo.note")).color(MUTED));
        for (i, s) in steps.iter().enumerate() {
            col = col.push(self.step_card(i, s));
        }
        col.into()
    }

    fn step_card<'a>(&'a self, i: usize, s: &'a Step) -> Element<'a, Message> {
        let done = self.checked.contains(&i);
        let number = container(text((i + 1).to_string()).size(14).font(bold()))
            .padding([2, 10])
            .style(move |_| filled(if done { NO_TRACES } else { INFO }));
        let head = row![
            number,
            text(&s.title).size(17).font(bold()).color(if done { MUTED } else { TEXT }).width(Fill),
            checkbox(done).label(self.t("ui.done")).on_toggle(move |b| Message::StepDone(i, b)).style(check_style),
        ]
        .spacing(12)
        .align_y(Alignment::Center);
        let mut c = Column::new().spacing(8).push(head);
        for part in &s.parts {
            c = c.push(match part {
                Part::Text(t) => text(t).wrapping(text::Wrapping::WordOrGlyph).into(),
                Part::Item(t) => bullet(t.as_str()),
                Part::Code(t) => mono_box(t.clone()),
                Part::Actions(actions) => {
                    row(actions.iter().map(|a| self.action_button(a))).spacing(10).wrap().vertical_spacing(10).into()
                }
            });
        }
        card(c).into()
    }

    fn action_button(&self, a: &Action) -> Element<'static, Message> {
        let open = |key, target| action(self.t(key), Some(Message::Open(target)), false);
        match a {
            Action::Reveal(path) => open("ui.button.open_folder", Target::Reveal(path.clone())),
            Action::Copy(label, text) => self.copy_button(Clip::Text(text.clone()), label, false),
            Action::TaskManager => open("ui.button.task_manager", Target::TaskManager),
            Action::RegistryEditor => open("ui.button.registry_editor", Target::RegistryEditor),
            Action::SaveReport => action(self.t("ui.button.save_report"), (!self.saving).then_some(Message::SaveReport), true),
            Action::CopyReport => self.copy_button(Clip::Report, self.t("ui.button.copy_report"), false),
            Action::ScanFolder => action(self.t("ui.button.scan_folder"), (!self.busy()).then_some(Message::PickFolder), true),
            Action::FullScan => action(self.t("ui.button.full_scan"), (!self.busy()).then_some(Message::ScanComputer(true)), false),
        }
    }

    fn details<'a>(&'a self, r: &'a ScanResult) -> Element<'a, Message> {
        let mut counts = [0usize; 3];
        for f in r.groups.iter().flat_map(|g| &g.findings) {
            counts[f.severity as usize] += 1;
        }
        let [info, warnings, critical] = counts;
        let lang = self.lang;
        let tiles = grid![
            tile(self.t("ui.tile.critical"), critical.to_string(), if critical > 0 { CRITICAL_TEXT } else { TEXT }),
            tile(self.t("ui.tile.warnings"), warnings.to_string(), if warnings > 0 { WARNING_TEXT } else { TEXT }),
            tile(self.t("ui.tile.info"), info.to_string(), TEXT),
            tile(self.t("ui.tile.items"), thousands(r.stats.entries), TEXT),
            tile(self.t("ui.tile.duration"), duration(r.seconds), TEXT),
        ]
        .fluid(220)
        .spacing(12)
        .height(Shrink);

        let checked = msg("ui.details.checked").arg("summary", report::checked_summary(r, lang)).arg("scope", report::scope(r, lang));
        let mut col = Column::new()
            .spacing(14)
            .push(tiles)
            .push(text(checked.render(lang)).color(MUTED).wrapping(text::Wrapping::WordOrGlyph));
        if r.groups.is_empty() {
            col = col.push(text(self.t("report.no_findings")));
        }
        for s in Section::ALL {
            if s == Section::Info
                && let Some(e) = &r.exposure
            {
                col = col.push(heading(self.t("exposure.title"))).push(exposure_view(e, guide::home_note(r, lang), lang));
            }
            let found = report::section(r, s);
            if found.is_empty() {
                continue;
            }
            if s == Section::Info {
                let label = self.t(if self.info_open { "ui.button.hide" } else { "ui.button.show" });
                let title = msg("ui.details.section_count").arg("title", s.title(lang)).arg("n", found.len().to_string());
                col = col.push(
                    row![text(title.render(lang)).size(20).font(bold()), action(label, Some(Message::ToggleInfo), false)]
                    .spacing(12)
                    .align_y(Alignment::Center),
                );
                if !self.info_open {
                    continue;
                }
            } else {
                col = col.push(heading(s.title(lang)));
            }
            for (gi, fi, g, f) in found {
                col = col.push(self.finding_card(gi, fi, g, f));
            }
        }

        if let Some(h) = &r.hosts {
            let hosts = msg("ui.details.hosts").arg("path", h.path.display().to_string());
            let mut p = Column::new().spacing(8).push(text(hosts.render(lang)).wrapping(text::Wrapping::WordOrGlyph));
            if let Some(note) = &h.note {
                p = p.push(text(note.render(lang)));
            }
            for (domain, blocked) in &h.domains {
                let color = match blocked {
                    Some(true) => OK_TEXT,
                    Some(false) => WARNING_TEXT,
                    None => MUTED,
                };
                p = p.push(
                    row![text(format!("{domain}:")).font(Font::MONOSPACE), text(report::block_state(*blocked, lang)).color(color)]
                        .spacing(8),
                );
            }
            let lines = report::block_lines(h);
            if !lines.is_empty() {
                p = p.push(text(self.t("hosts.block_lines_intro")));
                p = p.push(mono_box(lines.join("\n")));
                p = p.push(self.copy_button(Clip::Text(lines.join("\n")), self.t("common.copy_lines"), false));
            }
            p = p.push(text(self.t("hosts.note")).color(MUTED));
            p = p.push(text(self.t("hosts.ip_note")).color(MUTED));
            col = col.push(heading(self.t("ui.details.protection"))).push(card(p));
        }

        col = col.push(heading(self.t("ui.details.limits")));
        for c in report::caveats(lang) {
            col = col.push(bullet(c));
        }
        let mut places = Column::new().spacing(4);
        for t in &r.targets {
            places = places.push(
                text(format!("[{}] {}", t.kind.label(lang), t.path.display()))
                    .font(Font::MONOSPACE)
                    .size(13)
                    .wrapping(text::Wrapping::WordOrGlyph),
            );
        }
        col.push(
            row![
                text(msg("report.write_up").arg("url", report::GIST_URL).render(lang))
                    .font(Font::MONOSPACE)
                    .size(13)
                    .width(Fill)
                    .wrapping(text::Wrapping::WordOrGlyph),
                self.copy_button(Clip::Text(report::GIST_URL.into()), self.t("ui.button.copy_link"), false),
                action(self.t("ui.button.open_link"), Some(Message::Open(Target::Link(report::GIST_URL.into()))), false),
            ]
            .spacing(12)
            .align_y(Alignment::Center),
        )
        .push(heading(self.t("ui.details.locations")))
        .push(places)
        .push(text(msg("report.scan_stats").arg("stats", report::stats_line(r, lang)).render(lang)).size(13).color(MUTED))
        .into()
    }

    fn finding_card<'a>(&'a self, gi: usize, fi: usize, g: &'a Group, f: &'a Finding) -> Element<'a, Message> {
        let lang = self.lang;
        let color = severity_color(f.severity);
        let badge = container(text(f.severity.tag(lang)).size(12).font(bold()))
            .padding([2, 8])
            .style(move |_| filled(color));
        let meaning = msg("details.meaning").arg("text", guide::meaning(f.kind, lang));
        let found_in = msg("details.found_in").arg("location", report::location(g, lang));
        let mut c = Column::new()
            .spacing(6)
            .push(row![badge, text(f.title.render(lang)).size(16).font(bold()).width(Fill)].spacing(10))
            .push(text(f.detail.render(lang)).wrapping(text::Wrapping::WordOrGlyph))
            .push(text(meaning.render(lang)).color(INFO_TEXT))
            .push(text(found_in.render(lang)).size(13).color(MUTED).wrapping(text::Wrapping::WordOrGlyph));
        if let Some(p) = &f.path {
            let path = msg("details.path").arg("path", p.display().to_string());
            c = c.push(text(path.render(lang)).font(Font::MONOSPACE).size(13).wrapping(text::Wrapping::WordOrGlyph));
        }
        if let Some(t) = &f.time {
            c = c.push(text(msg("details.time").arg("time", t.clone()).render(lang)).size(13).color(MUTED));
        }
        if let Some(copy) = &f.copy_text {
            c = c.push(mono_box(msg("details.copy").arg("label", report::copy_label(f, lang)).arg("text", copy.as_str()).render(lang)));
        }
        let mut buttons: Vec<Element<'a, Message>> = Vec::new();
        if let Some(p) = &f.open_path {
            buttons.push(action(self.t("ui.button.open_folder"), Some(Message::Open(Target::Reveal(p.clone()))), false));
        }
        if let Some(p) = &f.path {
            buttons.push(self.copy_button(Clip::Text(p.display().to_string()), self.t("ui.button.copy_path"), false));
        }
        if let Some(copy) = &f.copy_text {
            let label = if matches!(f.kind, FindingKind::RegistryKey | FindingKind::RegistryLeftover) { "common.copy_key_path" } else { "common.copy" };
            buttons.push(self.copy_button(Clip::Text(copy.clone()), self.t(label), false));
        }
        let shown = self.evidence.contains(&(gi, fi));
        if !f.evidence.is_empty() {
            let label = self.t(if shown { "ui.button.hide_details" } else { "ui.button.show_details" });
            buttons.push(action(label, Some(Message::Evidence(gi, fi)), false));
        }
        if !buttons.is_empty() {
            c = c.push(row(buttons).spacing(10).wrap().vertical_spacing(10));
        }
        if shown {
            c = c.push(mono_box(f.evidence_lines(lang).join("\n")));
        }
        container(c)
            .padding(12)
            .width(Length::Fill)
            .style(move |_| surface(CARD, 6).border(border::rounded(6).color(color).width(1)))
            .into()
    }
}

/// One of the four answers of the What happened tab.
fn answer_card(a: Answer, lang: Lang) -> Element<'static, Message> {
    let color = match a.tone {
        Tone::Bad => CRITICAL_TEXT,
        Tone::Unsure => WARNING_TEXT,
        Tone::Good => OK_TEXT,
    };
    let mut c = Column::new()
        .spacing(6)
        .push(text(a.question).size(16).font(bold()))
        .push(text(a.reply).size(24).font(bold()).color(color));
    for line in a.lines {
        c = c.push(bullet(line));
    }
    if !a.runs.is_empty() {
        c = c.push(text(tr(lang, "ui.happened.agent_runs")).size(13).color(MUTED));
        c = c.push(mono_box(a.runs.join("\n")));
    }
    card(c).into()
}

/// What the agent's commands could read, from the existence checks.
fn exposure_view(e: &Exposure, note: Option<&'static str>, lang: Lang) -> Element<'static, Message> {
    let mut c = Column::new().spacing(8).push(text(tr(lang, "exposure.note")).color(MUTED)).push(note.map(|n| text(n).color(MUTED)));
    for (title, items) in guide::exposure_lists(e, lang) {
        c = c.push(text(title).size(16).font(bold()));
        if items.is_empty() {
            c = c.push(text(tr(lang, "ui.details.none_found")).color(MUTED));
        }
        for (what, path) in items {
            c = c.push(
                row![
                    column![
                        text(what),
                        text(path.display().to_string()).font(Font::MONOSPACE).size(13).wrapping(text::Wrapping::WordOrGlyph),
                    ]
                    .spacing(2)
                    .width(Fill),
                    action(tr(lang, "ui.button.open_folder"), Some(Message::Open(Target::Reveal(path))), false),
                ]
                .spacing(12)
                .align_y(Alignment::Center),
            );
        }
    }
    c = c.push(text(tr(lang, "ui.details.folders_checked")).size(16).font(bold()));
    for p in &e.checked {
        c = c.push(text(p.display().to_string()).font(Font::MONOSPACE).size(13).wrapping(text::Wrapping::WordOrGlyph));
    }
    card(c).into()
}

fn bullet<'a>(line: impl text::IntoFragment<'a>) -> Element<'a, Message> {
    row![text("-").width(12), text(line).width(Fill).wrapping(text::Wrapping::WordOrGlyph)].spacing(6).into()
}

/// The default "Done" box, with a visible border while unchecked (MUTED on CARD: 6.1:1).
fn check_style(theme: &Theme, status: checkbox::Status) -> checkbox::Style {
    let mut style = checkbox::primary(theme, status);
    if let checkbox::Status::Active { is_checked: false } | checkbox::Status::Hovered { is_checked: false } = status {
        style.border.color = MUTED;
    }
    style
}

/// The default switch, with a visible track while off (NEUTRAL on BG: 3.8:1).
fn switch_style(theme: &Theme, status: toggler::Status) -> toggler::Style {
    let mut style = toggler::default(theme, status);
    if let toggler::Status::Active { is_toggled: false } | toggler::Status::Hovered { is_toggled: false } = status {
        style.background = NEUTRAL.into();
        style.foreground = TEXT.into();
    }
    style
}

/// A result tab; the active one has the accent border and bold text.
fn tab_button<'a>(tab: Tab, label: String, active: bool) -> Element<'a, Message> {
    button(text(label).font(if active { bold() } else { Font::DEFAULT }))
        .padding([8, 18])
        .style(move |_, status| {
            let hover = matches!(status, button::Status::Hovered | button::Status::Pressed);
            let background = if active { CARD } else if hover { LINE } else { BG };
            button::Style {
                background: Some(Background::Color(background)),
                text_color: if active || hover { TEXT } else { MUTED },
                border: border::rounded(8).color(if active { ACCENT } else { LINE }).width(if active { 2 } else { 1 }),
                ..button::Style::default()
            }
        })
        .on_press(Message::Tab(tab))
        .into()
}

/// Where "Scan this computer" looks (see `locate::plan_computer`).
const QUICK_SCAN: &str = if cfg!(windows) {
    "ui.home.quick_windows"
} else if cfg!(target_os = "macos") {
    "ui.home.quick_macos"
} else {
    "ui.home.quick_linux"
};

fn top_bar<'a>(lang: Lang) -> Element<'a, Message> {
    let pill = container(text(tr(lang, "report.read_only")).size(12).color(MUTED))
        .padding([4, 12])
        .style(|_| surface(CARD, 999).border(border::rounded(999).color(LINE).width(1)));
    container(
        row![
            glyph(Glyph::Logo, 24.0),
            text(report::APP_NAME).size(16).font(bold()),
            text(env!("CARGO_PKG_VERSION")).size(13).color(MUTED),
            space::horizontal(),
            pill,
        ]
        .spacing(10)
        .align_y(Alignment::Center),
    )
    .padding([10, 24])
    .width(Fill)
    .style(|_| surface(BAR, 0))
    .into()
}

/// The language menu, at the bottom left of every screen.
fn bottom_bar<'a>(lang: Lang) -> Element<'a, Message> {
    container(pick_list(&Lang::ALL[..], Some(lang), Message::Lang).text_size(13).padding([4, 10]))
        .padding([6, 24])
        .width(Fill)
        .style(|_| surface(BAR, 0))
        .into()
}

fn scanning(scan: &Scan, lang: Lang) -> Element<'_, Message> {
    let t = |key| tr(lang, key);
    let p = &*scan.progress;
    let stage = p.stage();
    let elapsed = scan.now.saturating_duration_since(scan.started);
    let ring = stack![
        canvas(Ring { seconds: elapsed.as_secs_f32() }).width(150).height(150),
        container(column![text(clock(elapsed)).size(30).font(bold()), text(t("ui.scan.elapsed")).size(12).color(MUTED)].align_x(Alignment::Center))
            .center(150),
    ];

    let (done, total) = (p.checks_done.load(Relaxed), p.checks_total.load(Relaxed));
    let checking = match total {
        _ if stage < Stage::Locations => t("ui.scan.locations").to_string(),
        1 => t("ui.scan.locations_one").to_string(),
        n => msg("ui.scan.locations_other").arg("n", n.to_string()).render(lang),
    };
    let of = || msg("ui.scan.progress").arg("done", done.to_string()).arg("total", total.to_string()).render(lang);
    // The order run() uses: discovery, running programs, each location, hosts file.
    let steps = [
        (Stage::Searching, t("ui.scan.searching").to_string(), None),
        (Stage::Programs, t("ui.scan.programs").to_string(), None),
        (Stage::Locations, checking, (stage >= Stage::Locations).then(of)),
        (Stage::Hosts, t("ui.scan.hosts").to_string(), None),
    ];
    let mut list = Column::new().spacing(14);
    for (step, label, detail) in steps {
        let (state, color) = match step.cmp(&stage) {
            Ordering::Less => (Glyph::Done, TEXT),
            Ordering::Equal => (Glyph::Active, TEXT),
            Ordering::Greater => (Glyph::Pending, MUTED),
        };
        let mut line = row![glyph(state, 20.0), text(label).color(color).width(Fill)].spacing(12).align_y(Alignment::Center);
        if let Some(detail) = detail {
            line = line.push(text(detail).color(MUTED));
        }
        list = list.push(line);
    }

    let found: usize = p.found.iter().map(|n| n.load(Relaxed)).sum();
    let critical = p.findings[Severity::Critical as usize].load(Relaxed);
    let warnings = p.findings[Severity::Warning as usize].load(Relaxed);
    let flagged = if critical > 0 {
        CRITICAL_TEXT
    } else if warnings > 0 {
        WARNING_TEXT
    } else {
        TEXT
    };
    let tiles = grid![
        tile(t("ui.tile.items"), thousands(p.entries.load(Relaxed)), TEXT),
        tile(t("ui.tile.folders"), thousands(p.folders.load(Relaxed)), TEXT),
        tile(t("ui.tile.locations"), found.to_string(), TEXT),
        tile(t("ui.tile.findings"), (critical + warnings).to_string(), flagged),
    ]
    .fluid(200)
    .spacing(12)
    .height(Shrink);

    let folder = p.folder.lock().map(|f| f.display().to_string()).unwrap_or_default();
    // Cut from the left so the end of the path stays visible. 0.62 em is a little
    // wider than common monospace fonts (0.6 em), and the clip catches the rest.
    let now_in = responsive(move |size| {
        let fits = (size.width / (13.0 * 0.62)) as usize;
        container(text(tail(&folder, fits)).font(Font::MONOSPACE).size(13).color(MUTED).wrapping(text::Wrapping::None))
            .width(Fill)
            .clip(true)
            .into()
    })
    .height(Shrink);

    let target = match &scan.request {
        Request::Computer(false) => t("report.scope.computer").to_string(),
        Request::Computer(true) => t("report.scope.full").to_string(),
        Request::Folder(p) => p.display().to_string(),
    };
    let content = column![
        ring,
        text(msg("ui.scan.title").arg("target", target).render(lang))
            .size(22)
            .font(bold())
            .width(Fill)
            .align_x(Alignment::Center)
            .wrapping(text::Wrapping::WordOrGlyph),
        card(list),
        tiles,
        now_in,
        action(t("ui.button.stop"), Some(Message::Stop), false),
    ]
    .spacing(20)
    .align_x(Alignment::Center)
    .width(Fill)
    .max_width(720);
    container(content).center_x(Fill).into()
}

fn tile<'a>(label: &'a str, value: String, color: Color) -> Element<'a, Message> {
    card(
        column![
            text(value).size(22).font(bold()).color(color).wrapping(text::Wrapping::WordOrGlyph),
            text(label).size(13).color(MUTED),
        ]
        .spacing(2),
    )
    .padding([12, 16])
    .into()
}

fn mono_box<'a>(content: String) -> Element<'a, Message> {
    container(text(content).font(Font::MONOSPACE).size(13).wrapping(text::Wrapping::WordOrGlyph))
        .padding(8)
        .width(Length::Fill)
        .style(|_| surface(CODE, 4))
        .into()
}

/// Decoded once, so iced keeps one texture for every frame.
static MOTHERSPHERE: std::sync::LazyLock<image::Handle> =
    std::sync::LazyLock::new(|| image::Handle::from_bytes(include_bytes!("../assets/mothersphere.png").as_slice()));

/// MotherSphere pointing at a speech bubble. Below 560 px of width only the bubble is left.
fn helper(say: &'static str) -> Element<'static, Message> {
    responsive(move |size| {
        let bubble = container(text(say).size(16).wrapping(text::Wrapping::WordOrGlyph))
            .padding([14, 18])
            .width(Fill)
            .style(|_| surface(CARD, 12).border(border::rounded(12).color(INFO).width(1)));
        if size.width < 560.0 {
            return bubble.into();
        }
        row![image(MOTHERSPHERE.clone()).width(130), bubble].spacing(16).align_y(Alignment::Center).into()
    })
    .height(Shrink)
    .into()
}

fn card<'a>(content: impl Into<Element<'a, Message>>) -> container::Container<'a, Message> {
    container(content).padding(20).width(Fill).style(|_| surface(CARD, 10))
}

/// A button; `primary` is the main action of a screen.
fn action<'a>(label: impl text::IntoFragment<'a>, on_press: Option<Message>, primary: bool) -> Element<'a, Message> {
    let (base, hover, label_color) = if primary { (INFO, INFO_HOVER, Color::WHITE) } else { (LINE, LINE_HOVER, TEXT) };
    button(text(label))
        .padding([8, 18])
        .style(move |_, status| {
            let (background, text_color) = match status {
                button::Status::Disabled => (LINE, MUTED),
                button::Status::Hovered | button::Status::Pressed => (hover, label_color),
                button::Status::Active => (base, label_color),
            };
            button::Style {
                background: Some(Background::Color(background)),
                text_color,
                border: border::rounded(8),
                ..button::Style::default()
            }
        })
        .on_press_maybe(on_press)
        .into()
}

fn heading<'a>(label: &'a str) -> Element<'a, Message> {
    column![space().height(4), text(label).size(20).font(bold())].into()
}

fn bold() -> Font {
    Font { weight: font::Weight::Bold, ..Font::DEFAULT }
}

fn surface(color: Color, radius: u32) -> container::Style {
    container::Style {
        background: Some(Background::Color(color)),
        border: border::rounded(radius),
        ..container::Style::default()
    }
}

fn filled(color: Color) -> container::Style {
    container::Style {
        text_color: Some(Color::WHITE),
        background: Some(Background::Color(color)),
        border: border::rounded(6),
        ..container::Style::default()
    }
}

// Colors. Contrast ratios are WCAG 2 and taken against CARD, the lightest
// surface that text sits on; BG, BAR and CODE are darker, so they give more.
const BG: Color = Color::from_rgb8(0x1b, 0x1d, 0x21);
const BAR: Color = Color::from_rgb8(0x14, 0x15, 0x18);
const CARD: Color = Color::from_rgb8(0x24, 0x26, 0x2b);
const CODE: Color = Color::from_rgb8(0x16, 0x17, 0x1a);
/// Borders, the ring track and secondary buttons (TEXT on it: 9.8:1, MUTED: 4.8:1).
const LINE: Color = Color::from_rgb8(0x33, 0x36, 0x3d);
const LINE_HOVER: Color = Color::from_rgb8(0x3d, 0x40, 0x48); // TEXT on it: 8.4:1
const TEXT: Color = Color::from_rgb8(0xe6, 0xe7, 0xe9); // 12.2:1
const MUTED: Color = Color::from_rgb8(0xa0, 0xa4, 0xab); // 6.1:1
// Severity text on dark surfaces. The fill colors below are too dark for it (2.3 to 3.0:1).
const CRITICAL_TEXT: Color = Color::from_rgb8(0xf2, 0x8b, 0x82); // 6.3:1
const WARNING_TEXT: Color = Color::from_rgb8(0xf0, 0xa3, 0x5a); // 7.3:1
const OK_TEXT: Color = Color::from_rgb8(0x6c, 0xc4, 0x8f); // 7.2:1
const INFO_TEXT: Color = Color::from_rgb8(0x8a, 0xb4, 0xf8); // 7.2:1
// Fills under white text (white on each, WCAG AA needs 4.5:1).
const INFECTED: Color = Color::from_rgb8(0xb3, 0x26, 0x1e); // 6.5:1
const EXPOSED: Color = Color::from_rgb8(0xa8, 0x55, 0x00); // 5.3:1
const NO_TRACES: Color = Color::from_rgb8(0x2e, 0x7d, 0x4f); // 5.1:1
const NOT_FOUND: Color = Color::from_rgb8(0x5a, 0x5f, 0x66); // 6.4:1
const INFO: Color = Color::from_rgb8(0x3d, 0x6f, 0xb0); // 5.1:1
const INFO_HOVER: Color = Color::from_rgb8(0x34, 0x5f, 0x98); // 6.5:1
// Icons and the ring (non-text graphics need 3:1).
const ACCENT: Color = Color::from_rgb8(0x5b, 0x9b, 0xe8); // 5.3:1
const PENDING: Color = Color::from_rgb8(0x6b, 0x70, 0x79); // 3.0:1
const NEUTRAL: Color = Color::from_rgb8(0x7a, 0x7f, 0x88); // 3.8:1

fn verdict_color(verdict: Verdict) -> Color {
    match verdict {
        Verdict::Infected => INFECTED,
        Verdict::Exposed => EXPOSED,
        Verdict::NoTraces => NO_TRACES,
        Verdict::NotFound => NOT_FOUND,
    }
}

fn severity_color(severity: Severity) -> Color {
    match severity {
        Severity::Critical => INFECTED,
        Severity::Warning => EXPOSED,
        Severity::Info => INFO,
    }
}

/// winit 0.30 has no file drop on Wayland; Windows, macOS and X11 have it.
fn drop_works() -> bool {
    let set = |k: &str| std::env::var_os(k).is_some_and(|v| !v.is_empty());
    !cfg!(all(unix, not(target_os = "macos"))) || !(set("WAYLAND_DISPLAY") || set("WAYLAND_SOCKET"))
}

/// "m:ss".
fn clock(d: Duration) -> String {
    let s = d.as_secs();
    format!("{}:{:02}", s / 60, s % 60)
}

fn duration(seconds: f64) -> String {
    if seconds < 60.0 { format!("{seconds:.1} s") } else { clock(Duration::from_secs_f64(seconds)) }
}

/// The end of `s` in at most `max` characters, with "..." in front when cut.
fn tail(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        return s.to_string();
    }
    let keep = max.saturating_sub(3);
    format!("...{}", s.chars().skip(n - keep).collect::<String>())
}

// ------------------------------------------------------------------- icons

#[derive(Debug, Clone, Copy)]
enum Glyph {
    Logo,
    /// The home screen shield, before any scan.
    Shield,
    Verdict(Verdict),
    Done,
    Active,
    Pending,
}

const CHECK: [(f32, f32); 3] = [(0.33, 0.49), (0.45, 0.61), (0.68, 0.37)];

fn glyph<'a>(g: Glyph, size: f32) -> Element<'a, Message> {
    canvas(g).width(size).height(size).into()
}

impl canvas::Program<Message> for Glyph {
    type State = ();

    fn draw(&self, _: &(), renderer: &Renderer, _: &Theme, bounds: Rectangle, _: mouse::Cursor) -> Vec<canvas::Geometry> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let s = bounds.width.min(bounds.height);
        let pen = |color: Color, width: f32| {
            canvas::Stroke::default()
                .with_color(color)
                .with_width(width * s)
                .with_line_cap(canvas::LineCap::Round)
                .with_line_join(canvas::LineJoin::Round)
        };
        let circle = |x: f32, y: f32, r: f32| canvas::Path::circle(Point::new(x * s, y * s), r * s);
        let shield = path(&shield_outline(), s, true);
        match *self {
            Glyph::Logo => {
                frame.fill(&shield, ACCENT);
                frame.stroke(&path(&CHECK, s, false), pen(BAR, 0.1));
            }
            Glyph::Shield => frame.fill(&shield, NEUTRAL),
            Glyph::Verdict(Verdict::NotFound) => {
                frame.stroke(&circle(0.43, 0.43, 0.25), pen(Color::WHITE, 0.09));
                frame.stroke(&path(&[(0.62, 0.62), (0.84, 0.84)], s, false), pen(Color::WHITE, 0.12));
            }
            Glyph::Verdict(verdict) => {
                frame.fill(&shield, Color::WHITE);
                let mark = pen(verdict_color(verdict), 0.09);
                match verdict {
                    Verdict::Infected => {
                        frame.stroke(&path(&[(0.37, 0.34), (0.63, 0.60)], s, false), mark);
                        frame.stroke(&path(&[(0.63, 0.34), (0.37, 0.60)], s, false), mark);
                    }
                    Verdict::Exposed => {
                        frame.stroke(&path(&[(0.5, 0.26), (0.5, 0.54)], s, false), mark);
                        frame.fill(&circle(0.5, 0.69, 0.055), verdict_color(verdict));
                    }
                    _ => frame.stroke(&path(&CHECK, s, false), mark),
                }
            }
            Glyph::Done => {
                frame.fill(&circle(0.5, 0.5, 0.5), OK_TEXT);
                frame.stroke(&path(&[(0.28, 0.52), (0.43, 0.67), (0.72, 0.36)], s, false), pen(CARD, 0.12));
            }
            Glyph::Active => {
                frame.stroke(&circle(0.5, 0.5, 0.44), pen(ACCENT, 0.1));
                frame.fill(&circle(0.5, 0.5, 0.2), ACCENT);
            }
            Glyph::Pending => frame.stroke(&circle(0.5, 0.5, 0.44), pen(PENDING, 0.1)),
        }
        vec![frame.into_geometry()]
    }
}

/// The indeterminate scan ring.
struct Ring {
    seconds: f32,
}

impl canvas::Program<Message> for Ring {
    type State = ();

    fn draw(&self, _: &(), renderer: &Renderer, _: &Theme, bounds: Rectangle, _: mouse::Cursor) -> Vec<canvas::Geometry> {
        let mut frame = canvas::Frame::new(renderer, bounds.size());
        let center = frame.center();
        let radius = bounds.width.min(bounds.height) / 2.0 - 6.0;
        let pen = |color| canvas::Stroke::default().with_width(10.0).with_color(color).with_line_cap(canvas::LineCap::Round);
        frame.stroke(&canvas::Path::circle(center, radius), pen(LINE));
        // One turn every 1.5 s; the arc also grows and shrinks.
        let start = self.seconds * TAU / 1.5;
        let sweep = PI * (0.5 + 0.25 * (self.seconds * 2.0).sin());
        let arc = canvas::Path::new(|b| {
            b.arc(canvas::path::Arc { center, radius, start_angle: Radians(start), end_angle: Radians(start + sweep) });
        });
        frame.stroke(&arc, pen(ACCENT));
        vec![frame.into_geometry()]
    }
}

/// Lines through `points` (unit square) scaled to `s` pixels.
fn path(points: &[(f32, f32)], s: f32, closed: bool) -> canvas::Path {
    canvas::Path::new(|b| {
        for (i, &(x, y)) in points.iter().enumerate() {
            let p = Point::new(x * s, y * s);
            if i == 0 { b.move_to(p) } else { b.line_to(p) }
        }
        if closed {
            b.close();
        }
    })
}

/// Shield outline in a unit square, clockwise from the top middle.
fn shield_outline() -> Vec<(f32, f32)> {
    // The lower right edge is a cubic curve down to the tip.
    let (a, b, c, d) = ((0.86, 0.48), (0.86, 0.74), (0.68, 0.88), (0.5, 0.95));
    let mut points = vec![(0.5, 0.06), (0.86, 0.18), a];
    for i in 1..=16 {
        let t = i as f32 / 16.0;
        let u = 1.0 - t;
        let mix = |p: f32, q: f32, r: f32, s: f32| u * u * u * p + 3.0 * u * u * t * q + 3.0 * u * t * t * r + t * t * t * s;
        points.push((mix(a.0, b.0, c.0, d.0), mix(a.1, b.1, c.1, d.1)));
    }
    // The left half mirrors the right one, without the top middle and the tip.
    let left: Vec<(f32, f32)> = points[1..points.len() - 1].iter().rev().map(|&(x, y)| (1.0 - x, y)).collect();
    points.extend(left);
    points
}

const ICON_PX: u32 = 64;

/// The window icon (the top bar logo) as RGBA, with 4x4 samples per pixel.
fn icon_rgba() -> Vec<u8> {
    let outline = shield_outline();
    let inside = |x: f32, y: f32| {
        // Even-odd ray cast.
        let mut inside = false;
        for (i, &(xi, yi)) in outline.iter().enumerate() {
            let (xj, yj) = outline[(i + outline.len() - 1) % outline.len()];
            if (yi > y) != (yj > y) && x < (xj - xi) * (y - yi) / (yj - yi) + xi {
                inside = !inside;
            }
        }
        inside
    };
    let on_check = |x: f32, y: f32| {
        CHECK.windows(2).any(|w| {
            let ((ax, ay), (bx, by)) = (w[0], w[1]);
            let (dx, dy) = (bx - ax, by - ay);
            let t = (((x - ax) * dx + (y - ay) * dy) / (dx * dx + dy * dy)).clamp(0.0, 1.0);
            let (ex, ey) = (ax + t * dx - x, ay + t * dy - y);
            ex * ex + ey * ey <= 0.05 * 0.05
        })
    };
    let (shield, mark) = (ACCENT.into_rgba8(), BAR.into_rgba8());
    let mut rgba = Vec::with_capacity((ICON_PX * ICON_PX * 4) as usize);
    for py in 0..ICON_PX {
        for px in 0..ICON_PX {
            let (mut fill, mut check) = (0u32, 0u32);
            for sy in 0..4 {
                for sx in 0..4 {
                    let x = (px as f32 + (sx as f32 + 0.5) / 4.0) / ICON_PX as f32;
                    let y = (py as f32 + (sy as f32 + 0.5) / 4.0) / ICON_PX as f32;
                    if inside(x, y) {
                        fill += 1;
                        check += u32::from(on_check(x, y));
                    }
                }
            }
            for ch in 0..3 {
                let mixed = (u32::from(shield[ch]) * (fill - check) + u32::from(mark[ch]) * check) / fill.max(1);
                rgba.push(mixed as u8);
            }
            rgba.push((fill * 255 / 16) as u8);
        }
    }
    rgba
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn number_and_path_formats() {
        assert_eq!(thousands(0), "0");
        assert_eq!(thousands(999), "999");
        assert_eq!(thousands(1000), "1,000");
        assert_eq!(thousands(3_000_000), "3,000,000");
        assert_eq!(clock(Duration::from_secs(125)), "2:05");
        assert_eq!(tail("/home/u/Games", 20), "/home/u/Games");
        assert_eq!(tail("/home/u/Games/NIKKE", 10), "...s/NIKKE");
        assert_eq!(tail("abc", 0), "...");
    }

    #[test]
    fn every_result_tab_builds() {
        use crate::exposure::SecretFile;
        use crate::locate::{Target, TargetKind, WalkStats};
        use crate::scan::HostsStatus;
        use crate::timeline::{AgentRun, RunKind};
        let profile = PathBuf::from("/x/pfx/drive_c/users/steamuser");
        let finding = |kind, severity, title: &str| Finding {
            kind,
            severity,
            title: title.into(),
            detail: "Detail.".into(),
            path: Some(profile.join("AppData/Local/Temp/k2f-bcreds-1")),
            open_path: Some(profile.join("AppData/Local/Temp/k2f-bcreds-1")),
            copy_text: Some("HKCU\\Software\\Classes\\CLSID\\{E77CC89B-7401-4C04-8CED-149DB35ADD04}".into()),
            evidence: vec!["agent started as COLONY".into()],
            time: None,
        };
        let r = ScanResult {
            scope: "/x".into(),
            started: "2026-11-04 10:00:00 UTC".into(),
            verdict: Verdict::Infected,
            targets: vec![Target { kind: TargetKind::UserProfile, path: profile.clone(), host: false }],
            groups: vec![Group {
                label: "User profile".into(),
                path: Some(profile.clone()),
                findings: vec![
                    finding(FindingKind::TempFile, Severity::Critical, "Files left by the malware in Temp"),
                    finding(FindingKind::RegistryLeftover, Severity::Critical, "Registry leftover"),
                    finding(FindingKind::Info, Severity::Info, "Hex ID file in Temp"),
                    finding(FindingKind::Coverage, Severity::Info, "Some folders could not be read"),
                ],
            }],
            hosts: Some(HostsStatus { path: PathBuf::from("/etc/hosts"), note: None, domains: vec![("insightjs.com", Some(false))] }),
            stats: WalkStats::default(),
            seconds: 1.0,
            runs: vec![AgentRun { kind: RunKind::Started, time: None, agent_id: None, host: Some("COLONY".into()), file: None, source: PathBuf::new() }],
            builds: Vec::new(),
            exposure: Some(Exposure {
                checked: vec![profile.clone()],
                secrets: vec![SecretFile { what: "AWS credentials", path: profile.join(".aws/credentials") }],
                ..Exposure::default()
            }),
        };
        let (mut app, _) = App::boot(None, Lang::En);
        let _ = app.update(Message::Finished(0, Some(Arc::new(r))));
        app.info_open = true;
        app.evidence.insert((0, 0));
        for tab in Tab::ALL {
            let _ = app.update(Message::Tab(tab));
            let _ = app.view();
        }
        let Phase::Done(d) = &app.phase else { panic!("no result") };
        assert!(d.steps.iter().any(|s| s.title == "Delete the leftover registry key"));
        let report = app.report_text().unwrap();
        assert!(report.contains("COLONY"));
        // Every {name} of the texts got its value.
        let unfilled = report.split('{').skip(1).filter_map(|s| s.split_once('}')).find(|(n, _)| n.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'));
        assert!(unfilled.is_none(), "{unfilled:?} in:\n{report}");

        // Another language redraws the result in place; the Done marks and the tab stay.
        let _ = app.update(Message::StepDone(1, true));
        for lang in Lang::ALL {
            let _ = app.update(Message::Lang(lang));
            let _ = app.view();
        }
        let _ = app.update(Message::Lang(Lang::En));
        assert!(app.checked.contains(&1) && app.tab == Tab::Details);
        assert_eq!(app.report_text().unwrap(), report);
        let _ = app.update(Message::Hide(true));
        let hidden = app.report_text().unwrap();
        assert!(!hidden.contains("COLONY") && !hidden.contains("steamuser"), "{hidden}");

        // Closing before the steps were seen shows the warning; opening them removes it.
        let _ = app.update(Message::Finished(0, Some(d_result(&app))));
        assert_eq!(app.tab, Tab::Happened);
        let _ = app.update(Message::CloseRequested);
        assert!(app.close_warning);
        let _ = app.view();
        let _ = app.update(Message::Tab(Tab::Todo));
        assert!(!app.close_warning && !app.steps_unseen());
        // A result without traces closes at once.
        let Phase::Done(d) = &app.phase else { panic!("no result") };
        let mut clean = (*d.result).clone();
        clean.verdict = Verdict::NoTraces;
        let _ = app.update(Message::Finished(0, Some(Arc::new(clean))));
        let _ = app.update(Message::CloseRequested);
        assert!(!app.close_warning);
    }

    fn d_result(app: &App) -> Arc<ScanResult> {
        let Phase::Done(d) = &app.phase else { panic!("no result") };
        d.result.clone()
    }

    #[test]
    fn window_icon_is_a_shield() {
        let rgba = icon_rgba();
        assert_eq!(rgba.len(), (ICON_PX * ICON_PX * 4) as usize);
        let alpha = |x: u32, y: u32| rgba[((y * ICON_PX + x) * 4 + 3) as usize];
        assert_eq!(alpha(0, 0), 0);
        assert_eq!(alpha(ICON_PX / 2, ICON_PX / 4), 255);
        assert!(window::icon::from_rgba(rgba.clone(), ICON_PX, ICON_PX).is_ok());
    }
}
