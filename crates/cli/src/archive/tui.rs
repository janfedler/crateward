//! The terminal screen of `crateward archive`: filters on the left, the
//! jobs they choose on the right, the highlighted job's evidence below.

use std::collections::HashMap;
use std::path::Path;

use crateward_core::store::ArchiveCandidate;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Cell, Paragraph, Row, Table, TableState, Wrap};
use ratatui::{DefaultTerminal, Frame};

use super::selection::{COVERAGE, LEVELS, Mark, REVIEWS, Selection};

/// A line of the filter pane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Item {
    Level(&'static str),
    Review(&'static str, &'static str),
    Coverage(&'static str, &'static str),
    MinScore,
    PerLevel,
    Name,
}

/// The filter pane's lines, in order.
fn items() -> Vec<Item> {
    LEVELS
        .into_iter()
        .map(Item::Level)
        .chain(REVIEWS.into_iter().map(|(r, l)| Item::Review(r, l)))
        .chain(COVERAGE.into_iter().map(|(c, l)| Item::Coverage(c, l)))
        .chain([Item::MinScore, Item::PerLevel, Item::Name])
        .collect()
}

/// Where the keys go.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Focus {
    Filters,
    Jobs,
}

/// What a key asks for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Keep going.
    Continue,
    /// Write the archive.
    Write,
    /// Leave without writing.
    Quit,
}

/// The screen's state.
pub struct App<'a> {
    candidates: &'a [ArchiveCandidate],
    /// The choice so far.
    pub selection: Selection,
    marks: Vec<Mark>,
    /// Indices of the candidates in the job list.
    visible: Vec<usize>,
    /// Taken jobs per level.
    taken: HashMap<&'a str, usize>,
    /// Candidates per level.
    totals: HashMap<&'a str, usize>,
    items: Vec<Item>,
    focus: Focus,
    filter: usize,
    jobs: TableState,
    editing: bool,
    out: String,
    message: String,
}

const SEVERE: Color = Color::Red;
const MEDIUM: Color = Color::Yellow;
const QUIET: Color = Color::DarkGray;
const ACCENT: Color = Color::Cyan;

fn level_color(level: &str) -> Color {
    match level {
        "critical" | "high" => SEVERE,
        "medium" => MEDIUM,
        _ => Color::Gray,
    }
}

fn review_label(review: &str) -> &'static str {
    match review {
        "confirmed" => "confirmed",
        "false_positive" => "false positive",
        "pending" => "waits for review",
        _ => "not reviewed",
    }
}

fn coverage_label(kind: &str) -> &str {
    COVERAGE
        .iter()
        .find(|(k, _)| *k == kind)
        .map_or(kind, |(_, label)| label)
}

impl<'a> App<'a> {
    /// A screen over `candidates`, highest score first, starting from
    /// `selection`, for an archive in `out`.
    #[must_use]
    pub fn new(candidates: &'a [ArchiveCandidate], selection: Selection, out: &Path) -> Self {
        let mut totals: HashMap<&str, usize> = HashMap::new();
        for c in candidates {
            *totals.entry(c.level.as_str()).or_default() += 1;
        }

        let mut app = Self {
            candidates,
            selection,
            marks: Vec::new(),
            visible: Vec::new(),
            taken: HashMap::new(),
            totals,
            items: items(),
            focus: Focus::Filters,
            filter: 0,
            jobs: TableState::default(),
            editing: false,
            out: out.display().to_string(),
            message: String::new(),
        };

        app.refresh();
        app.jobs.select(Some(0));

        app
    }

    /// Recomputes the marks and the job list after a change.
    fn refresh(&mut self) {
        self.marks = self.selection.marks(self.candidates);
        self.taken.clear();
        self.visible.clear();

        for (i, (c, mark)) in self.candidates.iter().zip(&self.marks).enumerate() {
            if mark.taken() {
                *self.taken.entry(c.level.as_str()).or_default() += 1;
            }

            let shown = match mark {
                Mark::Filtered => false,
                Mark::Refused(_) => self.selection.matches_but_review(c),
                _ => true,
            };
            if shown {
                self.visible.push(i);
            }
        }

        let last = self.visible.len().saturating_sub(1);
        if self.jobs.selected().is_some_and(|s| s > last) {
            self.jobs.select(Some(last));
        }
    }

    /// The jobs the archive will hold.
    #[must_use]
    pub fn chosen(&self) -> usize {
        self.marks.iter().filter(|m| m.taken()).count()
    }

    /// The highlighted job and its mark.
    fn current(&self) -> Option<(&'a ArchiveCandidate, Mark)> {
        let i = *self.visible.get(self.jobs.selected()?)?;

        Some((self.candidates.get(i)?, *self.marks.get(i)?))
    }

    /// Handles a key.
    pub fn key(&mut self, key: KeyEvent) -> Outcome {
        if key.kind != KeyEventKind::Press {
            return Outcome::Continue;
        }

        self.message.clear();

        if self.editing {
            self.edit(key.code);
            return Outcome::Continue;
        }

        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Outcome::Quit;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return Outcome::Quit,
            KeyCode::Char('w') => {
                if self.chosen() == 0 {
                    self.message = "Nothing chosen yet.".to_owned();
                } else {
                    return Outcome::Write;
                }
            }
            KeyCode::Tab | KeyCode::BackTab => {
                self.focus = match self.focus {
                    Focus::Filters => Focus::Jobs,
                    Focus::Jobs => Focus::Filters,
                };
            }
            KeyCode::Char('/') => {
                self.focus = Focus::Filters;
                self.filter = self.items.len().saturating_sub(1);
                self.editing = true;
            }
            code => match self.focus {
                Focus::Filters => self.filter_key(code),
                Focus::Jobs => self.job_key(code),
            },
        }

        Outcome::Continue
    }

    fn edit(&mut self, code: KeyCode) {
        match code {
            KeyCode::Enter | KeyCode::Esc | KeyCode::Tab => self.editing = false,
            KeyCode::Backspace => {
                self.selection.name.pop();
            }
            KeyCode::Char(c) if self.selection.name.len() < 64 => self.selection.name.push(c),
            _ => return,
        }

        self.refresh();
    }

    fn filter_key(&mut self, code: KeyCode) {
        let item = self.items.get(self.filter).copied();
        let step = |value: i64, by: i64, max: i64| (value + by).clamp(0, max);

        match (code, item) {
            (KeyCode::Up | KeyCode::Char('k'), _) => self.filter = self.filter.saturating_sub(1),
            (KeyCode::Down | KeyCode::Char('j'), _) => {
                self.filter = (self.filter + 1).min(self.items.len().saturating_sub(1));
            }
            (KeyCode::Char(' ') | KeyCode::Enter, Some(Item::Level(l))) => {
                Selection::flip(&mut self.selection.levels, l);
            }
            (KeyCode::Char(' ') | KeyCode::Enter, Some(Item::Review(r, _))) => {
                Selection::flip(&mut self.selection.reviews, r);
            }
            (KeyCode::Char(' ') | KeyCode::Enter, Some(Item::Coverage(c, _))) => {
                Selection::flip(&mut self.selection.coverage, c);
            }
            (KeyCode::Char(' ') | KeyCode::Enter, Some(Item::Name)) => self.editing = true,
            (KeyCode::Left | KeyCode::Right | KeyCode::Char('h' | 'l'), Some(item)) => {
                let by = if matches!(code, KeyCode::Left | KeyCode::Char('h')) {
                    -5
                } else {
                    5
                };

                match item {
                    Item::MinScore => {
                        let score = step(i64::from(self.selection.min_score), by, 100);
                        self.selection.min_score = i32::try_from(score).unwrap_or(0);
                    }
                    Item::PerLevel => {
                        let per = i64::try_from(self.selection.per_level).unwrap_or(0);
                        self.selection.per_level =
                            usize::try_from(step(per, by, 10_000)).unwrap_or(0);
                    }
                    _ => return,
                }
            }
            _ => return,
        }

        self.refresh();
    }

    fn job_key(&mut self, code: KeyCode) {
        let last = self.visible.len().saturating_sub(1);
        let at = self.jobs.selected().unwrap_or(0);
        let to = |n: usize| Some(n.min(last));

        match code {
            KeyCode::Up | KeyCode::Char('k') => self.jobs.select(to(at.saturating_sub(1))),
            KeyCode::Down | KeyCode::Char('j') => self.jobs.select(to(at + 1)),
            KeyCode::PageUp => self.jobs.select(to(at.saturating_sub(20))),
            KeyCode::PageDown => self.jobs.select(to(at + 20)),
            KeyCode::Home | KeyCode::Char('g') => self.jobs.select(Some(0)),
            KeyCode::End | KeyCode::Char('G') => self.jobs.select(Some(last)),
            KeyCode::Char(' ') | KeyCode::Enter => {
                let Some((c, mark)) = self.current() else {
                    return;
                };

                if let Mark::Refused(reason) = mark {
                    self.message = format!("{} {} {reason}.", c.name, c.version);
                    return;
                }

                self.selection.toggle(c.id.0, mark);
                self.refresh();
            }
            _ => {}
        }
    }

    /// Draws the screen.
    pub fn draw(&mut self, frame: &mut Frame<'_>) {
        let [title, body, keys] = Layout::vertical([
            Constraint::Length(1),
            Constraint::Min(8),
            Constraint::Length(1),
        ])
        .areas(frame.area());

        let [filters, right] =
            Layout::horizontal([Constraint::Length(36), Constraint::Min(40)]).areas(body);

        let [jobs, detail] =
            Layout::vertical([Constraint::Min(5), Constraint::Length(5)]).areas(right);

        self.draw_title(frame, title);
        self.draw_filters(frame, filters);
        self.draw_jobs(frame, jobs);
        self.draw_detail(frame, detail);
        self.draw_keys(frame, keys);
    }

    fn pane(&self, title: &str, focus: Focus) -> Block<'static> {
        let color = if self.focus == focus { ACCENT } else { QUIET };

        Block::bordered()
            .border_type(BorderType::Rounded)
            .border_style(Style::new().fg(color))
            .title(Span::styled(format!(" {title} "), Style::new().bold()))
    }

    fn draw_title(&self, frame: &mut Frame<'_>, area: Rect) {
        let line = Line::from(vec![
            Span::styled(
                " Crateward ",
                Style::new().fg(Color::Black).bg(ACCENT).bold(),
            ),
            Span::raw(" archive into "),
            Span::styled(self.out.clone(), Style::new().bold()),
            Span::raw("   "),
            Span::styled(
                format!("{} reports", self.chosen()),
                Style::new().fg(ACCENT).bold(),
            ),
            Span::styled(
                format!(" of {} analyzed versions", self.candidates.len()),
                Style::new().fg(QUIET),
            ),
        ]);

        frame.render_widget(Paragraph::new(line), area);
    }

    fn draw_filters(&self, frame: &mut Frame<'_>, area: Rect) {
        let check = |on: bool| if on { "[x]" } else { "[ ]" };
        let mut lines = Vec::new();
        let heading = |lines: &mut Vec<Line<'static>>, text: &'static str| {
            if !lines.is_empty() {
                lines.push(Line::raw(""));
            }

            lines.push(Line::styled(
                text,
                Style::new().fg(QUIET).add_modifier(Modifier::BOLD),
            ));
        };

        for (i, item) in self.items.iter().enumerate() {
            match item {
                Item::Level(l) if *l == "critical" => heading(&mut lines, "LEVEL"),
                Item::Review(r, _) if *r == "none" => heading(&mut lines, "REVIEW"),
                Item::Coverage(c, _) if *c == "dynamic_linux" => heading(&mut lines, "COVERAGE"),
                Item::MinScore => heading(&mut lines, "LIMITS"),
                _ => {}
            }

            let line = match item {
                Item::Level(l) => Line::from(vec![
                    Span::raw(format!("{} ", check(self.selection.levels.contains(*l)))),
                    Span::styled(format!("{l:<9}"), Style::new().fg(level_color(l))),
                    Span::styled(
                        format!(
                            "{:>5} of {}",
                            self.taken.get(l).unwrap_or(&0),
                            self.totals.get(l).unwrap_or(&0)
                        ),
                        Style::new().fg(QUIET),
                    ),
                ]),
                Item::Review(r, label) => Line::raw(format!(
                    "{} {label}",
                    check(self.selection.reviews.contains(*r))
                )),
                Item::Coverage(c, label) => Line::raw(format!(
                    "{} {label}",
                    check(self.selection.coverage.contains(*c))
                )),
                Item::MinScore => {
                    Line::raw(format!("Min score  ‹ {:>3} ›", self.selection.min_score))
                }
                Item::PerLevel => Line::raw(if self.selection.per_level == 0 {
                    "Per level  ‹ all ›".to_owned()
                } else {
                    format!("Per level  ‹ {:>3} ›", self.selection.per_level)
                }),
                Item::Name => {
                    let cursor = if self.editing { "▏" } else { "" };
                    let shown = if self.selection.name.is_empty() && !self.editing {
                        "any (/ to type)".to_owned()
                    } else {
                        format!("{}{cursor}", self.selection.name)
                    };

                    Line::raw(format!("Name       {shown}"))
                }
            };

            let highlighted = self.focus == Focus::Filters && i == self.filter;
            lines.push(if highlighted {
                line.style(Style::new().bg(Color::Indexed(236)).fg(Color::White).bold())
            } else {
                line
            });
        }

        frame.render_widget(
            Paragraph::new(lines).block(self.pane("Filters", Focus::Filters)),
            area,
        );
    }

    fn draw_jobs(&mut self, frame: &mut Frame<'_>, area: Rect) {
        // Rows only for the part on screen: a filter may match many
        // thousands of jobs.
        let height = usize::from(area.height.saturating_sub(3)).max(1);
        let selected = self.jobs.selected().unwrap_or(0);
        let offset = self.jobs.offset();
        let offset = if selected < offset {
            selected
        } else if selected >= offset + height {
            selected + 1 - height
        } else {
            offset
        };

        let rows = self
            .visible
            .iter()
            .skip(offset)
            .take(height)
            .filter_map(|&i| Some((self.candidates.get(i)?, *self.marks.get(i)?)))
            .map(|(c, mark)| {
                let (sign, style) = match mark {
                    Mark::Chosen => ("✓", Style::new().fg(Color::Green)),
                    Mark::Included => ("+", Style::new().fg(Color::Green).bold()),
                    Mark::Excluded => ("−", Style::new().fg(SEVERE)),
                    Mark::Capped => ("·", Style::new().fg(QUIET)),
                    Mark::Refused(_) => ("⊘", Style::new().fg(QUIET)),
                    Mark::Filtered => (" ", Style::new()),
                };

                let dim = if mark.taken() {
                    Style::new()
                } else {
                    Style::new().fg(QUIET)
                };

                Row::new(vec![
                    Cell::from(sign).style(style),
                    Cell::from(format!("{:>3}", c.score))
                        .style(Style::new().fg(level_color(&c.level)).bold()),
                    Cell::from(c.level.clone()).style(Style::new().fg(level_color(&c.level))),
                    Cell::from(Line::from(vec![
                        Span::styled(c.name.clone(), dim.bold()),
                        Span::styled(format!(" {}", c.version), Style::new().fg(QUIET)),
                    ])),
                    Cell::from(review_label(&c.review)).style(dim),
                    Cell::from(coverage_label(&c.coverage).to_owned()).style(dim),
                ])
            });

        let title = format!("Jobs  {} shown", self.visible.len());
        let table = Table::new(
            rows,
            [
                Constraint::Length(1),
                Constraint::Length(3),
                Constraint::Length(8),
                Constraint::Min(20),
                Constraint::Length(16),
                Constraint::Length(13),
            ],
        )
        .header(
            Row::new(["", "Pts", "Level", "Crate", "Review", "Coverage"])
                .style(Style::new().fg(QUIET).bold()),
        )
        .row_highlight_style(if self.focus == Focus::Jobs {
            Style::new().bg(Color::Indexed(236)).fg(Color::White)
        } else {
            Style::new()
        })
        .block(self.pane(&title, Focus::Jobs));

        let mut state = TableState::default().with_selected(Some(selected - offset));
        frame.render_stateful_widget(table, area, &mut state);
        *self.jobs.offset_mut() = offset;
    }

    fn draw_detail(&self, frame: &mut Frame<'_>, area: Rect) {
        let text = match self.current() {
            _ if !self.message.is_empty() => {
                Line::styled(self.message.clone(), Style::new().fg(MEDIUM))
            }
            Some((c, Mark::Refused(reason))) => Line::from(vec![
                Span::styled(
                    format!("Job {}: never archived, it {reason}. ", c.id.0),
                    Style::new().fg(MEDIUM),
                ),
                Span::styled(c.top_evidence.clone(), Style::new().fg(QUIET)),
            ]),
            Some((c, _)) if c.top_evidence.is_empty() => Line::styled(
                format!("Job {}: no evidence.", c.id.0),
                Style::new().fg(QUIET),
            ),
            Some((c, _)) => Line::from(vec![
                Span::styled(format!("Job {}: ", c.id.0), Style::new().fg(QUIET)),
                Span::raw(c.top_evidence.clone()),
            ]),
            None => Line::styled("No job matches these filters.", Style::new().fg(QUIET)),
        };

        frame.render_widget(
            Paragraph::new(text).wrap(Wrap { trim: true }).block(
                Block::bordered()
                    .border_type(BorderType::Rounded)
                    .border_style(Style::new().fg(QUIET))
                    .title(" Strongest evidence "),
            ),
            area,
        );
    }

    fn draw_keys(&self, frame: &mut Frame<'_>, area: Rect) {
        let keys: &[(&str, &str)] = if self.editing {
            &[("type", "name prefix"), ("enter", "done")]
        } else {
            match self.focus {
                Focus::Filters => &[
                    ("↑↓", "move"),
                    ("space", "toggle"),
                    ("←→", "change"),
                    ("tab", "jobs"),
                    ("/", "name"),
                    ("w", "write"),
                    ("q", "quit"),
                ],
                Focus::Jobs => &[
                    ("↑↓ pgup pgdn", "move"),
                    ("space", "take or leave out"),
                    ("tab", "filters"),
                    ("w", "write"),
                    ("q", "quit"),
                ],
            }
        };

        let spans: Vec<Span<'_>> = keys
            .iter()
            .flat_map(|(key, what)| {
                [
                    Span::styled(
                        format!(" {key} "),
                        Style::new().fg(Color::Black).bg(Color::Gray),
                    ),
                    Span::styled(format!(" {what}  "), Style::new().fg(QUIET)),
                ]
            })
            .collect();

        frame.render_widget(Paragraph::new(Line::from(spans)), area);
    }
}

/// Runs the screen until the maintainer writes or quits. Returns the
/// selection to write, or `None`.
///
/// # Errors
///
/// Fails if the terminal cannot be used.
pub fn run(app: &mut App<'_>) -> std::io::Result<Option<Selection>> {
    let mut terminal = ratatui::try_init()?;
    let result = event_loop(&mut terminal, app);
    ratatui::try_restore()?;

    result
}

fn event_loop(
    terminal: &mut DefaultTerminal,
    app: &mut App<'_>,
) -> std::io::Result<Option<Selection>> {
    loop {
        terminal.draw(|frame| app.draw(frame))?;

        if let Event::Key(key) = event::read()? {
            match app.key(key) {
                Outcome::Continue => {}
                Outcome::Write => return Ok(Some(app.selection.clone())),
                Outcome::Quit => return Ok(None),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crateward_core::job::JobId;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;

    fn candidate(id: i64, name: &str, score: i32, level: &str, review: &str) -> ArchiveCandidate {
        ArchiveCandidate {
            id: JobId(id),
            name: name.to_owned(),
            version: "0.1.0".to_owned(),
            score,
            level: level.to_owned(),
            review: review.to_owned(),
            coverage: "dynamic_linux".to_owned(),
            published: true,
            top_evidence: format!("evidence of {name}"),
        }
    }

    fn candidates() -> Vec<ArchiveCandidate> {
        vec![
            candidate(1, "monica_rand_core", 95, "critical", "confirmed"),
            candidate(2, "waiting", 80, "critical", "pending"),
            candidate(3, "cmake-sys", 60, "high", "false_positive"),
            candidate(4, "middling", 30, "medium", "none"),
            candidate(5, "quiet", 0, "none", "none"),
        ]
    }

    fn press(app: &mut App<'_>, code: KeyCode) -> Outcome {
        app.key(KeyEvent::new(code, KeyModifiers::NONE))
    }

    fn screen(app: &mut App<'_>) -> String {
        let mut terminal = Terminal::new(TestBackend::new(110, 30)).unwrap();
        terminal.draw(|frame| app.draw(frame)).unwrap();

        let buffer = terminal.backend().buffer();

        buffer
            .content()
            .chunks(usize::from(buffer.area.width))
            .map(|row| {
                row.iter()
                    .map(|c| c.symbol())
                    .collect::<String>()
                    .trim_end()
                    .to_owned()
            })
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn the_screen_shows_filters_jobs_and_why_a_job_is_refused() {
        let all = candidates();
        let mut app = App::new(&all, Selection::default(), Path::new("/srv/archive"));
        let shown = screen(&mut app);

        assert!(
            shown.contains(
                "Crateward  archive into /srv/archive   3 reports of 5 analyzed versions"
            ),
            "{shown}"
        );
        assert!(shown.contains("[x] critical     1 of 2"), "{shown}");
        assert!(shown.contains("[ ] none         0 of 1"), "{shown}");
        assert!(
            shown.contains("✓  95 critical monica_rand_core 0.1.0"),
            "{shown}"
        );
        assert!(shown.contains("⊘  80 critical waiting 0.1.0"), "{shown}");
        assert!(!shown.contains("quiet 0.1.0"), "{shown}");
        assert!(
            shown.contains("Job 1: evidence of monica_rand_core"),
            "{shown}"
        );

        press(&mut app, KeyCode::Tab);
        press(&mut app, KeyCode::Down);
        press(&mut app, KeyCode::Char(' '));
        assert!(screen(&mut app).contains("waiting 0.1.0 waits for review."));
        assert_eq!(app.chosen(), 3);
    }

    #[test]
    fn keys_change_the_filters_and_pick_jobs() {
        let all = candidates();
        let mut app = App::new(&all, Selection::default(), Path::new("out"));

        // Level "none" is the fifth line.
        for _ in 0..4 {
            press(&mut app, KeyCode::Down);
        }

        press(&mut app, KeyCode::Char(' '));
        assert_eq!(app.chosen(), 4);

        press(&mut app, KeyCode::Char('/'));

        for c in "cm".chars() {
            press(&mut app, KeyCode::Char(c));
        }

        press(&mut app, KeyCode::Enter);
        assert_eq!(app.selection.name, "cm");
        assert_eq!(app.chosen(), 1);

        press(&mut app, KeyCode::Tab);
        press(&mut app, KeyCode::Char(' '));
        assert_eq!(app.chosen(), 0);
        assert_eq!(press(&mut app, KeyCode::Char('w')), Outcome::Continue);
        assert!(screen(&mut app).contains("Nothing chosen yet."));

        press(&mut app, KeyCode::Char(' '));
        assert_eq!(press(&mut app, KeyCode::Char('w')), Outcome::Write);
        assert_eq!(press(&mut app, KeyCode::Char('q')), Outcome::Quit);
    }

    #[test]
    fn limits_change_in_steps_and_stay_in_range() {
        let all = candidates();
        let mut app = App::new(&all, Selection::default(), Path::new("out"));

        let limits = app.items.iter().position(|i| *i == Item::MinScore).unwrap();
        for _ in 0..limits {
            press(&mut app, KeyCode::Down);
        }

        press(&mut app, KeyCode::Left);
        assert_eq!(app.selection.min_score, 0);

        for _ in 0..7 {
            press(&mut app, KeyCode::Right);
        }

        assert_eq!(app.selection.min_score, 35);
        assert_eq!(app.chosen(), 2);

        press(&mut app, KeyCode::Down);

        for _ in 0..6 {
            press(&mut app, KeyCode::Left);
        }

        assert_eq!(app.selection.per_level, 0);
        assert!(screen(&mut app).contains("Per level  ‹ all ›"));
    }
}
