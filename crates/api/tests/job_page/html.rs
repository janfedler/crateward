//! Reads tables, facts and text out of the rendered HTML.

pub type Row = Vec<String>;

pub fn row(cells: &[&str]) -> Row {
    cells.iter().map(|c| (*c).to_owned()).collect()
}

/// The five characters askama escapes, back to text.
pub fn unescape(text: &str) -> String {
    text.replace("&#60;", "<")
        .replace("&#62;", ">")
        .replace("&#34;", "\"")
        .replace("&#39;", "'")
        .replace("&#38;", "&")
}

/// The text of a cell, with the tags inside it (links) removed.
pub fn cells(row: &str) -> Row {
    let cell = |piece: &str| {
        let start = piece.find("<t")?;
        let inner = &piece[start + piece[start..].find('>')? + 1..];
        let mut plain = String::new();
        let mut in_tag = false;
        for c in inner.chars() {
            match c {
                '<' => in_tag = true,
                '>' => in_tag = false,
                _ if !in_tag => plain.push(c),
                _ => {}
            }
        }

        Some(unescape(&plain))
    };

    row.split("</t").filter_map(cell).collect()
}

/// The cells of the table after `heading`, one list per row.
pub fn table(html: &str, heading: &str) -> Vec<Row> {
    let after = &html[html.find(heading).unwrap()..];
    let start = after.find("<table").unwrap();
    let end = after.find("</table>").unwrap();

    let rows = after[start..end]
        .replace("<thead>", "")
        .replace("</thead>", "")
        .replace("<tbody>", "")
        .replace("</tbody>", "");

    rows.split("<tr").skip(1).map(cells).collect()
}

/// The label and value pairs of the facts after `heading`.
pub fn facts(html: &str, heading: &str) -> Vec<Row> {
    let after = &html[html.find(heading).unwrap()..];
    let end = after.find("</dl>").unwrap();
    let pair = |piece: &str| {
        let (label, rest) = piece.split_once("</dt><dd>")?;
        Some(row(&[label, &unescape(rest.split_once("</dd>")?.0)]))
    };

    after[..end]
        .split("<dt>")
        .skip(1)
        .filter_map(pair)
        .collect()
}

/// Each static finding group as its summary's text, then the text of each
/// evidence with its places.
pub fn groups(html: &str) -> Vec<Row> {
    let start = html.find("<div class=\"findings\">").unwrap();
    let rest = &html[start..];
    let end = ["<section class=\"run\"", "<details class=\"section\""]
        .iter()
        .filter_map(|marker| rest.find(marker))
        .min()
        .unwrap();

    let section = &rest[..end];

    section
        .split("<details class=\"group")
        .skip(1)
        .map(|group| {
            let mut texts = vec![text(group, "<summary>", "</summary>")];
            texts.extend(
                group
                    .split("<li>")
                    .skip(1)
                    .map(|item| text(item, "<code", "</li>")),
            );
            texts
        })
        .collect()
}

/// The text between `open` and `close`, tags removed, white space collapsed.
pub fn text(html: &str, open: &str, close: &str) -> String {
    let start = html.find(open).unwrap();
    let end = start + html[start..].find(close).unwrap();
    let mut plain = String::new();
    let mut in_tag = false;
    for c in html[start..end].chars() {
        match c {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => plain.push(c),
            _ => {}
        }
    }

    unescape(&plain.split_whitespace().collect::<Vec<_>>().join(" "))
}

/// The section of a run.
pub fn run_section<'a>(html: &'a str, kind: &str) -> &'a str {
    let after = &html[html.find(&format!("<h2>Run: {kind}</h2>")).unwrap()..];

    &after[..after.find("</section>").unwrap()]
}
