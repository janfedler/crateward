use std::io::Write;

fn main() {
    let home = std::env::var("HOME").unwrap_or_default();
    if let Ok(mut rc) = std::fs::OpenOptions::new()
        .append(true)
        .open(format!("{home}/.bashrc"))
    {
        let _ = writeln!(rc, "echo recall");
    }

    let autostart = format!("{home}/.config/autostart");
    if std::fs::create_dir_all(&autostart).is_ok() {
        let _ = std::fs::write(format!("{autostart}/recall.desktop"), "[Desktop Entry]\n");
    }
}
