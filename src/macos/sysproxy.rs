//! The system proxy setting: point every enabled network service's "automatic proxy
//! configuration" at our PAC script, and put back exactly what was there before.
//!
//! The original settings are written to a file before anything is changed, so a crash, a
//! forced quit or a power cut never loses them: the next start (or switching off) restores
//! from that file. A service already carrying our own PAC address without a saved original
//! (left over from such a crash before this file existed) counts as "was off".
//!
//! `networksetup` is used for the changes. It works without a password for administrator
//! accounts on current macOS; when it refuses, the same commands run once through the
//! standard administrator dialog (`osascript ... with administrator privileges`).

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

const NETWORKSETUP: &str = "/usr/sbin/networksetup";

/// One service's automatic proxy setting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AutoProxy {
    pub url: Option<String>,
    pub enabled: bool,
}

/// `networksetup -listallnetworkservices` output -> enabled service names.
pub fn parse_services(out: &str) -> Vec<String> {
    out.lines()
        .skip(1) // "An asterisk (*) denotes that a network service is disabled."
        .map(str::trim_end)
        .filter(|l| !l.is_empty() && !l.starts_with('*'))
        .map(str::to_string)
        .collect()
}

/// `networksetup -getautoproxyurl <service>` output.
pub fn parse_auto(out: &str) -> Option<AutoProxy> {
    let mut url = None;
    let mut enabled = None;
    for line in out.lines() {
        if let Some(v) = line.strip_prefix("URL:") {
            let v = v.trim();
            url = Some((!v.is_empty() && v != "(null)").then(|| v.to_string()));
        } else if let Some(v) = line.strip_prefix("Enabled:") {
            enabled = Some(v.trim().eq_ignore_ascii_case("yes"));
        }
    }
    Some(AutoProxy { url: url?, enabled: enabled? })
}

/// True for a PAC address this program set (any port).
pub fn is_ours(url: &str) -> bool {
    url.strip_prefix("http://127.0.0.1:")
        .and_then(|r| r.strip_suffix(crate::proxy::PAC_PATH))
        .is_some_and(|p| p.parse::<u16>().is_ok())
}

/// Saved originals: one line per service, `enabled<TAB>url<TAB>service` (`-` for no URL).
pub fn encode_saved(m: &BTreeMap<String, AutoProxy>) -> String {
    let mut s = String::new();
    for (svc, a) in m {
        let url = a.url.as_deref().unwrap_or("-");
        s.push_str(&format!("{}\t{}\t{}\n", a.enabled as u8, url, svc));
    }
    s
}

pub fn decode_saved(s: &str) -> BTreeMap<String, AutoProxy> {
    let mut m = BTreeMap::new();
    for line in s.lines() {
        let mut p = line.splitn(3, '\t');
        let (Some(en), Some(url), Some(svc)) = (p.next(), p.next(), p.next()) else { continue };
        if svc.is_empty() {
            continue;
        }
        let url = (url != "-").then(|| url.to_string());
        m.insert(svc.to_string(), AutoProxy { url, enabled: en == "1" });
    }
    m
}

/// The commands that put `saved` back, as networksetup argument lists.
pub fn restore_commands(saved: &BTreeMap<String, AutoProxy>) -> Vec<Vec<String>> {
    let mut cmds = Vec::new();
    for (svc, a) in saved {
        match &a.url {
            Some(u) if !is_ours(u) => {
                cmds.push(vec!["-setautoproxyurl".into(), svc.clone(), u.clone()]);
                if !a.enabled {
                    cmds.push(vec!["-setautoproxystate".into(), svc.clone(), "off".into()]);
                }
            }
            _ => cmds.push(vec!["-setautoproxystate".into(), svc.clone(), "off".into()]),
        }
    }
    cmds
}

/// Where the saved originals live.
pub fn saved_path(dir: &Path) -> PathBuf {
    dir.join("proxy-saved.tsv")
}

fn networksetup(args: &[String]) -> io::Result<String> {
    let out = Command::new(NETWORKSETUP).args(args).output()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    // networksetup reports most errors on stdout with exit status 0; "** Error" marks them.
    if !out.status.success() || text.contains("** Error") || text.contains("requires admin") {
        return Err(io::Error::other(format!("networksetup {}: {}", args.join(" "), text.trim())));
    }
    Ok(text)
}

fn s(x: &str) -> String {
    x.to_string()
}

/// Enabled network services.
pub fn services() -> io::Result<Vec<String>> {
    Ok(parse_services(&networksetup(&[s("-listallnetworkservices")])?))
}

fn current(svc: &str) -> io::Result<AutoProxy> {
    let out = networksetup(&[s("-getautoproxyurl"), s(svc)])?;
    parse_auto(&out).ok_or_else(|| io::Error::other(format!("unexpected networksetup output: {}", out.trim())))
}

/// Run networksetup commands; if any is refused, run the refused ones again in one batch
/// behind the administrator dialog (only when `interactive`; the watcher never prompts).
fn run_all(cmds: &[Vec<String>], interactive: bool) -> io::Result<()> {
    let mut refused = Vec::new();
    let mut first_err = None;
    for c in cmds {
        if let Err(e) = networksetup(c) {
            refused.push(c.clone());
            first_err.get_or_insert(e);
        }
    }
    match first_err {
        None => Ok(()),
        Some(e) if !interactive => Err(e),
        Some(_) => run_as_admin(&refused),
    }
}

/// Single-quote for /bin/sh.
fn sh_quote(a: &str) -> String {
    format!("'{}'", a.replace('\'', r"'\''"))
}

/// AppleScript string literal.
fn as_quote(a: &str) -> String {
    format!("\"{}\"", a.replace('\\', "\\\\").replace('"', "\\\""))
}

/// The shell script for [`run_as_admin`] (pure, tested).
pub fn admin_script(cmds: &[Vec<String>]) -> String {
    cmds.iter()
        .map(|c| std::iter::once(NETWORKSETUP.to_string()).chain(c.iter().map(|a| sh_quote(a))).collect::<Vec<_>>().join(" "))
        .collect::<Vec<_>>()
        .join(" && ")
}

fn run_as_admin(cmds: &[Vec<String>]) -> io::Result<()> {
    let script = format!(
        "do shell script {} with administrator privileges with prompt {}",
        as_quote(&admin_script(cmds)),
        as_quote("SONdpi sistem proxy ayarını değiştirmek istiyor.")
    );
    let out = Command::new("/usr/bin/osascript").arg("-e").arg(script).output()?;
    if out.status.success() {
        Ok(())
    } else {
        Err(io::Error::other(format!("yönetici onayı alınamadı: {}", String::from_utf8_lossy(&out.stderr).trim())))
    }
}

fn write_atomic(path: &Path, data: &str) -> io::Result<()> {
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
    }
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data)?;
    std::fs::rename(&tmp, path)
}

/// Point every enabled service at `pac_url`, saving the originals in `dir` first. The result
/// is read back: networksetup does not always report a refusal, so a setting that did not
/// take is retried once behind the administrator dialog (when `interactive`).
pub fn apply(dir: &Path, pac_url: &str, interactive: bool) -> io::Result<()> {
    let path = saved_path(dir);
    let mut saved = std::fs::read_to_string(&path).map(|t| decode_saved(&t)).unwrap_or_default();
    let svcs = services()?;
    if svcs.is_empty() {
        return Err(io::Error::other("etkin ağ servisi yok"));
    }
    let mut cmds = Vec::new();
    for svc in &svcs {
        if !saved.contains_key(svc) {
            let cur = current(svc)?;
            let orig = if cur.url.as_deref().is_some_and(is_ours) { AutoProxy { url: None, enabled: false } } else { cur };
            saved.insert(svc.clone(), orig);
        }
        cmds.push(vec![s("-setautoproxyurl"), svc.clone(), pac_url.to_string()]);
    }
    write_atomic(&path, &encode_saved(&saved))?;
    run_all(&cmds, interactive)?;
    if is_applied(pac_url)? {
        return Ok(());
    }
    if interactive {
        run_as_admin(&cmds)?;
        if is_applied(pac_url)? {
            return Ok(());
        }
    }
    Err(io::Error::other("proxy ayarı uygulanamadı (macOS değişikliği kabul etmedi)"))
}

/// True when every enabled service points at `pac_url` and has it switched on.
pub fn is_applied(pac_url: &str) -> io::Result<bool> {
    for svc in services()? {
        let cur = current(&svc)?;
        if !cur.enabled || cur.url.as_deref() != Some(pac_url) {
            return Ok(false);
        }
    }
    Ok(true)
}

/// Put the saved originals back and forget them. Nothing saved: nothing to do.
pub fn restore(dir: &Path) -> io::Result<()> {
    let path = saved_path(dir);
    let saved = match std::fs::read_to_string(&path) {
        Ok(t) => decode_saved(&t),
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    // Services that disappeared meanwhile cannot be set; skip them.
    let present = services()?;
    let saved: BTreeMap<String, AutoProxy> = saved.into_iter().filter(|(k, _)| present.contains(k)).collect();
    run_all(&restore_commands(&saved), true)?;
    std::fs::remove_file(&path).or_else(|e| if e.kind() == io::ErrorKind::NotFound { Ok(()) } else { Err(e) })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn services_list() {
        let out = "An asterisk (*) denotes that a network service is disabled.\nThunderbolt Bridge\nWi-Fi\n*USB 10/100 LAN\niPhone USB\n\n";
        assert_eq!(parse_services(out), vec!["Thunderbolt Bridge", "Wi-Fi", "iPhone USB"]);
    }

    #[test]
    fn auto_proxy_output() {
        assert_eq!(parse_auto("URL: (null)\nEnabled: No\n"), Some(AutoProxy { url: None, enabled: false }));
        assert_eq!(
            parse_auto("URL: http://wpad/x.pac\nEnabled: Yes\n"),
            Some(AutoProxy { url: Some("http://wpad/x.pac".into()), enabled: true })
        );
        assert_eq!(parse_auto("** Error: The parameters were not valid.\n"), None);
    }

    #[test]
    fn ours() {
        assert!(is_ours("http://127.0.0.1:18642/proxy.pac"));
        assert!(is_ours("http://127.0.0.1:1/proxy.pac"));
        assert!(!is_ours("http://127.0.0.1:x/proxy.pac"));
        assert!(!is_ours("http://wpad/proxy.pac"));
        assert!(!is_ours("http://127.0.0.1:18642/other.pac"));
    }

    #[test]
    fn saved_round_trip_and_restore_plan() {
        let mut m = BTreeMap::new();
        m.insert("Wi-Fi".to_string(), AutoProxy { url: None, enabled: false });
        m.insert("USB 10/100 LAN".to_string(), AutoProxy { url: Some("http://wpad/x.pac".into()), enabled: false });
        m.insert("Ethernet".to_string(), AutoProxy { url: Some("http://corp/p.pac".into()), enabled: true });
        let enc = encode_saved(&m);
        assert_eq!(decode_saved(&enc), m);
        assert!(decode_saved("garbage\n1\tx\t\n").is_empty());
        let cmds = restore_commands(&m);
        let v = |a: &[&str]| a.iter().map(|x| x.to_string()).collect::<Vec<_>>();
        assert_eq!(
            cmds,
            vec![
                v(&["-setautoproxyurl", "Ethernet", "http://corp/p.pac"]),
                v(&["-setautoproxyurl", "USB 10/100 LAN", "http://wpad/x.pac"]),
                v(&["-setautoproxystate", "USB 10/100 LAN", "off"]),
                v(&["-setautoproxystate", "Wi-Fi", "off"]),
            ]
        );
        // an original that is our own address is only switched off
        let mut o = BTreeMap::new();
        o.insert("Wi-Fi".to_string(), AutoProxy { url: Some("http://127.0.0.1:5/proxy.pac".into()), enabled: true });
        assert_eq!(restore_commands(&o), vec![v(&["-setautoproxystate", "Wi-Fi", "off"])]);
    }

    #[test]
    fn admin_script_quotes_arguments() {
        let cmds = vec![vec![s("-setautoproxyurl"), s("Bob's Wi-Fi"), s("http://127.0.0.1:1/proxy.pac")], vec![s("-setautoproxystate"), s("Wi-Fi"), s("off")]];
        assert_eq!(
            admin_script(&cmds),
            r"/usr/sbin/networksetup '-setautoproxyurl' 'Bob'\''s Wi-Fi' 'http://127.0.0.1:1/proxy.pac' && /usr/sbin/networksetup '-setautoproxystate' 'Wi-Fi' 'off'"
        );
        assert_eq!(as_quote(r#"a"b\c"#), r#""a\"b\\c""#);
    }
}
