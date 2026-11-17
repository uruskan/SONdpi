//! "Mac açılışında başlat": a per-user LaunchAgent that opens the app at login.

use std::io;
use std::path::{Path, PathBuf};

pub const LABEL: &str = "io.github.uruskan.sondpi";

fn plist_path() -> PathBuf {
    let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/tmp"));
    home.join("Library/LaunchAgents").join(format!("{LABEL}.plist"))
}

pub fn is_enabled() -> bool {
    plist_path().is_file()
}

/// The `.app` bundle containing `exe` (`X.app/Contents/MacOS/exe`), if any.
pub fn bundle_of(exe: &Path) -> Option<PathBuf> {
    let macos = exe.parent()?;
    let contents = macos.parent()?;
    let app = contents.parent()?;
    let is_bundle = macos.file_name()? == "MacOS" && contents.file_name()? == "Contents" && app.extension()? == "app";
    is_bundle.then(|| app.to_path_buf())
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

/// The agent: `open -a <bundle>` (so Launch Services starts it like a double click), or the
/// executable itself outside a bundle.
pub fn plist(exe: &Path) -> String {
    let args: Vec<String> = match bundle_of(exe) {
        Some(app) => vec!["/usr/bin/open".into(), "-a".into(), app.display().to_string()],
        None => vec![exe.display().to_string()],
    };
    let args: String = args.iter().map(|a| format!("\t\t<string>{}</string>\n", xml_escape(a))).collect();
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n\
         <plist version=\"1.0\">\n<dict>\n\t<key>Label</key>\n\t<string>{LABEL}</string>\n\
         \t<key>ProgramArguments</key>\n\t<array>\n{args}\t</array>\n\t<key>RunAtLoad</key>\n\t<true/>\n\
         \t<key>LimitLoadToSessionType</key>\n\t<string>Aqua</string>\n</dict>\n</plist>\n"
    )
}

pub fn set_enabled(on: bool) -> io::Result<()> {
    let path = plist_path();
    if on {
        let exe = std::env::current_exe()?;
        if let Some(d) = path.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::write(&path, plist(&exe))
    } else {
        match std::fs::remove_file(&path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_detection() {
        assert_eq!(bundle_of(Path::new("/Applications/SONdpi.app/Contents/MacOS/sondpi")), Some(PathBuf::from("/Applications/SONdpi.app")));
        assert_eq!(bundle_of(Path::new("/x/target/release/sondpi")), None);
    }

    #[test]
    fn plist_contents() {
        let p = plist(Path::new("/Applications/A & B.app/Contents/MacOS/sondpi"));
        assert!(p.contains("<string>/usr/bin/open</string>"));
        assert!(p.contains("<string>/Applications/A &amp; B.app</string>"));
        assert!(p.contains(&format!("<string>{LABEL}</string>")));
        assert!(plist(Path::new("/x/sondpi")).contains("<string>/x/sondpi</string>"));
    }
}
