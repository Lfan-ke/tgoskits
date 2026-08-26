//! Path and symbol compatibility for foreign personalities.
//!
//! Windows and POSIX disagree on path syntax: separators (`\` vs `/`), drive
//! letters (`C:\`), NT prefixes (`\??\`, `\\?\`) and case sensitivity. A foreign
//! personality that reuses `ax-fs` must translate its paths into the POSIX form
//! the VFS expects, and translate results back. This crate is that pure,
//! allocation-only translation layer - it holds no VFS state - so a personality
//! (or the `path-compat` feature of the umbrella crate) can call it at the
//! syscall boundary.
//!
//! The drive-letter convention is fixed: `X:\p` maps to `/x/p` (drive letter as
//! a lowercase top-level directory), which the kernel mounts as it chooses. Case
//! folding is ASCII-only here; full Unicode folding is a VFS lookup concern.

#![no_std]

extern crate alloc;

use alloc::string::String;

/// Translate a Windows/NT path to the POSIX form `ax-fs` expects.
///
/// Strips NT/Win32 long-path prefixes, maps a leading drive letter `X:` to
/// `/x`, and normalizes `\` to `/`. A UNC path (`\\server\share` or
/// `\??\UNC\server\share`) becomes `//server/share`. Relative paths keep their
/// relativity, only swapping separators.
pub fn to_posix(path: &str) -> String {
    let (path, is_unc) = strip_nt_prefix(path);

    // Both UNC spellings collapse to a "//server/share" root.
    let unc_body = if is_unc {
        Some(path)
    } else {
        path.strip_prefix(r"\\")
    };
    if let Some(body) = unc_body {
        let mut out = String::from("//");
        push_normalized(&mut out, body);
        return out;
    }

    // Drive-qualified: "X:\..." or "X:..." -> "/x/...".
    if let Some((drive, rest)) = split_drive(path) {
        let mut out = String::from("/");
        out.push(drive.to_ascii_lowercase());
        // A leading separator in `rest` becomes the "/" after the drive dir;
        // a drive-relative "X:foo" gets one inserted, treated as rooted (the
        // common intent when a personality hands us an absolute path).
        match rest.chars().next() {
            None => {}
            Some('\\') | Some('/') => push_normalized(&mut out, rest),
            Some(_) => {
                out.push('/');
                push_normalized(&mut out, rest);
            }
        }
        return out;
    }

    // Relative or drive-less rooted path: just swap separators.
    let mut out = String::new();
    push_normalized(&mut out, path);
    out
}

/// Translate a POSIX path back to Windows form, the inverse of [`to_posix`] for
/// paths it produced. A leading `/x/` becomes `X:\`; other absolute paths get a
/// `\` root. This is lossy for paths that never had a drive letter.
pub fn to_win(path: &str) -> String {
    if let Some((drive, rest)) = split_posix_drive(path) {
        let mut out = String::new();
        out.push(drive.to_ascii_uppercase());
        out.push_str(":\\");
        push_backslashed(&mut out, rest);
        return out;
    }

    match path.strip_prefix('/') {
        Some(rest) => {
            let mut out = String::from("\\");
            push_backslashed(&mut out, rest);
            out
        }
        None => {
            let mut out = String::new();
            push_backslashed(&mut out, path);
            out
        }
    }
}

/// Compare two paths the way Windows does: case-insensitively (ASCII folding).
/// Full Unicode case folding is left to the VFS.
pub fn eq_ignore_case(a: &str, b: &str) -> bool {
    a.eq_ignore_ascii_case(b)
}

/// Strip an NT (`\??\`) or Win32 (`\\?\`, `\\.\`) long-path/device prefix,
/// reporting whether what remains is the body of a UNC path (`\??\UNC\...`).
fn strip_nt_prefix(path: &str) -> (&str, bool) {
    for prefix in [r"\??\", r"\\?\", r"\\.\"] {
        if let Some(rest) = path.strip_prefix(prefix) {
            return match rest.strip_prefix(r"UNC\") {
                Some(unc) => (unc, true),
                None => (rest, false),
            };
        }
    }
    (path, false)
}

/// Split a leading `X:` drive qualifier, returning `(letter, rest_after_colon)`.
fn split_drive(path: &str) -> Option<(char, &str)> {
    let mut chars = path.chars();
    let letter = chars.next()?;
    (letter.is_ascii_alphabetic() && chars.next() == Some(':')).then(|| (letter, &path[2..]))
}

/// Split a leading `/x` single-letter directory, the POSIX form [`to_posix`]
/// produces for a drive. Requires the letter to be followed by `/` or the end.
fn split_posix_drive(path: &str) -> Option<(char, &str)> {
    let rest = path.strip_prefix('/')?;
    let mut chars = rest.chars();
    let letter = chars.next()?;
    if !letter.is_ascii_alphabetic() {
        return None;
    }
    match chars.next() {
        None => Some((letter, "")),
        Some('/') => Some((letter, chars.as_str())),
        Some(_) => None,
    }
}

/// Append `s` to `out`, turning every `\` into `/`.
fn push_normalized(out: &mut String, s: &str) {
    out.extend(s.chars().map(|c| if c == '\\' { '/' } else { c }));
}

/// Append `s` to `out`, turning every `/` into `\`.
fn push_backslashed(out: &mut String, s: &str) {
    out.extend(s.chars().map(|c| if c == '/' { '\\' } else { c }));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_drive_letters_to_rooted_dirs() {
        assert_eq!(to_posix(r"C:\Windows\System32"), "/c/Windows/System32");
        assert_eq!(to_posix(r"D:\data\file.txt"), "/d/data/file.txt");
    }

    #[test]
    fn strips_nt_and_win32_prefixes() {
        assert_eq!(to_posix(r"\??\C:\Windows"), "/c/Windows");
        assert_eq!(to_posix(r"\\?\C:\Users\x"), "/c/Users/x");
    }

    #[test]
    fn normalizes_relative_and_rooted_paths() {
        assert_eq!(to_posix(r"src\main.rs"), "src/main.rs");
        assert_eq!(to_posix(r"\Windows\notepad.exe"), "/Windows/notepad.exe");
    }

    #[test]
    fn both_unc_spellings_become_double_slash() {
        assert_eq!(to_posix(r"\\server\share\dir"), "//server/share/dir");
        assert_eq!(to_posix(r"\??\UNC\server\share"), "//server/share");
    }

    #[test]
    fn round_trips_drive_paths() {
        assert_eq!(to_win("/c/Windows/System32"), r"C:\Windows\System32");
        assert_eq!(to_win(&to_posix(r"E:\a\b")), r"E:\a\b");
        assert_eq!(to_win("/c"), r"C:\");
    }

    #[test]
    fn case_insensitive_comparison() {
        assert!(eq_ignore_case(r"C:\WINDOWS", r"c:\windows"));
        assert!(!eq_ignore_case("alpha", "beta"));
    }

    #[test]
    fn drive_less_absolute_uses_backslash_root() {
        assert_eq!(to_win("/Windows/notepad.exe"), r"\Windows\notepad.exe");
    }

    #[test]
    fn translates_typical_program_paths() {
        // Paths a real Windows program hands the loader/VFS, spaces and all.
        assert_eq!(
            to_posix(r"C:\Program Files\App\app.exe"),
            "/c/Program Files/App/app.exe"
        );
        assert_eq!(
            to_posix(r"C:\Windows\System32\kernel32.dll"),
            "/c/Windows/System32/kernel32.dll"
        );
        assert_eq!(
            to_posix(r"\??\C:\Users\me\AppData\file.txt"),
            "/c/Users/me/AppData/file.txt"
        );
        // A device path keeps its single-root shape after prefix stripping.
        assert_eq!(to_posix(r"\??\NUL"), "NUL");
    }
}
