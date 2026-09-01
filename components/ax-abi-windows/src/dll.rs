//! Loading the libraries an image imports.
//!
//! On Windows the loader lives in ntdll: it walks an image's import table,
//! maps every library named there, and resolves each entry against that
//! library's exports (`LdrpLoadDll` and `LdrpSnapModule`; Wine's
//! `dlls/ntdll/loader.c`). There is no ntdll here, so this package does the
//! same walk before the program runs. A library that is part of the system -
//! kernel32, and the api-set names that forward to it - is not a file at all:
//! its entries bind to synthesized stubs ([`crate::thunk`]). Everything else is
//! found the way Windows finds it, beside the program first and then in the
//! system directory, and placed after the program at the next free page.

use alloc::{
    format,
    string::{String, ToString},
    vec,
    vec::Vec,
};

use ax_binfmt::{
    AbiError, AbiResult, LoadEnv,
    pe::{self, ExportTarget, ImportedSymbol, PeInfo},
};

use crate::{
    image_extent, page_up,
    thunk::{self, STUB_LEN},
    win32::Win32Call,
};

/// Where Windows keeps the libraries every program shares.
const SYSTEM_DIR: &str = "/windows/system32";

/// How many forwarders may chain before the walk is called a loop.
const FORWARD_LIMIT: u8 = 8;

/// One image in the process: the program, or a library it reached.
pub struct Module {
    /// Its name as imports spell it, lowered, so lookups ignore case as the
    /// loader does.
    pub name: String,
    /// Where it was found.
    pub path: String,
    pub pe: PeInfo,
    /// The whole file.
    pub bytes: Vec<u8>,
    /// Where it is placed.
    pub base: u64,
    /// Address table entries to write before its sections are mapped.
    pub binds: Vec<(u32, u64)>,
    /// Single words to write likewise: the TLS slot a module's index takes.
    pub words: Vec<(u32, u32)>,
}

/// Everything a program needs mapped before it starts.
pub struct Linked {
    /// The program first, then every library it reached in the order found,
    /// which is also the order they are placed in memory.
    pub modules: Vec<Module>,
    /// Where the stubs go: the page after the last module.
    pub stubs_va: u64,
    /// The stubs, one per distinct system function imported.
    pub stubs: Vec<u8>,
    /// Where `ExitProcess`'s stub is. It is always among them, because the
    /// startup sequence ends the process through it whether or not the
    /// program imports it.
    pub exit_stub: u64,
}

/// Reach every library the program needs and resolve every import in the set.
///
/// Nothing is mapped here, so a program whose libraries cannot all be found or
/// whose imports cannot all be resolved is refused while the host still has
/// the space it came with. `path` is where the program was found; its
/// directory is searched first, as Windows does.
pub fn link(pe: PeInfo, bytes: Vec<u8>, path: &str, env: &mut dyn LoadEnv) -> AbiResult<Linked> {
    let app_dir = dir_of(path).to_string();
    let program = Module {
        name: file_name(path).to_ascii_lowercase(),
        path: path.to_string(),
        base: pe.image_base,
        binds: Vec::new(),
        words: Vec::new(),
        pe,
        bytes,
    };
    let mut next = page_up(program.base + image_extent(&program.pe, &program.bytes));
    let mut modules = vec![program];

    // Breadth first, each library once: one reached by two routes is one
    // module, as it is one file.
    let mut at = 0;
    while at < modules.len() {
        for lib in libraries(&modules[at]) {
            if is_system(&lib) || modules.iter().any(|m| m.name == lib) {
                continue;
            }
            let (path, bytes) = find(&lib, &app_dir, env)?;
            let pe = pe::parse(&bytes).ok_or(AbiError::MalformedImage)?;
            if !pe.pe64 {
                return Err(AbiError::Unsupported);
            }
            let module = Module {
                name: lib,
                path,
                base: next,
                binds: Vec::new(),
                words: Vec::new(),
                pe,
                bytes,
            };
            next = page_up(next + image_extent(&module.pe, &module.bytes));
            modules.push(module);
        }
        at += 1;
    }
    let stubs_va = next;

    let mut calls: Vec<Win32Call> = Vec::new();
    for at in 0..modules.len() {
        let mut binds = Vec::new();
        let pe = modules[at].pe;
        if let Some(imports) = pe.imports(&modules[at].bytes) {
            for import in imports {
                let lib = canonical(import.library);
                let value = match resolve(&modules, &lib, import.symbol, 0)? {
                    Resolved::At(va) => va,
                    Resolved::Stub(call) => {
                        stubs_va + (slot_of(&mut calls, call) * STUB_LEN) as u64
                    }
                };
                binds.push((import.thunk, value));
            }
        }
        modules[at].binds = binds;
    }

    let exit_stub = stubs_va + (slot_of(&mut calls, Win32Call::EXIT_PROCESS) * STUB_LEN) as u64;
    let mut stubs = vec![0u8; calls.len() * STUB_LEN];
    for (slot, call) in calls.iter().enumerate() {
        stubs[slot * STUB_LEN..(slot + 1) * STUB_LEN].copy_from_slice(&thunk::stub(*call));
    }
    Ok(Linked {
        modules,
        stubs_va,
        stubs,
        exit_stub,
    })
}

/// The order libraries are initialized in: each after everything it depends
/// on, the program's own dependencies last, the program itself not at all -
/// its entry is where the process starts once the libraries are ready. This is
/// `process_attach` walking the dependency graph post-order.
pub fn init_order(modules: &[Module]) -> Vec<usize> {
    fn visit(modules: &[Module], at: usize, seen: &mut [bool], order: &mut Vec<usize>) {
        if seen[at] {
            return;
        }
        seen[at] = true;
        for lib in libraries(&modules[at]) {
            if let Some(dep) = modules.iter().position(|m| m.name == lib) {
                visit(modules, dep, seen, order);
            }
        }
        if at != 0 {
            order.push(at);
        }
    }
    let mut order = Vec::new();
    let mut seen = vec![false; modules.len()];
    visit(modules, 0, &mut seen, &mut order);
    order
}

/// The module an import's library name really means.
///
/// Windows resolves api-set names through the apiset schema. The two families
/// a C runtime and CPython reach for are stable enough to name directly: the
/// core sets are kernel32's exports, and the crt sets are ucrtbase's.
pub fn canonical(library: &str) -> String {
    let lower = library.to_ascii_lowercase();
    if lower.starts_with("api-ms-win-core-") || lower == "kernelbase.dll" {
        "kernel32.dll".to_string()
    } else if lower.starts_with("api-ms-win-crt-") {
        "ucrtbase.dll".to_string()
    } else {
        lower
    }
}

/// Whether a library is served by this package rather than loaded from a file.
pub fn is_system(name: &str) -> bool {
    name == "kernel32.dll"
}

/// The whole of the file the host currently holds as the image.
pub(crate) fn read_all(env: &mut dyn LoadEnv) -> AbiResult<Vec<u8>> {
    let len = env.image_len() as usize;
    let mut bytes = vec![0u8; len];
    let mut got = 0;
    while got < len {
        match env.read_image(got as u64, &mut bytes[got..])? {
            0 => break,
            n => got += n,
        }
    }
    bytes.truncate(got);
    Ok(bytes)
}

/// Every library a module can lead to: those it imports, and those its own
/// forwarders name, which the loader must have on hand when an entry resolves.
fn libraries(module: &Module) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut add = |lib: String| {
        if !out.contains(&lib) {
            out.push(lib);
        }
    };
    if let Some(imports) = module.pe.imports(&module.bytes) {
        for import in imports {
            add(canonical(import.library));
        }
    }
    if let Some(exports) = module.pe.exports(&module.bytes) {
        for export in exports {
            if let ExportTarget::Forwarder(spec) = export.target
                && let Some((lib, _)) = spec.rsplit_once('.')
            {
                add(canonical(&format!("{lib}.dll")));
            }
        }
    }
    out
}

/// Locate `lib` the way Windows does - beside the program, then in the system
/// directory - and read it whole.
fn find(lib: &str, app_dir: &str, env: &mut dyn LoadEnv) -> AbiResult<(String, Vec<u8>)> {
    let beside = if app_dir.is_empty() {
        lib.to_string()
    } else {
        format!("{app_dir}/{lib}")
    };
    for path in [beside, format!("{SYSTEM_DIR}/{lib}")] {
        if env.interpret(&path).is_ok() {
            return Ok((path, read_all(env)?));
        }
    }
    Err(AbiError::MissingLibrary)
}

/// What an import resolves to.
enum Resolved {
    /// An address in a module that was loaded.
    At(u64),
    /// A system function, served by a stub.
    Stub(Win32Call),
}

/// What `symbol` from `lib` leads to, following forwarders.
///
/// A library exports some entries by ordinal alone; the export walk names only
/// the ones with names, so an import by ordinal finds an entry only if it also
/// has a name.
fn resolve(
    modules: &[Module],
    lib: &str,
    symbol: ImportedSymbol<'_>,
    depth: u8,
) -> AbiResult<Resolved> {
    if is_system(lib) {
        // A synthesized library has names and nothing else.
        let ImportedSymbol::Name(name) = symbol else {
            return Err(AbiError::MissingLibrary);
        };
        return Win32Call::resolve("KERNEL32.dll", name)
            .map(Resolved::Stub)
            .ok_or(AbiError::MissingLibrary);
    }
    let module = modules
        .iter()
        .find(|m| m.name == lib)
        .ok_or(AbiError::MissingLibrary)?;
    let export = module
        .pe
        .exports(&module.bytes)
        .ok_or(AbiError::MissingLibrary)?
        .find(|export| match symbol {
            ImportedSymbol::Name(name) => export.name == name,
            ImportedSymbol::Ordinal(ordinal) => export.ordinal == u32::from(ordinal),
        })
        .ok_or(AbiError::MissingLibrary)?;
    match export.target {
        ExportTarget::Rva(rva) => Ok(Resolved::At(module.base + u64::from(rva))),
        ExportTarget::Forwarder(spec) => {
            if depth >= FORWARD_LIMIT {
                return Err(AbiError::MalformedImage);
            }
            // A forwarder spells the library without its extension, and an
            // entry taken by ordinal as `#n`.
            let (lib, name) = spec.rsplit_once('.').ok_or(AbiError::MalformedImage)?;
            let symbol = match name.strip_prefix('#') {
                Some(n) => {
                    ImportedSymbol::Ordinal(n.parse().map_err(|_| AbiError::MalformedImage)?)
                }
                None => ImportedSymbol::Name(name),
            };
            resolve(
                modules,
                &canonical(&format!("{lib}.dll")),
                symbol,
                depth + 1,
            )
        }
    }
}

fn slot_of(calls: &mut Vec<Win32Call>, call: Win32Call) -> usize {
    match calls.iter().position(|it| *it == call) {
        Some(at) => at,
        None => {
            calls.push(call);
            calls.len() - 1
        }
    }
}

fn file_name(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

fn dir_of(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(dir, _)| dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_set_names_fold_into_the_modules_that_export_them() {
        assert_eq!(canonical("api-ms-win-core-file-l1-1-0.dll"), "kernel32.dll");
        assert_eq!(canonical("KERNELBASE.dll"), "kernel32.dll");
        assert_eq!(canonical("api-ms-win-crt-stdio-l1-1-0.dll"), "ucrtbase.dll");
        // Anything else is itself, lowered as the loader compares names.
        assert_eq!(canonical("PYTHON313.dll"), "python313.dll");
        assert!(is_system(&canonical("KERNEL32.dll")));
        assert!(!is_system(&canonical("ucrtbase.dll")));
    }

    #[test]
    fn a_program_path_splits_into_where_to_search_and_what_it_is_called() {
        assert_eq!(dir_of("/app/python.exe"), "/app");
        assert_eq!(file_name("/app/python.exe"), "python.exe");
        // A bare name has no directory of its own; the search starts where
        // the caller is.
        assert_eq!(dir_of("python.exe"), "");
        assert_eq!(file_name("python.exe"), "python.exe");
    }
}
