//! The `main` of Windows: the console run, and the proxy as a Windows service. The command line is
//! the one of the win-containers services: no option runs the proxy in the console; `--install`,
//! `--uninstall` and `--start` manage it as a Windows service and exit; `--run-as-service` is what
//! the installed service's command line invokes. `--settings <file>` names the settings file - see
//! `settings::set_settings_file`. Linux and macOS have none of this: their `main` is the console
//! run, with no command line.
//!
//! No `#[tokio::main]` here: the service modes do not run in a runtime of `main`. `--install`,
//! `--uninstall` and `--start` are calls to the Service Control Manager, and `--run-as-service`
//! gives the main thread to the service dispatcher, while the service host builds the runtime the
//! service runs in. The console run builds the runtime `#[tokio::main]` would.

use std::path::{Path, PathBuf};

use win_service_host::cli::{CliArgs, Mode};
use win_service_host::ServiceAccount;

mod file_access;
mod harden;

/// The account `--install` registers the service to run as when `--account` is not given:
/// `NT SERVICE\<service name>`, an account of this service alone with the rights of a plain
/// user. The proxy faces the network, and needs nothing of the machine but its own folders.
const DEFAULT_SERVICE_ACCOUNT: ServiceAccount = ServiceAccount::Virtual;

/// The name `--install` registers the Windows service under when `--name` is not given; what
/// `--start` and `--uninstall` address.
const DEFAULT_SERVICE_NAME: &str = "my-reverse-proxy";

/// What services.msc shows in the Description column when `--install` is run without
/// `--description`. The service host requires one: a blank line there tells whoever looks at the
/// machine nothing about what the process is.
const DEFAULT_SERVICE_DESCRIPTION: &str =
    "my-reverse-proxy: reverse proxy for http, https, http/2, websocket and tcp endpoints, with \
     ssh and gateway tunnels to the upstreams. The settings file is named in the command line of \
     the service (--settings).";

pub fn main() {
    let args = match win_service_host::cli::parse_args(crate::app::APP_NAME, DEFAULT_SERVICE_NAME)
    {
        Ok(args) => args,
        Err(usage) => {
            eprintln!("{usage}");
            std::process::exit(2);
        }
    };

    let result = match args.mode {
        Mode::Console => console(args.settings.as_deref()),
        Mode::Install => install(&args),
        Mode::Uninstall => win_service_host::uninstall(&args.name),
        Mode::Start => win_service_host::start(&args.name),
        Mode::RunAsService => run_as_service(args),
    };

    if let Err(err) = result {
        eprintln!("{err}");
        std::process::exit(1);
    }
}

/// No option: the console run, as on Linux - here with the settings file `--settings` names.
fn console(settings_file: Option<&str>) -> Result<(), String> {
    harden::harden_process().map_err(|err| format!("Can not start. {err}"))?;

    if let Some(settings_file) = settings_file {
        crate::settings::set_settings_file(settings_file)
            .map_err(|err| format!("Can not start. {err}"))?;
    }

    let runtime = tokio::runtime::Runtime::new().expect("Can not build the tokio runtime");
    runtime.block_on(crate::console_main())
}

/// `--install`: registers this exe with the Service Control Manager - auto-start at boot,
/// restart-on-failure, a command line with `--run-as-service` and the settings file. The settings
/// file is required here, as `--settings` or as `settings.yaml` next to the exe: a service does
/// not run as you, and the profile folder of its account holds nobody's `.my-reverse-proxy`, so
/// without a file named at install time the service would start and find no settings.
///
/// Before that, the folders the service takes its exe, its settings and its keys from are
/// checked: one which a plain user can write to is a way to the rights of the service, and the
/// install is refused. After it, the account of the service is given these folders.
fn install(args: &CliArgs) -> Result<(), String> {
    let settings_near_exe = win_service_host::cli::resolve_settings_file_near_exe();

    let settings_file = match args.settings.as_deref() {
        Some(file) => std::fs::canonicalize(file)
            .map_err(|err| format!("settings file '{file}' is not readable: {err}"))?,
        None => settings_near_exe.clone().ok_or_else(|| {
            "--install needs the settings file: --settings <file>, or a settings.yaml next to the \
             exe. The service does not run as you, so the .my-reverse-proxy of your profile \
             would not be read. The folder of the file named is what a leading ~ in the \
             settings stands for."
                .to_string()
        })?,
    };

    let exe = std::env::current_exe()
        .map_err(|err| format!("Can not determine the path of this exe: {err}"))?;

    let settings_folder = folder_of(&settings_file)?;
    let exe_folder = folder_of(&exe)?;

    check_access(&settings_folder, &settings_file, &exe_folder, &exe)?;
    check_folders_above(&folders_to_keep_in_place(&settings_folder, &exe_folder, &exe)?)?;

    let account = args.account.unwrap_or(DEFAULT_SERVICE_ACCOUNT);

    win_service_host::install(win_service_host::InstallSpec {
        account,
        name: &args.name,
        description: args
            .description
            .as_deref()
            .unwrap_or(DEFAULT_SERVICE_DESCRIPTION),
        settings: args.settings.as_deref(),
        settings_near_exe,
    })?;

    if let Some(account) = account.account_name(&args.name) {
        grant_folders(account.as_str(), &settings_folder, &exe_folder);
    }

    Ok(())
}

/// The folder of a file, without the verbatim prefix `canonicalize` gives a path - `icacls` and
/// a reader of the message take `C:\proxy`, not `\\?\C:\proxy`.
fn folder_of(file: &Path) -> Result<PathBuf, String> {
    let folder = file
        .parent()
        .ok_or_else(|| format!("{} is not in a folder", file.display()))?;

    let folder = folder.to_string_lossy();

    Ok(PathBuf::from(match folder.strip_prefix(r"\\?\UNC\") {
        Some(rest) => format!(r"\\{rest}"),
        None => folder.strip_prefix(r"\\?\").unwrap_or(&folder).to_string(),
    }))
}

/// Refuses folders and files a plain account can change, with the commands which close them;
/// warns about a settings folder a plain account can read - the key files are in it.
fn check_access(
    settings_folder: &Path,
    settings_file: &Path,
    exe_folder: &Path,
    exe: &Path,
) -> Result<(), String> {
    let mut open_folders: Vec<&Path> = Vec::new();
    let mut problems = String::new();

    for (folder, file) in [(settings_folder, settings_file), (exe_folder, exe)] {
        let mut writers = file_access::read(folder)?.findings().writers;
        for writer in file_access::read(file)?.findings().writers {
            if !writers.contains(&writer) {
                writers.push(writer);
            }
        }

        if !writers.is_empty() && !open_folders.contains(&folder) {
            open_folders.push(folder);
            problems.push_str(&format!(
                "  {} can be changed by: {}\n",
                folder.display(),
                writers.join(", ")
            ));
        }
    }

    if !open_folders.is_empty() {
        let mut commands = String::new();
        for folder in open_folders {
            commands.push_str(&close_folder_commands(folder));
        }

        return Err(format!(
            "--install is refused: the service takes its exe, its settings and its keys from \
             folders which accounts other than the system and the administrators can change - \
             whoever changes them runs what they like with the rights of the service.\n\
             {problems}\
             Close them, in an elevated prompt, and install again:\n{commands}"
        ));
    }

    let readers = file_access::read(settings_folder)?.findings().readers;
    if !readers.is_empty() {
        println!(
            "WARNING: {} can be read by: {}. Key files kept there are open to them; the secure \
             store is encrypted. To close the folder:\n{}",
            settings_folder.display(),
            readers.join(", "),
            close_folder_commands(settings_folder)
        );
    }

    Ok(())
}

/// The folders which have to stay where they are: the ones of the settings and of the exe, and
/// the folder the exe is really in when its path goes through a link - the service is started
/// by the path, and what the path leads to is what runs.
fn folders_to_keep_in_place(
    settings_folder: &Path,
    exe_folder: &Path,
    exe: &Path,
) -> Result<Vec<PathBuf>, String> {
    let real_exe = std::fs::canonicalize(exe)
        .map_err(|err| format!("the exe {} is not readable: {err}", exe.display()))?;

    let mut folders = vec![settings_folder.to_path_buf()];
    for folder in [exe_folder.to_path_buf(), folder_of(&real_exe)?] {
        if !folders.contains(&folder) {
            folders.push(folder);
        }
    }

    Ok(folders)
}

/// The folders above `folder`, up to the root of its drive.
fn folders_above(folder: &Path) -> Vec<&Path> {
    folder
        .ancestors()
        .skip(1)
        .filter(|above| !above.as_os_str().is_empty())
        .collect()
}

/// Refuses folders of the service which a plain account can move away: one who can rename a
/// folder above puts a folder of their own, with their exe and their settings, at the path the
/// service is started from - the closed folder moves with its parent, and its access list is
/// not asked.
fn check_folders_above(folders: &[PathBuf]) -> Result<(), String> {
    let mut checked: Vec<&Path> = Vec::new();
    let mut problems = String::new();

    for folder in folders {
        for above in folders_above(folder) {
            if checked.contains(&above) {
                continue;
            }
            checked.push(above);

            let movers = file_access::read(above)?.movers(above.parent().is_none());
            if !movers.is_empty() {
                problems.push_str(&format!(
                    "  {} - by: {}\n",
                    above.display(),
                    movers.join(", ")
                ));
            }
        }
    }

    if problems.is_empty() {
        return Ok(());
    }

    Err(format!(
        "--install is refused: a folder above the folders of the service can be renamed, or \
         have what is in it renamed, by accounts other than the system and the administrators \
         - whoever does it puts their own exe and settings at the path the service is started \
         from.\n\
         {problems}\
         Put the exe and the settings where only the administrators change the folders above \
         - a folder of its own in the root of the drive, or in %ProgramFiles% - or take the \
         rights to delete, to change the access and to take ownership from these accounts \
         there, and install again.\n"
    ))
}

/// The owner becomes the administrators; the folder stops inheriting, and is given to the system
/// and the administrators alone; what is in it takes its access from the folder. The SIDs are
/// written out: the names of these groups differ with the language of Windows.
fn close_folder_commands(folder: &Path) -> String {
    let folder = folder.display();
    format!(
        "  icacls \"{folder}\" /setowner *S-1-5-32-544 /T /C\n  \
         icacls \"{folder}\" /inheritance:r /grant:r \"*S-1-5-18:(OI)(CI)F\" \"*S-1-5-32-544:(OI)(CI)F\"\n  \
         icacls \"{folder}\\*\" /reset /T /C\n"
    )
}

/// Gives the account of the service its folders: the settings folder to change - the secure
/// store, the dynamic settings and the logs are written there - and the exe folder to read. A
/// grant which fails does not undo the install: the command is printed for the operator.
fn grant_folders(account: &str, settings_folder: &Path, exe_folder: &Path) {
    let mut grants = vec![(settings_folder, "(OI)(CI)M")];
    if exe_folder != settings_folder {
        grants.push((exe_folder, "(OI)(CI)RX"));
    }

    let icacls = std::env::var("SystemRoot")
        .map(|root| format!(r"{root}\System32\icacls.exe"))
        .unwrap_or_else(|_| "icacls.exe".to_string());

    for (folder, rights) in grants {
        let grant = format!("{account}:{rights}");

        let granted = std::process::Command::new(icacls.as_str())
            .arg(folder)
            .arg("/grant")
            .arg(grant.as_str())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .map(|status| status.success())
            .unwrap_or(false);

        if granted {
            println!("{account} is given {}: {rights}", folder.display());
        } else {
            println!(
                "WARNING: {account} could not be given {}; the service will not start without \
                 it. Run:  icacls \"{}\" /grant \"{grant}\"",
                folder.display(),
                folder.display()
            );
        }
    }
}

/// `--run-as-service`: the service host speaks the SCM protocol and calls back in to bring the
/// proxy up, and to take it down when the SCM says stop.
fn run_as_service(args: CliArgs) -> Result<(), String> {
    // A service starts in C:\Windows\System32. The admin ui (wwwroot\) and the IPv6 country
    // database (ip_v6\) are read relative to the working directory, so make it the folder of the
    // exe - where a release puts them, next to it.
    set_current_dir_to_exe_folder()?;

    let settings_file = args.settings;

    win_service_host::run_as_service(
        args.name,
        Box::new(move || {
            Box::pin(async move {
                // Here, not before the dispatcher: a wrong path fails the start of the service,
                // which the SCM records, instead of a process which ends before it is a service.
                harden::harden_process()?;

                if let Some(settings_file) = settings_file.as_deref() {
                    crate::settings::set_settings_file(settings_file)?;
                }

                crate::start_proxy().await?;

                let shutdown: win_service_host::ShutdownFn =
                    Box::new(|| Box::pin(crate::stop_proxy()));

                Ok(shutdown)
            })
        }),
    )
}

fn set_current_dir_to_exe_folder() -> Result<(), String> {
    let exe = std::env::current_exe()
        .map_err(|err| format!("Can not determine the path of this exe: {err}"))?;

    let folder = exe
        .parent()
        .ok_or_else(|| format!("The exe {} is not in a folder", exe.display()))?;

    std::env::set_current_dir(folder).map_err(|err| {
        format!(
            "Can not make {} the working directory: {err}",
            folder.display()
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_folders_above_end_with_the_root_of_the_drive() {
        assert_eq!(
            folders_above(Path::new(r"C:\tools\proxy")),
            vec![Path::new(r"C:\tools"), Path::new(r"C:\")]
        );
        assert!(folders_above(Path::new(r"C:\")).is_empty());
    }

    #[test]
    fn a_folder_in_the_folder_of_windows_stays_in_place() {
        let windows = std::env::var("SystemRoot").unwrap();
        let folder = Path::new(windows.as_str()).join("System32");

        assert_eq!(check_folders_above(&[folder]), Ok(()));
    }

    /// The temp folder of a user is theirs to rename, whatever a folder made in it is closed to.
    #[test]
    fn a_folder_in_the_profile_of_a_user_is_refused() {
        let folder = std::env::temp_dir().join("my-reverse-proxy-service");

        let err = check_folders_above(&[folder]).unwrap_err();
        assert!(err.contains("--install is refused"), "{err}");
    }
}
