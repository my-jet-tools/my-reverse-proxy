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

use win_service_host::cli::{CliArgs, Mode};

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
    if let Some(settings_file) = settings_file {
        crate::settings::set_settings_file(settings_file)
            .map_err(|err| format!("Can not start. {err}"))?;
    }

    let runtime = tokio::runtime::Runtime::new().expect("Can not build the tokio runtime");
    runtime.block_on(crate::console_main())
}

/// `--install`: registers this exe with the Service Control Manager - auto-start at boot,
/// restart-on-failure, a command line with `--run-as-service` and the settings file. The settings
/// file is required here, as `--settings` or as `settings.yaml` next to the exe: a service runs as
/// LocalSystem, whose profile folder holds nobody's `.my-reverse-proxy`, so without a file named
/// at install time the service would start and find no settings.
fn install(args: &CliArgs) -> Result<(), String> {
    let settings_near_exe = win_service_host::cli::resolve_settings_file_near_exe();

    if args.settings.is_none() && settings_near_exe.is_none() {
        return Err(
            "--install needs the settings file: --settings <file>, or a settings.yaml next to the \
             exe. The service runs as LocalSystem, whose home directory is not yours, so the \
             .my-reverse-proxy of your profile would not be read. The folder of the file named is \
             what a leading ~ in the settings stands for."
                .to_string(),
        );
    }

    win_service_host::install(win_service_host::InstallSpec {
        name: &args.name,
        description: args
            .description
            .as_deref()
            .unwrap_or(DEFAULT_SERVICE_DESCRIPTION),
        settings: args.settings.as_deref(),
        settings_near_exe,
    })
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
