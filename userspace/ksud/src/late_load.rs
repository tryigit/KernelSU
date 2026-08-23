use anyhow::{Context, Result, anyhow, bail, ensure};
use log::{info, warn};
use rustix::cstr;
use std::process::Command;
use std::thread;
use std::time::Duration;

use crate::module::{handle_updated_modules, prune_modules};
use crate::{assets, defs, init_event, metamodule, restorecon, utils};

const ZYGOTE_STOP_RETRIES: usize = 100;
const ZYGOTE_STOP_RETRY_DELAY: Duration = Duration::from_millis(50);

fn dump_process_info(label: &str) {
    use rustix::process::{getgid, getgroups, getpid, getuid};

    let pid = getpid().as_raw_nonzero();
    let uid = getuid().as_raw();
    let gid = getgid().as_raw();
    let groups: Vec<String> = getgroups()
        .unwrap_or_default()
        .iter()
        .map(|g| g.as_raw().to_string())
        .collect();
    let selinux = std::fs::read_to_string("/proc/self/attr/current")
        .unwrap_or_else(|_| "unknown".to_string());
    let seccomp = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with("Seccomp:"))
                .map(|l| l.trim().to_string())
        })
        .unwrap_or_else(|| "unknown".to_string());

    info!(
        "[{label}] pid={pid}, uid={uid}, gid={gid}, groups=[{}], selinux={}, {seccomp}",
        groups.join(","),
        selinux.trim(),
    );
}

fn zygote_services_stopped() -> bool {
    ["init.svc.zygote", "init.svc.zygote_secondary"]
        .iter()
        .all(|name| utils::getprop(name).is_none_or(|state| state == "stopped"))
}

fn stop_android_services_for_mount() -> Result<()> {
    let status = Command::new("stop")
        .status()
        .context("failed to execute Android stop command")?;
    ensure!(status.success(), "Android stop exited with status {status}");

    for _ in 0..ZYGOTE_STOP_RETRIES {
        if zygote_services_stopped() {
            return Ok(());
        }
        thread::sleep(ZYGOTE_STOP_RETRY_DELAY);
    }

    bail!("zygote services did not stop before metamodule mount synchronization")
}

fn start_android_services() -> Result<()> {
    let status = Command::new("start")
        .status()
        .context("failed to execute Android start command")?;
    ensure!(status.success(), "Android start exited with status {status}");
    Ok(())
}

fn mount_metamodule_without_app_spawn(module_dir: &str) -> Result<()> {
    info!("late-load: stopping Android services before metamodule mount synchronization");
    stop_android_services_for_mount()?;

    let mount_result = metamodule::exec_mount_script(module_dir);
    let start_result = start_android_services();

    match (mount_result, start_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(mount_err), Ok(())) => Err(mount_err).context("metamodule mount synchronization failed"),
        (Ok(()), Err(start_err)) => Err(start_err).context("failed to restart Android services after metamodule mount"),
        (Err(mount_err), Err(start_err)) => Err(anyhow!(
            "metamodule mount synchronization failed: {mount_err:#}; Android service restart also failed: {start_err:#}"
        )),
    }
}

pub fn run(package_name: &String, kmi: Option<String>, allow_shell: bool) -> Result<()> {
    utils::daemonize(false)?;
    info!("late-load command triggered!");
    dump_process_info("late-load start");

    // 1. Check if KernelSU is already loaded
    if ksuinit::has_kernelsu() {
        info!("KernelSU already loaded, skip loading ko");
    } else {
        // 2. Detect current KMI version
        let kmi = kmi.map_or_else(
            || crate::boot_patch::get_current_kmi().context("Failed to detect current KMI version"),
            Ok,
        )?;
        info!("Detected KMI: {kmi}");

        // 3. Get kernelsu.ko from embedded assets
        let ko_name = format!("{kmi}_kernelsu.ko");
        let ko_data = assets::get_asset_data(&ko_name)
            .with_context(|| format!("Failed to get {ko_name} from assets"))?;

        // 4. Load kernelsu.ko from memory with manual relocation
        info!("Loading kernelsu.ko for KMI {kmi}...");
        let params = if allow_shell {
            cstr!("allow_shell=1")
        } else {
            cstr!("")
        };
        ksuinit::load_module(&ko_data, params).context("Failed to load kernelsu.ko")?;
        info!("kernelsu.ko loaded successfully!");
        dump_process_info("after load_module");
    }

    // We need to reset stdin/stdout/stderr; otherwise, sending file descriptors via cmd transactions
    // will be blocked by SELinux because its fsec->sid is still u:r:su:s0 instead of u:r:ksu:s0.
    utils::reset_std()?;

    utils::umask(0);

    if let Err(e) = crate::module_config::clear_all_temp_configs() {
        warn!("clear temp configs failed: {e}");
    }

    utils::install(None, None).context("Failed to install ksud")?;

    // 5. Handle module updates
    if let Err(e) = handle_updated_modules() {
        warn!("handle updated modules failed: {e}");
    }

    if let Err(e) = prune_modules() {
        warn!("prune modules failed: {e}");
    }

    if let Err(e) = restorecon::restorecon() {
        warn!("restorecon failed: {e}");
    }

    // 6. Load SELinux rules
    if crate::module::load_sepolicy_rule().is_err() {
        warn!("load sepolicy.rule failed");
    }

    if let Err(e) = crate::profile::apply_sepolies() {
        warn!("apply root profile sepolicy failed: {e}");
    }

    // 7. Initialize features
    if let Err(e) = crate::feature::init_features() {
        warn!("init features failed: {e}");
    }

    // 8. Execute late-load stage scripts (blocking)
    init_event::run_stage("late-load", true);

    // 9. Load system.prop
    if let Err(e) = crate::module::load_system_prop() {
        warn!("load system.prop failed: {e}");
    }

    // 10. Stop zygote-backed app spawning while the metamodule creates mounts
    // and the kernel isolation list is synchronized from the resulting stack.
    mount_metamodule_without_app_spawn(defs::MODULE_DIR)?;

    // 11. Execute post-mount stage scripts (blocking)
    init_event::run_stage("post-mount", true);

    // 12. Execute service stage scripts (non-blocking)
    init_event::run_stage("service", false);

    // 13. Execute boot-completed stage scripts (non-blocking)
    init_event::run_stage("boot-completed", false);

    // 14. Restart Manager so it gets a fresh ksu fd from the newly loaded kernel module
    info!("Restarting KernelSU Manager {package_name}...");
    let _ = Command::new("am")
        .args(["force-stop", package_name])
        .status();
    let _ = Command::new("am")
        .args([
            "start",
            "-n",
            &format!("{package_name}/me.weishu.kernelsu.ui.MainActivity"),
        ])
        .status();

    Ok(())
}
