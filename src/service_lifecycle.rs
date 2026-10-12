//! Identity-bound service callbacks. The transaction owner orders callbacks and gates native enrollment.
use crate::{
    native_guard::ScopePurpose,
    process_scope::{self, CommandSpec, OwnedProcess, ProcessIdentity, ProcessState},
    restore_qualification::{self, AuthorizedPermissions, QualificationPlan, QualificationState},
};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    cell::RefCell,
    collections::BTreeMap,
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    rc::Rc,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceRole {
    Studio,
    Omlx,
}

/// The native binding has fixed names/port, not user-selected exclusions.
/// CPU probes are explicit fixtures and can never authorize native work.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AbsenceBinding {
    Native,
    Cpu { probe: CommandSpec, executable_root: PathBuf },
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AbsenceState {
    Absent,
    Present,
    Unavailable,
}

#[derive(Clone, Debug, Serialize)]
pub struct AbsenceObservation {
    pub state: AbsenceState,
    pub private_qualification: &'static str,
    pub scope: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnmanagedAcknowledgement {
    AcceptUnverifiedOmlx,
}

#[derive(Clone, Debug, Serialize)]
pub struct UnmanagedObservation {
    pub state: &'static str,
    pub policy: &'static str,
    pub scope: &'static str,
    pub acknowledgement: UnmanagedAcknowledgement,
    pub purpose: ScopePurpose,
    pub private_qualification: &'static str,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ServiceSpec {
    OwnedCpu {
        role: ServiceRole,
        command: CommandSpec,
        restore_command: CommandSpec,
        gui_command: Option<CommandSpec>,
    },
    StudioLaunchd {
        target: String,
        plist: PathBuf,
        expected: ProcessIdentity,
    },
    Omlx {
        gui: ProcessIdentity,
        gui_group_members: Vec<ProcessIdentity>,
        backend: ProcessIdentity,
        launcher: CommandSpec,
        health_address: SocketAddr,
        qualification: Box<QualificationPlan>,
    },
    OmlxAbsent {
        binding: AbsenceBinding,
    },
    OmlxUnmanaged {
        purpose: ScopePurpose,
        acknowledgement: UnmanagedAcknowledgement,
    },
}
impl ServiceSpec {
    pub fn role(&self) -> ServiceRole {
        match self {
            Self::OwnedCpu { role, .. } => *role,
            Self::StudioLaunchd { .. } => ServiceRole::Studio,
            Self::Omlx { .. } | Self::OmlxAbsent { .. } | Self::OmlxUnmanaged { .. } => ServiceRole::Omlx,
        }
    }
    /// Pure validation: never opens a path, probes a PID, or reads the environment.
    pub fn validate(&self, purpose: ScopePurpose) -> Result<()> {
        match self {
            Self::OmlxUnmanaged { purpose: bound, .. } => {
                ensure!(*bound == purpose, "unmanaged oMLX purpose mismatch");
            }
            Self::OmlxAbsent { binding } => match binding {
                AbsenceBinding::Native => ensure!(
                    purpose == ScopePurpose::Native,
                    "native absence probes denied in CPU scope"
                ),
                AbsenceBinding::Cpu { probe, executable_root } => {
                    ensure!(purpose == ScopePurpose::Cpu, "CPU absence cannot authorize native work");
                    probe.validate()?;
                    ensure!(*executable_root == probe.cwd.join("absence-bin"), "CPU executable binding must be fixture-local");
                }
            },
            Self::OwnedCpu {
                role,
                command,
                restore_command,
                gui_command,
            } => {
                ensure!(
                    purpose == ScopePurpose::Cpu,
                    "CPU services cannot authorize native maintenance"
                );
                command.validate()?;
                restore_command.validate()?;
                if let Some(gui) = gui_command {
                    gui.validate()?;
                }
                ensure!(
                    (*role == ServiceRole::Omlx) == gui_command.is_some(),
                    "only CPU oMLX requires an owned GUI actor"
                );
            }
            Self::StudioLaunchd {
                target,
                plist,
                expected,
            } => {
                ensure!(
                    purpose == ScopePurpose::Native,
                    "live Studio denied in CPU scope"
                );
                let prefix = format!("gui/{}/", expected.uid);
                let label = target
                    .strip_prefix(&prefix)
                    .context("Studio target must bind expected UID")?;
                ensure!(
                    !label.is_empty()
                        && label.len() <= 256
                        && label
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b)),
                    "invalid launchd label"
                );
                ensure!(
                    plist.is_absolute() && plist.as_os_str().len() <= 4096,
                    "absolute opaque plist reference required"
                );
                validate_identity(expected)?;
            }
            Self::Omlx {
                gui,
                gui_group_members,
                backend,
                launcher,
                health_address,
                qualification,
            } => {
                ensure!(
                    purpose == ScopePurpose::Native,
                    "live oMLX denied in CPU scope"
                );
                qualification.validate()?;
                ensure!(
                    backend.pgid == backend.pid
                        && backend.sid == backend.pid as i32
                        && gui.pgid != backend.pgid,
                    "independent GUI/backend process groups and session-root backend required"
                );
                ensure!(
                    !gui_group_members.is_empty() && gui_group_members.len() <= 256,
                    "bounded reviewed GUI group membership required"
                );
                let mut seen = std::collections::BTreeSet::new();
                for member in gui_group_members {
                    validate_identity(member)?;
                    ensure!(
                        member.pgid == gui.pgid && member.uid == gui.uid && seen.insert(member.pid),
                        "invalid/duplicate reviewed GUI group member"
                    );
                }
                ensure!(
                    gui_group_members
                        .iter()
                        .any(|member| member.same_process(gui)),
                    "reviewed GUI group must include exact GUI root"
                );
                validate_identity(gui)?;
                validate_identity(backend)?;
                ensure!(gui.pid != backend.pid, "GUI/backend identities must differ");
                launcher.validate()?;
                restore_qualification::validate_restore_environment(&launcher.environment)?;
                ensure!(
                    launcher.cwd == backend.cwd && gui.uid == backend.uid,
                    "restore cwd and GUI/backend owner must match enrolled service"
                );
                ensure!(launcher.args == ["serve"], "exact oMLX serve argv required");
                ensure!(
                    launcher.executable == qualification.bundle_contents.join("MacOS/omlx-cli"),
                    "launcher does not bind qualified bundle"
                );
                ensure!(
                    *health_address == "127.0.0.1:8000".parse::<SocketAddr>()?,
                    "exact qualified loopback health endpoint required"
                );
            }
        }
        Ok(())
    }
    fn unmanaged_observation(&self) -> Option<UnmanagedObservation> {
        match self {
            Self::OmlxUnmanaged { purpose, acknowledgement } => Some(UnmanagedObservation {
                state: "unverified",
                policy: "unmanaged",
                scope: "oMLX excluded from lifecycle authority; GPU exclusivity unverified",
                acknowledgement: *acknowledgement,
                purpose: *purpose,
                private_qualification: "not_applicable",
            }),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ActorDisposition {
    pub kind: String,
    pub pid: u32,
    pub identity: Option<ProcessIdentity>,
    pub intermediate_pid: Option<u32>,
    pub intermediate_identity: Option<ProcessIdentity>,
    pub intermediate_reaped: bool,
    pub intermediate_status: Option<i32>,
    pub launch_record: CommandSpec,
    pub settlement: Option<process_scope::Settlement>,
    pub complete: bool,
    pub known_absent: bool,
    pub failure: Option<String>,
    pub descendant_uncertainty: Option<String>,
}

/// An enrolled recovery slot starts at first use and can never be extended.
pub struct RecoveryBudget {
    span: Duration,
    ceiling: Instant,
    deadline: Option<Instant>,
    actors: Vec<ActorDisposition>,
    retained: Vec<OwnedProcess>,
    pending: Vec<(OwnedProcess, usize)>,
}
impl RecoveryBudget {
    pub fn new(span: Duration, ceiling: Instant) -> Self {
        Self {
            span,
            ceiling,
            deadline: None,
            actors: Vec::new(),
            retained: Vec::new(),
            pending: Vec::new(),
        }
    }
    pub fn deadline(&mut self) -> Instant {
        *self
            .deadline
            .get_or_insert_with(|| cap(self.ceiling, self.span))
    }
    pub fn observations(&self) -> &[ActorDisposition] {
        &self.actors
    }
    pub fn complete(&self) -> bool {
        self.actors.iter().all(|actor| actor.complete)
    }
}

pub struct RecoveryControl<'a> {
    pub budget: Rc<RefCell<RecoveryBudget>>,
    tick: &'a mut dyn FnMut() -> Result<()>,
    defer_cleanup: bool,
}
impl<'a> RecoveryControl<'a> {
    pub fn new(
        budget: Rc<RefCell<RecoveryBudget>>,
        tick: &'a mut dyn FnMut() -> Result<()>,
    ) -> Self {
        Self {
            budget,
            tick,
            defer_cleanup: false,
        }
    }
    /// Observation callbacks defer failed helper disposal so the experiment can
    /// first receive cancellation and settle under its own cleanup authority.
    pub fn deferred(
        budget: Rc<RefCell<RecoveryBudget>>,
        tick: &'a mut dyn FnMut() -> Result<()>,
    ) -> Self {
        Self {
            budget,
            tick,
            defer_cleanup: true,
        }
    }
    /// Drain only actors whose cleanup has not been attempted. Failed attempted
    /// settlements remain retained, and this never resets the shared deadline.
    pub fn finish_pending(&mut self) -> Result<()> {
        ensure!(
            !self.defer_cleanup,
            "pending disposal requires a normal recovery control"
        );
        let pending = std::mem::take(&mut self.budget.borrow_mut().pending);
        let mut failures = Vec::new();
        for (actor, index) in pending {
            if let Err(error) = self.dispose(actor, index) {
                failures.push(format!("{error:#}"));
            }
        }
        ensure!(
            failures.is_empty(),
            "pending helper cleanup: {}",
            failures.join("; ")
        );
        Ok(())
    }
    pub fn deadline(&mut self) -> Instant {
        self.budget.borrow_mut().deadline()
    }
    pub fn complete(&self) -> bool {
        self.budget.borrow().complete()
    }
    pub fn observations(&self) -> Vec<ActorDisposition> {
        self.budget.borrow().actors.clone()
    }
    fn enroll_actor(&mut self, actor: &OwnedProcess, spec: &CommandSpec, kind: &str) -> usize {
        let mut budget = self.budget.borrow_mut();
        let index = budget.actors.len();
        budget.actors.push(ActorDisposition {
            kind: kind.into(),
            pid: actor.pid(),
            identity: actor.identity().ok(),
            intermediate_pid: None,
            intermediate_reaped: true,
            intermediate_status: None,
            intermediate_identity: None,
            launch_record: spec.clone(),
            settlement: None,
            complete: false,
            failure: None,
            known_absent: false,
            descendant_uncertainty: None,
        });
        index
    }
    fn settle(&mut self, actor: &mut OwnedProcess, index: usize) -> Result<()> {
        let deadline = self.deadline();
        let result = actor.settle(deadline, Duration::from_millis(100), self.tick);
        let mut budget = self.budget.borrow_mut();
        let entry = &mut budget.actors[index];
        match result {
            Ok(settlement) => {
                entry.complete =
                    settlement.complete && settlement.group_absent && settlement.leader_reaped;
                entry.known_absent = settlement.group_absent && settlement.leader_reaped;
                entry.settlement = Some(settlement);
                ensure!(entry.complete, "cleanup incomplete for pid {}", entry.pid);
                Ok(())
            }
            Err(error) => {
                entry.failure = Some(format!("{error:#}"));
                Err(error)
            }
        }
    }
    fn dispose(&mut self, mut actor: OwnedProcess, index: usize) -> Result<()> {
        if self.defer_cleanup {
            let _ = self.deadline();
            self.budget.borrow_mut().pending.push((actor, index));
            anyhow::bail!("cleanup deferred until experiment cancellation is settled");
        }
        let result = self.settle(&mut actor, index);
        if result.is_err() {
            self.budget.borrow_mut().retained.push(actor);
        }
        result
    }
}

#[derive(Debug)]
pub struct ServiceEnrollmentFailure {
    pub observation: ServiceObservation,
}
impl std::fmt::Display for ServiceEnrollmentFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "service enrollment failed: {}",
            self.observation.failure.as_deref().unwrap_or("unknown")
        )
    }
}
impl std::error::Error for ServiceEnrollmentFailure {}

#[derive(Clone, Debug, Serialize)]
pub struct ServiceObservation {
    pub role: ServiceRole,
    pub root: Option<ProcessIdentity>,
    pub gui: Option<ProcessIdentity>,
    pub inhibited: bool,
    pub restored: bool,
    pub failure: Option<String>,
    pub evidence: Vec<String>,
    pub launch_record: Option<CommandSpec>,
    pub actors: Vec<ActorDisposition>,
    pub absence: Option<AbsenceObservation>,
    pub unmanaged: Option<UnmanagedObservation>,
}

pub struct ServiceHandle {
    spec: ServiceSpec,
    cpu: Option<OwnedProcess>,
    cpu_gui: Option<OwnedProcess>,
    root: Option<ProcessIdentity>,
    gui: Option<ProcessIdentity>,
    qualification: Option<QualificationState>,
    permissions: Option<AuthorizedPermissions>,
    stop_attempted: bool,
    restore_attempted: bool,
    stopped: bool,
    restored: bool,
    failure: Option<String>,
    evidence: Vec<String>,
    launch_record: Option<CommandSpec>,
    actors: Vec<ActorDisposition>,
    absence: Option<AbsenceObservation>,
}
impl ServiceHandle {
    pub(crate) fn is_absent_scope(&self) -> bool {
        matches!(self.spec, ServiceSpec::OmlxAbsent { .. })
    }

    pub(crate) fn is_unmanaged_scope(&self) -> bool {
        matches!(self.spec, ServiceSpec::OmlxUnmanaged { .. })
    }

    pub(crate) fn is_no_control_scope(&self) -> bool {
        self.is_absent_scope() || self.is_unmanaged_scope()
    }

    /// Observation only, including after revocation. A fresh final absence never
    /// clears the sticky failure and never grants control of an appearing actor.
    pub(crate) fn observe_absent_scope(
        &mut self,
        deadline: Instant,
        tick: &mut dyn FnMut() -> Result<()>,
        recovery: &mut RecoveryControl<'_>,
    ) -> Result<()> {
        if self.is_absent_scope() {
            self.observe_absence(deadline, tick, recovery)?;
        }
        Ok(())
    }

    fn observe_absence(
        &mut self,
        deadline: Instant,
        tick: &mut dyn FnMut() -> Result<()>,
        recovery: &mut RecoveryControl<'_>,
    ) -> Result<()> {
        let ServiceSpec::OmlxAbsent { binding } = &self.spec else {
            anyhow::bail!("absence observation requires explicit absence scope");
        };
        let deadline = cap(deadline, Duration::from_millis(500));
        let reading = (|| -> Result<AbsenceState> {
            check(deadline, tick)?;
            let state = match binding {
                AbsenceBinding::Native => {
                    if !process_scope::named_executable_absent(
                        std::path::Path::new("/Applications/oMLX.app/Contents"),
                        deadline, tick,
                    )? {
                        check(deadline, tick)?;
                        return Ok(AbsenceState::Present);
                    }
                    let (status, output) = bounded_command_status(
                        "/usr/bin/pgrep",
                        &["-x".into(), "oMLX|omlx-server".into()],
                        deadline, tick, recovery,
                    )?;
                    let names = absence_probe_state(status, &output);
                    if !matches!(names, AbsenceState::Absent) {
                        check(deadline, tick)?;
                        return Ok(names);
                    }
                    let observation = listener_query(
                        8000, ListenerFields::Pids, false, deadline, tick, recovery,
                    )?;
                    if observation.listeners.is_empty() {
                        AbsenceState::Absent
                    } else {
                        AbsenceState::Present
                    }
                }
                AbsenceBinding::Cpu { probe, .. } => {
                    let (status, output) = bounded_spec_status(probe, deadline, tick, recovery)?;
                    let state = absence_probe_state(status, &output);
                    ensure!(
                        !matches!(state, AbsenceState::Unavailable),
                        "owned CPU absence probe unavailable (exit {status:?}): {output}"
                    );
                    state
                }
            };
            check(deadline, tick)?;
            Ok(state)
        })();
        let (state, result) = match reading {
            Ok(AbsenceState::Absent) => (AbsenceState::Absent, Ok(())),
            Ok(state) => (state, Err(anyhow::anyhow!(
                "named absence not established; no control of candidates authorized"
            ))),
            Err(error) => (AbsenceState::Unavailable, Err(
                error.context("bounded named absence probe unavailable")
            )),
        };
        self.absence = Some(AbsenceObservation {
            state,
            private_qualification: "not_applicable",
            scope: "bounded named absence only; non-atomic, not whole-host idle",
        });
        self.actors = recovery.observations();
        self.record_result(result)
    }
    /// Caller must validate every native specification and transaction authority before enrolling any service.
    pub fn enroll(
        spec: &ServiceSpec,
        purpose: ScopePurpose,
        permissions: Option<&AuthorizedPermissions>,
        deadline: Instant,
        tick: &mut dyn FnMut() -> Result<()>,
        recovery: &mut RecoveryControl<'_>,
    ) -> Result<Self> {
        let start = recovery.budget.borrow().actors.len();
        let result = Self::enroll_inner(spec, purpose, permissions, deadline, tick, recovery);
        result.map_err(|error| {
            if error.downcast_ref::<ServiceEnrollmentFailure>().is_some() {
                return error;
            }
            let actors = recovery.observations();
            let current = &actors[start..];
            let (root, gui) = match spec {
                ServiceSpec::OwnedCpu { .. } => (
                    current
                        .iter()
                        .find(|actor| actor.kind == "CPU enrollment")
                        .and_then(|actor| actor.identity.clone()),
                    current
                        .iter()
                        .find(|actor| actor.kind == "CPU GUI enrollment")
                        .and_then(|actor| actor.identity.clone()),
                ),
                ServiceSpec::StudioLaunchd { expected, .. } => (Some(expected.clone()), None),
                ServiceSpec::Omlx { backend, gui, .. } => {
                    (Some(backend.clone()), Some(gui.clone()))
                }
                ServiceSpec::OmlxAbsent { .. } | ServiceSpec::OmlxUnmanaged { .. } => (None, None),
            };
            ServiceEnrollmentFailure {
                observation: ServiceObservation {
                    role: spec.role(),
                    root,
                    gui,
                    inhibited: false,
                    restored: false,
                    failure: Some(format!("{error:#}")),
                    evidence: Vec::new(),
                    launch_record: if matches!(spec, ServiceSpec::OmlxUnmanaged { .. }) {
                        None
                    } else {
                        current.last().map(|actor| actor.launch_record.clone())
                    },
                    actors: if matches!(spec, ServiceSpec::OmlxUnmanaged { .. }) {
                        Vec::new()
                    } else {
                        actors
                    },
                    absence: matches!(spec, ServiceSpec::OmlxAbsent { .. }).then_some(
                        AbsenceObservation {
                            state: AbsenceState::Unavailable,
                            private_qualification: "not_applicable",
                            scope: "bounded named absence only; non-atomic, not whole-host idle",
                        },
                    ),
                    unmanaged: spec.unmanaged_observation(),
                },
            }
            .into()
        })
    }
    fn enroll_inner(
        spec: &ServiceSpec,
        purpose: ScopePurpose,
        permissions: Option<&AuthorizedPermissions>,
        deadline: Instant,
        tick: &mut dyn FnMut() -> Result<()>,
        recovery: &mut RecoveryControl<'_>,
    ) -> Result<Self> {
        spec.validate(purpose)?;
        if matches!(spec, ServiceSpec::OmlxUnmanaged { .. }) {
            ensure!(permissions.is_none(), "unmanaged oMLX cannot carry private permissions");
        }
        if let ServiceSpec::Omlx { qualification, backend, .. } = spec {
            permissions
                .context("native enrollment denied before probes: missing reviewed X2/X3 authority")?
                .validate_for(qualification, backend)?;
        }
        check(deadline, tick)?;
        let mut cpu = None;
        let mut cpu_gui = None;
        let mut qualification = None;
        if matches!(spec, ServiceSpec::OmlxAbsent { .. } | ServiceSpec::OmlxUnmanaged { .. }) {
            let mut handle = Self {
                spec: spec.clone(),
                cpu: None,
                cpu_gui: None,
                root: None,
                gui: None,
                qualification: None,
                permissions: None,
                stop_attempted: false,
                restore_attempted: false,
                stopped: false,
                restored: false,
                failure: None,
                evidence: Vec::new(),
                launch_record: None,
                actors: Vec::new(),
                absence: None,
            };
            if handle.is_absent_scope() && handle.observe_absence(deadline, tick, recovery).is_err() {
                return Err(ServiceEnrollmentFailure { observation: handle.last_observation() }.into());
            }
            return Ok(handle);
        }
        let (root, gui) = match spec {
            ServiceSpec::OwnedCpu {
                command,
                gui_command,
                ..
            } => {
                let attempt = OwnedProcess::spawn_with_deadline(command, deadline, tick)?;
                let mut actor = attempt.process;
                let enrolled: Result<(ProcessIdentity, Option<ProcessIdentity>)> = (|| {
                    if let Some(failure) = attempt.failure {
                        anyhow::bail!(failure);
                    }
                    stable_owned(&mut actor, deadline, tick)?;
                    let gui = if let Some(command) = gui_command {
                        let attempt = OwnedProcess::spawn_with_deadline(command, deadline, tick)?;
                        cpu_gui = Some(attempt.process);
                        if let Some(failure) = attempt.failure {
                            anyhow::bail!(failure);
                        }
                        let process = cpu_gui.as_mut().unwrap();
                        stable_owned(process, deadline, tick)?;
                        Some(process.identity()?)
                    } else {
                        None
                    };
                    Ok((actor.identity()?, gui))
                })(
                );
                match enrolled {
                    Ok(pair) => {
                        cpu = Some(actor);
                        pair
                    }
                    Err(error) => {
                        let index = recovery.enroll_actor(&actor, command, "CPU enrollment");
                        let cleanup = recovery.dispose(actor, index);
                        if let Some(gui) = cpu_gui.take() {
                            let index = recovery.enroll_actor(
                                &gui,
                                gui_command.as_ref().unwrap(),
                                "CPU GUI enrollment",
                            );
                            let _ = recovery.dispose(gui, index);
                        }
                        return Err(error).context(format!(
                            "CPU enrollment cleanup complete={}: {cleanup:?}",
                            recovery.complete()
                        ));
                    }
                }
            }
            ServiceSpec::StudioLaunchd {
                target,
                plist,
                expected,
            } => {
                let root = process_scope::verify_identity(expected)?;
                ensure!(root.state == ProcessState::Running, "Studio is not running");
                launchctl_registration(target, plist, Some(root.pid), deadline, tick, recovery)?;
                (root, None)
            }
            ServiceSpec::Omlx {
                gui,
                gui_group_members,
                backend,
                launcher,
                qualification: plan,
                ..
            } => {
                // Pure mandatory grant validation has already run before these observations.
                let grant = permissions.context("missing native permissions")?;
                let mut verify = |identity: &ProcessIdentity| {
                    verify_backend_listener(identity, deadline, recovery)
                };
                let gate = restore_qualification::capture_gate(
                    plan,
                    grant,
                    &launcher.environment,
                    deadline,
                    tick,
                    &mut verify,
                )?;
                qualification = Some(QualificationState::preflight_authorized(
                    plan,
                    &launcher.environment,
                    gate,
                    deadline,
                    tick,
                )?);
                let root = process_scope::verify_identity(backend)?;
                let gui = process_scope::verify_identity(gui)?;
                verify_gui_group(&gui, gui_group_members, Some(ProcessState::Running))?;
                ensure!(
                    root.state == ProcessState::Running && gui.state == ProcessState::Running,
                    "oMLX must initially be running"
                );
                (root, Some(gui))
            }
            ServiceSpec::OmlxAbsent { .. } | ServiceSpec::OmlxUnmanaged { .. } => unreachable!(),
        };
        Ok(Self {
            spec: spec.clone(),
            cpu,
            cpu_gui,
            root: Some(root),
            gui,
            qualification,
            permissions: permissions.cloned(),
            stop_attempted: false,
            restore_attempted: false,
            stopped: false,
            restored: false,
            failure: None,
            evidence: Vec::new(),
            launch_record: None,
            actors: recovery.observations(),
            absence: None,
        })
    }
    pub(crate) fn check_named_scope_absence(
        &mut self,
        deadline: Instant,
        tick: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        if let Some(qualification) = self.qualification.as_mut() {
            let observation = qualification.check_named_scope_absence(deadline, tick)?;
            self.evidence
                .push(format!("SC2 {}", serde_json::to_string(&observation)?));
        }
        if self.is_absent_scope() {
            ensure!(self.failure.is_none(), "absence admission was revoked");
        }
        Ok(())
    }
    pub fn stop(
        &mut self,
        deadline: Instant,
        tick: &mut dyn FnMut() -> Result<()>,
        recovery: &mut RecoveryControl<'_>,
    ) -> Result<ServiceObservation> {
        ensure!(!self.is_no_control_scope(), "no-control service has no stop callback");
        let deadline = cap(deadline, Duration::from_secs(120));
        ensure!(
            !self.stop_attempted && self.failure.is_none(),
            "stop is single-attempt and failure-sticky"
        );
        self.stop_attempted = true;
        let result = self.stop_inner(deadline, tick, recovery);
        self.actors = recovery.observations();
        self.record_result(result)?;
        self.stopped = true;
        self.observe_inhibited(deadline, tick, recovery)
    }
    fn stop_inner(
        &mut self,
        deadline: Instant,
        tick: &mut dyn FnMut() -> Result<()>,
        recovery: &mut RecoveryControl<'_>,
    ) -> Result<()> {
        let root = self.root.as_ref().context("missing service root")?;
        check(deadline, tick)?;
        if let Some(gui) = &self.gui {
            let pause_end = cap(deadline, Duration::from_secs(1));
            if let Some(actor) = self.cpu_gui.as_mut() {
                actor.signal(libc::SIGSTOP)?;
            } else {
                if let ServiceSpec::Omlx {
                    gui_group_members, ..
                } = &self.spec
                {
                    verify_gui_group(gui, gui_group_members, Some(ProcessState::Running))?;
                    process_scope::signal_bound(gui, libc::SIGSTOP, false, &mut || {
                        check(pause_end, tick)
                    })?;
                    for member in gui_group_members
                        .iter()
                        .filter(|member| member.pid != gui.pid)
                    {
                        check(pause_end, tick)?;
                        process_scope::signal_bound(member, libc::SIGSTOP, false, &mut || {
                            check(pause_end, tick)
                        })?;
                    }
                }
            }
            wait_state(gui, ProcessState::Stopped, pause_end, tick)?;
            if let ServiceSpec::Omlx {
                gui_group_members, ..
            } = &self.spec
            {
                loop {
                    if verify_gui_group(gui, gui_group_members, Some(ProcessState::Stopped)).is_ok()
                    {
                        break;
                    }
                    pause(pause_end, tick)?;
                }
                self.evidence.push(format!("exact reviewed GUI group paused: {}; no claim about arbitrary escaped GUI descendants; external identity-check-to-signal race remains",serde_json::to_string(gui_group_members)?));
            }
            self.evidence
                .push("same GUI birth identity observed stopped after SIGSTOP".into());
            self.gui = Some(process_scope::verify_identity(gui)?);
        }
        if let Some(actor) = self.cpu.as_mut() {
            let settlement = actor.settle(deadline, Duration::from_millis(100), tick)?;
            ensure!(
                settlement.complete && settlement.group_absent && settlement.leader_reaped,
                "CPU stop incomplete: {:?}",
                settlement
            );
            self.evidence
                .push("owned backend settled and reaped; group absent".into());
            self.cpu = None;
        } else {
            match &self.spec {
                ServiceSpec::StudioLaunchd { target, plist, .. } => {
                    launchctl_registration(
                        target,
                        plist,
                        Some(root.pid),
                        deadline,
                        tick,
                        recovery,
                    )?;
                    process_scope::verify_identity(root)?;
                    launchctl(
                        &["bootout".into(), target.clone()],
                        deadline,
                        tick,
                        recovery,
                    )?;
                    wait_absent(root, deadline, Duration::ZERO, tick)?;
                    launchctl_absent(target, deadline, tick, recovery)?;
                    self.evidence.push(
                        "exact launchd target booted out; original process/group absent".into(),
                    );
                }
                ServiceSpec::Omlx { .. } => {
                    terminate_bound(root, deadline, tick)?;
                    wait_absent(root, deadline, Duration::from_secs(10), tick)?;
                    self.evidence.push(
                        "bound backend TERM60/KILL20; group absent throughout quiet10".into(),
                    );
                }
                _ => unreachable!(),
            }
        }
        Ok(())
    }
    pub fn observe_inhibited(
        &mut self,
        deadline: Instant,
        tick: &mut dyn FnMut() -> Result<()>,
        recovery: &mut RecoveryControl<'_>,
    ) -> Result<ServiceObservation> {
        let deadline = cap(deadline, Duration::from_millis(500));
        if self.is_unmanaged_scope() {
            let result = check(deadline, tick);
            self.record_result(result)?;
            ensure!(self.failure.is_none(), "unmanaged admission was revoked");
            return Ok(self.observation(false));
        }
        if self.is_absent_scope() {
            self.observe_absence(deadline, tick, recovery)?;
            ensure!(self.failure.is_none(), "absence admission was revoked");
            return Ok(self.observation(false));
        }
        let result = (|| {
            ensure!(self.stopped && !self.restored, "service is not inhibited");
            ensure!(
                self.failure.is_none(),
                "inhibition observation failure is sticky"
            );
            ensure!(
                bound_absent(self.root.as_ref().context("missing service root")?)?,
                "backend identity/group reappeared"
            );
            if let Some(gui) = &self.gui {
                ensure!(
                    process_scope::verify_identity(gui)?.state == ProcessState::Stopped,
                    "same GUI is no longer paused"
                );
            }
            match &self.spec {
                ServiceSpec::OwnedCpu { .. } => {}
                ServiceSpec::StudioLaunchd { target, .. } => {
                    launchctl_absent(target, deadline, tick, recovery)?;
                }
                ServiceSpec::Omlx {
                    gui_group_members,
                    health_address,
                    ..
                } => {
                    let gui = self.gui.as_ref().context("missing enrolled GUI identity")?;
                    verify_gui_group(gui, gui_group_members, Some(ProcessState::Stopped))?;
                    listener_absent(*health_address, deadline, tick, recovery)?;
                    verify_gui_group(gui, gui_group_members, Some(ProcessState::Stopped))?;
                }
                ServiceSpec::OmlxAbsent { .. } | ServiceSpec::OmlxUnmanaged { .. } => unreachable!(),
            }
            ensure!(
                Instant::now() < deadline,
                "inhibition observation deadline expired"
            );
            Ok(())
        })();
        self.actors = recovery.observations();
        self.record_result(result)?;
        let mut observation = self.observation(true);
        match &self.spec {
            ServiceSpec::OwnedCpu { .. } => {}
            ServiceSpec::StudioLaunchd { .. } => observation.evidence.push("fresh exact launchd registration absence plus original PID/group absence; polling is non-atomic and does not prove continuous absence".into()),
            ServiceSpec::Omlx { .. } => observation.evidence.push("fresh enrolled-port listener absence and exact reviewed GUI group still stopped plus original PID/group absence; polling is non-atomic and does not attest arbitrary escaped descendants".into()),
            ServiceSpec::OmlxAbsent { .. } | ServiceSpec::OmlxUnmanaged { .. } => unreachable!(),
        }
        Ok(observation)
    }
    pub fn restore(
        &mut self,
        deadline: Instant,
        tick: &mut dyn FnMut() -> Result<()>,
        recovery: &mut RecoveryControl<'_>,
    ) -> Result<ServiceObservation> {
        ensure!(!self.is_no_control_scope(), "no-control service has no restore callback");
        let deadline = cap(deadline, Duration::from_secs(120));
        ensure!(
            self.stopped && !self.restore_attempted && self.failure.is_none(),
            "restore requires inhibition; failure is sticky and no retry is permitted"
        );
        self.restore_attempted = true;
        let result = if recovery.complete() {
            self.restore_inner(deadline, tick, recovery)
        } else {
            Err(anyhow::anyhow!(
                "incomplete helper/detached accounting forbids restore"
            ))
        };
        if result.is_err()
            && let ServiceSpec::OwnedCpu {
                restore_command, ..
            } = &self.spec
            && let Some(actor) = self.cpu.take()
        {
            let index = recovery.enroll_actor(&actor, restore_command, "failed CPU replacement");
            let _ = recovery.dispose(actor, index);
        }
        self.actors = recovery.observations();
        self.record_result(result)?;
        self.restored = true;
        Ok(self.observation(false))
    }
    fn restore_inner(
        &mut self,
        deadline: Instant,
        tick: &mut dyn FnMut() -> Result<()>,
        recovery: &mut RecoveryControl<'_>,
    ) -> Result<()> {
        check(deadline, tick)?;
        self.observe_inhibited(deadline, tick, recovery)?;
        match &self.spec {
            ServiceSpec::OwnedCpu {
                restore_command, ..
            } => {
                self.launch_record = Some(restore_command.clone());
                let attempt = OwnedProcess::spawn_with_deadline(restore_command, deadline, tick)?;
                self.cpu = Some(attempt.process);
                if let Some(failure) = attempt.failure {
                    let actor = self.cpu.take().unwrap();
                    let index = recovery.enroll_actor(&actor, restore_command, "CPU replacement");
                    let cleanup = recovery.dispose(actor, index);
                    anyhow::bail!(
                        "{failure}; cleanup complete={}: {cleanup:?}",
                        recovery.complete()
                    );
                }
                let actor = self.cpu.as_mut().unwrap();
                self.evidence
                    .push(format!("owned replacement launch PID {}", actor.pid()));
                self.root = Some(actor.identity()?);
                stable_owned(actor, deadline, tick)?;
                self.evidence.push("owned CPU replacement survived bounded lifetime observation; not native fidelity evidence".into());
            }
            ServiceSpec::StudioLaunchd { target, plist, .. } => {
                let domain = target.rsplit_once('/').context("invalid launchd target")?.0;
                launchctl(
                    &[
                        "bootstrap".into(),
                        domain.into(),
                        plist.to_string_lossy().into_owned(),
                    ],
                    deadline,
                    tick,
                    recovery,
                )?;
                let new_pid =
                    launchctl_registration(target, plist, None, deadline, tick, recovery)?;
                let previous = self.root.as_ref().context("missing Studio root")?;
                let root = wait_studio_replacement(
                    new_pid, previous, deadline, tick, &mut self.evidence,
                )?;
                self.root = Some(root);
                self.evidence.push(
                    "exact launchd target bootstrapped once; fresh bound replacement observed"
                        .into(),
                );
            }
            ServiceSpec::Omlx {
                launcher,
                health_address,
                ..
            } => {
                self.evidence.push("restore stdin/stdout/stderr preserve /dev/null; console-only diagnostics UNAVAILABLE; no persistent output file or collector".into());
                let qualification = self
                    .qualification
                    .as_mut()
                    .context("missing preflight qualification")?;
                qualification.before_restore(cap(deadline, Duration::from_secs(10)), tick)?;
                let launch_end = cap(deadline, Duration::from_secs(60));
                let old_executable = self.root.as_ref().context("missing backend root")?.executable.clone();
                self.launch_record = Some(launcher.clone());
                qualification.check_named_scope_absence(launch_end, tick)?;
                self.root = Some(launch_detached(launcher, &old_executable, launch_end, tick, recovery)?);
                let health = wait_health(*health_address, launch_end, tick)?;
                let root = process_scope::verify_identity(self.root.as_ref().context("missing backend root")?)?;
                ensure!(
                    root.ppid == 1
                        && root.pgid == root.pid
                        && root.sid == root.pid as i32
                        && root.cwd == launcher.cwd
                        && root.executable == old_executable
                        && root.state == ProcessState::Running,
                    "detached backend identity mismatch"
                );
                let grant = self
                    .permissions
                    .as_ref()
                    .context("missing restore permissions")?;
                let mut verify = |identity: &ProcessIdentity| {
                    verify_backend_listener(identity, deadline, recovery)
                };
                verify(&root)?;
                let mut report = qualification.after_restore_authorized(
                    &health,
                    &root,
                    grant,
                    deadline,
                    tick,
                    &mut verify,
                )?;
                report.record_service_checks(true, true);
                self.evidence.push(serde_json::to_string(&report)?);
                ensure!(
                    report.gui_resume_allowed(true, true),
                    "operational startup AND mandatory fidelity required: {report:?}"
                );
                self.evidence.push("guardian recorded exact launcher argv/cwd/environment; detached PPID1 PGID=SID=PID observed".into());
            }
            ServiceSpec::OmlxAbsent { .. } | ServiceSpec::OmlxUnmanaged { .. } => unreachable!(),
        }
        if let Some(gui) = &self.gui {
            ensure!(
                process_scope::verify_identity(gui)?.state == ProcessState::Stopped,
                "same GUI must remain paused until qualified"
            );
            if let ServiceSpec::Omlx {
                gui_group_members, ..
            } = &self.spec
            {
                verify_gui_group(gui, gui_group_members, Some(ProcessState::Stopped))?;
            }
            let watch = if self.cpu_gui.is_some() {
                Duration::from_millis(250)
            } else {
                Duration::from_secs(20)
            };
            let end = Instant::now()
                .checked_add(watch)
                .context("watch deadline overflow")?;
            ensure!(
                end <= deadline,
                "insufficient GUI watch deadline; GUI remains paused"
            );
            check(deadline, tick)?;
            if let Some(actor) = self.cpu_gui.as_mut() {
                actor.signal(libc::SIGCONT)?;
            } else if let ServiceSpec::Omlx {
                gui_group_members, ..
            } = &self.spec
            {
                for member in gui_group_members
                    .iter()
                    .filter(|member| member.pid != gui.pid)
                {
                    check(deadline, tick)?;
                    process_scope::signal_bound(member, libc::SIGCONT, false, &mut || {
                        check(deadline, tick)
                    })?;
                }
                check(deadline, tick)?;
                process_scope::signal_bound(gui, libc::SIGCONT, false, &mut || {
                    check(deadline, tick)
                })?;
            }
            loop {
                check(deadline, tick)?;
                if let ServiceSpec::Omlx {
                    gui_group_members, ..
                } = &self.spec
                {
                    verify_gui_group(gui, gui_group_members, Some(ProcessState::Running))?;
                }
                ensure!(
                    process_scope::verify_identity(gui)?.state == ProcessState::Running,
                    "GUI failed after resume"
                );
                ensure!(
                    process_scope::verify_identity(self.root.as_ref().context("missing backend root")?)?.state == ProcessState::Running,
                    "backend failed after resume"
                );
                if Instant::now() >= end {
                    break;
                }
                pause(deadline, tick)?;
            }
            self.evidence
                .push("same GUI resumed only after qualified restore; bounded watch passed".into());
            self.gui = Some(process_scope::verify_identity(gui)?);
        }
        Ok(())
    }
    fn record_result(&mut self, result: Result<()>) -> Result<()> {
        if let Err(error) = result {
            if self.failure.is_none() {
                self.failure = Some(format!("{error:#}"));
                if let Some(expected) = &self.gui {
                    match process_scope::verify_identity(expected) {
                        Ok(current) => {
                            self.evidence.push(format!(
                                "GUI state observed on failure: {:?}; no recovery signal sent",
                                current.state
                            ));
                            self.gui = Some(current);
                        }
                        Err(_) => self.evidence.push(
                            "GUI state unavailable on failure; no recovery signal sent".into(),
                        ),
                    }
                }
                if let Some(qualification) = &self.qualification
                    && let Ok(report) = serde_json::to_string(&qualification.report())
                {
                    self.evidence.push(report);
                }
            }
            return Err(error);
        }
        Ok(())
    }
    fn observation(&self, inhibited: bool) -> ServiceObservation {
        ServiceObservation {
            role: self.spec.role(),
            root: self.root.clone(),
            gui: self.gui.clone(),
            inhibited,
            restored: self.restored,
            failure: self.failure.clone(),
            evidence: self.evidence.clone(),
            launch_record: self.launch_record.clone(),
            actors: self.actors.clone(),
            absence: self.absence.clone(),
            unmanaged: self.spec.unmanaged_observation(),
        }
    }
    pub fn last_observation(&self) -> ServiceObservation {
        self.observation(self.stopped && !self.restored && self.failure.is_none())
    }
    /// Disposes only this handle's owned CPU actors; never controls a restored production process.
    pub fn finish_owned_cpu(&mut self, recovery: &mut RecoveryControl<'_>) -> Result<()> {
        if self.is_no_control_scope() {
            return Ok(());
        }
        let ServiceSpec::OwnedCpu {
            command,
            restore_command,
            gui_command,
            ..
        } = &self.spec
        else {
            anyhow::bail!("production service disposal forbidden");
        };
        let backend_command = if self.launch_record.is_some() {
            restore_command
        } else {
            command
        };
        let mut failures = Vec::new();
        for (actor, command) in [
            (self.cpu.take(), Some(backend_command)),
            (self.cpu_gui.take(), gui_command.as_ref()),
        ] {
            if let Some(actor) = actor {
                let index = recovery.enroll_actor(
                    &actor,
                    command.context("owned actor missing launch record")?,
                    "CPU fixture disposal",
                );
                if let Err(error) = recovery.dispose(actor, index) {
                    failures.push(format!("{error:#}"));
                }
            }
        }
        self.actors = recovery.observations();
        if !failures.is_empty() {
            let error = anyhow::anyhow!(failures.join("; "));
            return self.record_result(Err(error));
        }
        Ok(())
    }
}

fn absence_probe_state(status: i32, output: &str) -> AbsenceState {
    if status == 1 && output.is_empty() {
        AbsenceState::Absent
    } else if status == 0 && !output.is_empty()
        && output.lines().all(|line| {
            line.strip_prefix('p').unwrap_or(line).parse::<u32>().is_ok_and(|pid| pid > 1)
        })
    {
        AbsenceState::Present
    } else {
        AbsenceState::Unavailable
    }
}
fn validate_identity(identity: &ProcessIdentity) -> Result<()> {
    ensure!(
        identity.pid > 1
            && identity.pid <= i32::MAX as u32
            && identity.pgid > 1
            && identity.pgid <= i32::MAX as u32
            && identity.sid > 0
            && identity.executable.is_absolute()
            && identity.cwd.is_absolute(),
        "invalid process binding"
    );
    Ok(())
}
fn cap(deadline: Instant, span: Duration) -> Instant {
    std::cmp::min(deadline, Instant::now() + span)
}
fn check(deadline: Instant, tick: &mut dyn FnMut() -> Result<()>) -> Result<()> {
    ensure!(Instant::now() < deadline, "service deadline expired");
    tick()?;
    ensure!(Instant::now() < deadline, "service deadline expired");
    Ok(())
}
fn pause(deadline: Instant, tick: &mut dyn FnMut() -> Result<()>) -> Result<()> {
    check(deadline, tick)?;
    std::thread::sleep(std::cmp::min(
        Duration::from_millis(20),
        deadline.saturating_duration_since(Instant::now()),
    ));
    Ok(())
}

fn studio_replacement_mismatches(current: &ProcessIdentity, previous: &ProcessIdentity) -> u8 {
    u8::from(current.uid != previous.uid)
        | (u8::from(current.executable != previous.executable) << 1)
        | (u8::from(current.cwd != previous.cwd) << 2)
        | (u8::from(current.same_process(previous)
            || (current.pid == previous.pid
                && current.start_seconds == previous.start_seconds
                && current.start_subseconds == previous.start_subseconds)) << 3)
        | (u8::from(current.state != ProcessState::Running) << 4)
}

/// Observe one registered PID through startup; never relaunch or follow a replacement PID.
/// Executable/cwd may transition, but the initially observed kernel instance must not drift.
fn wait_studio_replacement(
    pid: u32,
    previous: &ProcessIdentity,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
    evidence: &mut Vec<String>,
) -> Result<ProcessIdentity> {
    let started = Instant::now();
    let mut first: Option<ProcessIdentity> = None;
    let mut last: Option<ProcessIdentity> = None;
    let mut observations = 0u32;
    let result = (|| {
        loop {
            check(deadline, tick)?;
            let current = process_scope::observe(pid)?.context("registered Studio PID unavailable during startup")?;
            observations += 1;
            let same_instance = first.as_ref().is_none_or(|anchor| {
                current.pid == anchor.pid
                    && current.uid == anchor.uid
                    && current.pgid == anchor.pgid
                    && current.sid == anchor.sid
                    && current.start_seconds == anchor.start_seconds
                    && current.start_subseconds == anchor.start_subseconds
            });
            if first.is_none() {
                first = Some(current.clone());
            }
            let mismatch = studio_replacement_mismatches(&current, previous);
            last = Some(current);
            ensure!(same_instance, "Studio startup process birth/owner/group identity changed");
            ensure!(mismatch & 1 == 0, "Studio replacement UID mismatch");
            ensure!(mismatch & 8 == 0, "Studio replacement is not a fresh process");
            let current = last.as_ref().expect("startup identity recorded");
            ensure!(current.state != ProcessState::Zombie, "Studio replacement exited during startup");
            if mismatch == 0 {
                check(deadline, tick)?;
                return Ok(current.clone());
            }
            pause(deadline, tick)?;
        }
    })();
    let mismatch_fields: Vec<_> = match &last {
        Some(current) => {
            let mismatch = studio_replacement_mismatches(current, previous);
            ["uid", "executable", "cwd", "fresh_process", "running"]
                .into_iter().enumerate()
                .filter_map(|(bit, name)| (mismatch & (1 << bit) != 0).then_some(name))
                .collect()
        }
        None => vec!["pid_unavailable"],
    };
    evidence.push(serde_json::to_string(&serde_json::json!({
        "kind": "studio_replacement_startup_observation",
        "registered_pid": pid,
        "expected_previous": previous,
        "first_observed": first,
        "last_observed": last,
        "last_mismatch_fields": mismatch_fields,
        "observations": observations,
        "elapsed_us": started.elapsed().as_micros(),
        "qualified": result.is_ok(),
        "failure": result.as_ref().err().map(|error| format!("{error:#}")),
        "scope": "one registered PID; bounded read-only startup observation; no lifecycle retry",
    }))?);
    result
}
fn stable_owned(
    actor: &mut OwnedProcess,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    let end = Instant::now() + Duration::from_millis(250);
    ensure!(
        end < deadline,
        "insufficient CPU lifetime observation budget"
    );
    loop {
        check(deadline, tick)?;
        actor.check_membership()?;
        ensure!(
            !actor.exited_unreaped()?,
            "CPU service exited during startup"
        );
        ensure!(
            actor.identity()?.state == ProcessState::Running,
            "CPU service not running"
        );
        if Instant::now() >= end {
            return Ok(());
        }
        pause(deadline, tick)?;
    }
}
fn wait_state(
    expected: &ProcessIdentity,
    state: ProcessState,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    loop {
        check(deadline, tick)?;
        if process_scope::verify_identity(expected)?.state == state {
            return Ok(());
        }
        pause(deadline, tick)?;
    }
}
fn bound_absent(expected: &ProcessIdentity) -> Result<bool> {
    process_scope::bound_absent(expected)
}
fn wait_absent(
    expected: &ProcessIdentity,
    deadline: Instant,
    quiet: Duration,
    tick: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    let mut since = None;
    loop {
        check(deadline, tick)?;
        if bound_absent(expected)? {
            let start = *since.get_or_insert_with(Instant::now);
            if start.elapsed() >= quiet {
                return Ok(());
            }
        } else {
            ensure!(
                since.is_none(),
                "backend group reappeared during quiet interval"
            );
        }
        pause(deadline, tick)?;
    }
}

fn terminate_bound(
    root: &ProcessIdentity,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
) -> Result<()> {
    check(deadline, tick)?;
    process_scope::signal_bound(root, libc::SIGTERM, true, &mut || check(deadline, tick))?;
    let term_end = cap(deadline, Duration::from_secs(60));
    while Instant::now() < term_end && !bound_absent(root)? {
        pause(term_end, tick)?;
    }
    if !bound_absent(root)? {
        check(deadline, tick)?;
        process_scope::signal_bound(root, libc::SIGKILL, true, &mut || check(deadline, tick))?;
        wait_absent(
            root,
            cap(deadline, Duration::from_secs(20)),
            Duration::ZERO,
            tick,
        )?;
    }
    Ok(())
}

/// Executes only the exact system launchctl, with bounded output and guardian-owned lifetime.
fn launchctl(
    args: &[String],
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
    recovery: &mut RecoveryControl<'_>,
) -> Result<String> {
    bounded_command("/bin/launchctl", args, deadline, tick, recovery)
}
fn bounded_command(
    executable: &str,
    args: &[String],
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
    recovery: &mut RecoveryControl<'_>,
) -> Result<String> {
    let (status, output) = bounded_command_status(executable, args, deadline, tick, recovery)?;
    ensure!(
        status == 0,
        "bounded system command failed (output omitted)"
    );
    Ok(output)
}
fn bounded_command_status(
    executable: &str,
    args: &[String],
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
    recovery: &mut RecoveryControl<'_>,
) -> Result<(i32, String)> {
    let spec = CommandSpec {
        executable: PathBuf::from(executable),
        args: args.to_vec(),
        cwd: PathBuf::from("/"),
        environment: BTreeMap::new(),
    };
    bounded_spec_status(&spec, deadline, tick, recovery)
}

#[derive(Clone, Copy)]
enum CapturePolicy {
    Merged,
    StdoutOnly,
}

fn bounded_spec_status(
    spec: &CommandSpec,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
    recovery: &mut RecoveryControl<'_>,
) -> Result<(i32, String)> {
    bounded_spec_read(spec, deadline, tick, recovery, CapturePolicy::Merged, |status, output| {
        Ok((status, output))
    }).map(|(value, _)| value)
}

// Decode before discarding successful accounting, so malformed observations retain
// the exact helper disposition just like execution/cancellation failures.
fn bounded_spec_read<T>(
    spec: &CommandSpec,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
    recovery: &mut RecoveryControl<'_>,
    policy: CapturePolicy,
    decode: impl FnOnce(i32, String) -> Result<T>,
) -> Result<(T, ActorDisposition)> {
    let attempt = OwnedProcess::spawn_with_deadline(spec, deadline, tick)?;
    let mut actor = attempt.process;
    let index = recovery.enroll_actor(&actor, spec, "bounded helper");
    let result = (|| {
        if let Some(failure) = attempt.failure {
            anyhow::bail!(failure);
        }
        let mut output = Vec::new();
        let mut diagnostic = false;
        let mut captured = 0usize;
        loop {
            check(deadline, tick)?;
            // Drain after observing exit so late stderr cannot be mistaken for
            // the empty-output "no listeners" result.
            let exited = actor.exited_unreaped()?;
            for (is_stderr, stream) in [(false, &mut actor.stdout), (true, &mut actor.stderr)] {
                let Some(stream) = stream else { continue };
                loop {
                    let mut bytes = [0u8; 4096];
                    match stream.read(&mut bytes) {
                        Ok(0) => break,
                        Ok(n) => {
                            captured += n;
                            ensure!(captured <= 65536, "bounded command output exceeds bound");
                            if is_stderr && matches!(policy, CapturePolicy::StdoutOnly) {
                                // Raw diagnostics never leave this bounded private capture.
                                diagnostic = true;
                            } else {
                                output.extend_from_slice(&bytes[..n]);
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            if exited {
                break;
            }
            pause(deadline, tick)?;
        }
        let settlement = actor.settle(deadline, Duration::ZERO, tick)?;
        {
            let mut budget = recovery.budget.borrow_mut();
            budget.actors[index].complete =
                settlement.complete && settlement.leader_reaped && settlement.group_absent;
            budget.actors[index].known_absent = settlement.leader_reaped && settlement.group_absent;
            budget.actors[index].settlement = Some(settlement.clone());
        }
        ensure!(settlement.complete, "bounded command settlement failed");
        ensure!(!diagnostic, "listener helper emitted diagnostics (output omitted)");
        let status = settlement.exit_code.context("bounded command exited by signal")?;
        let output = String::from_utf8(output)
            .map_err(|_| anyhow::anyhow!("bounded command output is not UTF-8"))?;
        let value = decode(status, output)?;
        check(deadline, tick)?;
        Ok(value)
    })();
    match result {
        Ok(value) => {
            // Read-only polling may run repeatedly: settled successes have no
            // residual ownership and must not grow the shared receipt history.
            let receipt = recovery.budget.borrow_mut().actors.remove(index);
            Ok((value, receipt))
        }
        Err(error) => {
            let cleanup = if recovery.budget.borrow().actors[index].complete {
                Ok(())
            } else {
                recovery.dispose(actor, index)
            };
            recovery.budget.borrow_mut().actors[index].failure =
                Some(format!("{error:#}; cleanup: {cleanup:?}"));
            Err(error).context(format!(
                "helper pid {} cleanup complete={}: {cleanup:?}",
                recovery.budget.borrow().actors[index].pid,
                recovery.budget.borrow().actors[index].complete
            ))
        }
    }
}

/// A syntactically complete process record returned by the selected-port query.
#[derive(Debug, Serialize)]
pub struct ListenerRecord {
    pub pid: u32,
    pub command: Option<String>,
    pub endpoints: Vec<String>,
}

/// A bounded tool observation, NOT a certificate of complete global visibility.
/// In particular, an empty list cannot establish cross-user listener absence.
#[derive(Debug, Serialize)]
pub struct ListenerObservation {
    pub listeners: Vec<ListenerRecord>,
    pub helper: ActorDisposition,
    pub elapsed_micros: u128,
}

#[derive(Clone, Copy)]
enum ListenerFields {
    Pids,
    Records,
}

/// Read-only all-PID/all-address/all-family TCP LISTEN observation of one port.
/// Uses the same execution, parser and settlement path as service qualification.
/// Caller supplies existing execution/recovery authority; this grants no control
/// over any discovered listener. The observation remains capped at 500 ms.
pub fn observe_tcp_listeners(
    port: u16,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
    recovery: &mut RecoveryControl<'_>,
) -> Result<ListenerObservation> {
    listener_query(port, ListenerFields::Records, true,
        cap(deadline, Duration::from_millis(500)), tick, recovery)
}

fn listener_query(
    port: u16,
    fields: ListenerFields,
    full_command: bool,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
    recovery: &mut RecoveryControl<'_>,
) -> Result<ListenerObservation> {
    ensure!(port != 0, "listener observation requires a port");
    let started = Instant::now();
    // -O disables lsof's potentially blocking-operation children, not the
    // guardian's strict NOTE_FORK, cancellation or settlement requirements.
    let mut args = vec!["-O".into(), "-nP".into()];
    if full_command {
        args.extend(["+c".into(), "0".into()]);
    }
    args.extend([
        format!("-iTCP:{port}"), "-sTCP:LISTEN".into(),
        match fields { ListenerFields::Pids => "-Fp", ListenerFields::Records => "-Fpcn" }.into(),
    ]);
    let spec = CommandSpec {
        executable: "/usr/sbin/lsof".into(),
        args,
        cwd: "/".into(),
        environment: BTreeMap::new(),
    };
    let (listeners, helper) = bounded_spec_read(
        &spec, deadline, tick, recovery, CapturePolicy::StdoutOnly,
        |status, output| parse_listener_output(status, &output, fields, port),
    )?;
    Ok(ListenerObservation { listeners, helper, elapsed_micros: started.elapsed().as_micros() })
}

fn parse_listener_output(
    status: i32,
    output: &str,
    fields: ListenerFields,
    port: u16,
) -> Result<Vec<ListenerRecord>> {
    if status == 1 && output.is_empty() {
        return Ok(Vec::new());
    }
    ensure!(status == 0 && !output.is_empty() && output.ends_with('\n'),
        "invalid listener exit/output combination (output omitted)");
    let mut records: Vec<ListenerRecord> = Vec::new();
    let mut pids = std::collections::BTreeSet::new();
    for line in output.split_terminator('\n') {
        ensure!(!line.is_empty() && !line.chars().any(char::is_control),
            "malformed listener record (output omitted)");
        if let Some(pid) = line.strip_prefix('p') {
            if let Some(previous) = records.last() {
                validate_listener_record(previous, fields)?;
            }
            ensure!(!pid.is_empty() && pid.bytes().all(|b| b.is_ascii_digit()) && !pid.starts_with('0'),
                "malformed listener PID (output omitted)");
            let pid = pid.parse::<u32>()
                .map_err(|_| anyhow::anyhow!("invalid listener PID (output omitted)"))?;
            ensure!(pid > 1 && pid <= i32::MAX as u32 && pids.insert(pid),
                "invalid or duplicate listener PID (output omitted)");
            records.push(ListenerRecord { pid, command: None, endpoints: Vec::new() });
            continue;
        }
        ensure!(matches!(fields, ListenerFields::Records),
            "unexpected listener field (output omitted)");
        let record = records.last_mut().context("listener field precedes PID (output omitted)")?;
        if let Some(command) = line.strip_prefix('c') {
            ensure!(!command.is_empty() && record.command.is_none() && record.endpoints.is_empty(),
                "invalid or duplicate listener command (output omitted)");
            record.command = Some(command.into());
        } else if let Some(endpoint) = line.strip_prefix('n') {
            ensure!(record.command.is_some() && listener_endpoint(endpoint, port)
                && !record.endpoints.iter().any(|old| old == endpoint),
                "invalid or duplicate listener endpoint (output omitted)");
            record.endpoints.push(endpoint.into());
        } else {
            anyhow::bail!("unrecognized listener field (output omitted)");
        }
    }
    validate_listener_record(records.last().context("missing listener record")?, fields)?;
    Ok(records)
}

fn validate_listener_record(record: &ListenerRecord, fields: ListenerFields) -> Result<()> {
    ensure!(matches!(fields, ListenerFields::Pids)
        || (record.command.is_some() && !record.endpoints.is_empty()),
        "incomplete listener record (output omitted)");
    Ok(())
}

fn listener_endpoint(endpoint: &str, port: u16) -> bool {
    let Some((address, number)) = endpoint.rsplit_once(':') else { return false };
    if !number.bytes().all(|byte| byte.is_ascii_digit())
        || number.starts_with('0') || number.parse::<u16>().ok() != Some(port) {
        return false;
    }
    address == "*"
        || address.parse::<std::net::Ipv4Addr>().is_ok()
        || address.strip_prefix('[').and_then(|s| s.strip_suffix(']'))
            .is_some_and(|s| s.parse::<std::net::Ipv6Addr>().is_ok())
}

fn launchctl_absent(
    target: &str,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
    recovery: &mut RecoveryControl<'_>,
) -> Result<()> {
    let label = target
        .rsplit_once('/')
        .context("invalid enrolled launchd target")?
        .1;
    let (status, output) = bounded_command_status(
        "/bin/launchctl",
        &["print".into(), target.into()],
        deadline,
        tick,
        recovery,
    )?;
    ensure!(
        status == 113 && output.contains(&format!("Could not find service \"{label}\"")),
        "exact Studio registration absence is not established"
    );
    Ok(())
}

fn listener_absent(
    address: SocketAddr,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
    recovery: &mut RecoveryControl<'_>,
) -> Result<()> {
    ensure!(
        address == "127.0.0.1:8000".parse::<SocketAddr>()?,
        "unexpected enrolled listener endpoint"
    );
    // The port-restricted query also rejects wildcard/IPv6 listeners on that port:
    // it cannot miss a replacement by filtering only the old backend PID.
    let observation =
        listener_query(address.port(), ListenerFields::Records, false, deadline, tick, recovery)?;
    ensure!(
        observation.listeners.is_empty(),
        "enrolled backend listener absence is not established"
    );
    Ok(())
}
fn launchctl_registration(
    target: &str,
    plist: &std::path::Path,
    expected_pid: Option<u32>,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
    recovery: &mut RecoveryControl<'_>,
) -> Result<u32> {
    let output = launchctl(&["print".into(), target.into()], deadline, tick, recovery)?;
    ensure!(
        output.starts_with(&format!("{target} = {{")),
        "launchd target header mismatch"
    );
    let expected_path = plist.to_str().context("plist path must be UTF-8")?;
    let paths: Vec<_> = output
        .lines()
        .filter_map(|line| line.trim().strip_prefix("path = "))
        .collect();
    ensure!(
        paths == [expected_path],
        "launchd registration plist reference mismatch"
    );
    let mut pids = output.lines().filter_map(|line| {
        line.trim()
            .strip_prefix("pid = ")
            .and_then(|pid| pid.parse::<u32>().ok())
    });
    let pid = pids
        .next()
        .context("launchd registration lacks unambiguous PID")?;
    ensure!(pids.next().is_none() && pid > 1, "ambiguous launchd PID");
    if let Some(expected) = expected_pid {
        ensure!(pid == expected, "launchd registration PID mismatch");
    }
    Ok(pid)
}
fn wait_health(
    address: SocketAddr,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
) -> Result<serde_json::Value> {
    loop {
        check(deadline, tick)?;
        match health_once(address, deadline) {
            Ok(value) => return Ok(value),
            Err(_) => pause(deadline, tick)?,
        }
    }
}
fn health_once(address: SocketAddr, deadline: Instant) -> Result<serde_json::Value> {
    let deadline = cap(deadline, Duration::from_millis(200));
    let timeout = std::cmp::min(
        Duration::from_millis(200),
        deadline.saturating_duration_since(Instant::now()),
    );
    ensure!(!timeout.is_zero(), "health deadline expired");
    let mut stream = TcpStream::connect_timeout(&address, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write!(
        stream,
        "GET /health HTTP/1.0\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )?;
    let mut bytes = Vec::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        ensure!(!remaining.is_zero(), "health exchange deadline expired");
        stream.set_read_timeout(Some(remaining))?;
        let mut buffer = [0u8; 4096];
        let size = stream.read(&mut buffer)?;
        if size == 0 {
            break;
        }
        ensure!(bytes.len() + size <= 65536, "health response exceeds bound");
        bytes.extend_from_slice(&buffer[..size]);
    }
    let split = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("malformed health HTTP")?;
    let header = std::str::from_utf8(&bytes[..split])?;
    ensure!(
        header.starts_with("HTTP/1.0 200 ") || header.starts_with("HTTP/1.1 200 "),
        "health HTTP status not 200"
    );
    let raw: serde_json::Value = serde_json::from_slice(&bytes[split + 4..])?;
    // Persist only safe health fields, never arbitrary server output.
    Ok(
        serde_json::json!({"status":raw.get("status"),"default_model":raw.get("default_model"),"engine_pool":{"model_count":raw.pointer("/engine_pool/model_count"),"loaded_count":raw.pointer("/engine_pool/loaded_count")}}),
    )
}

fn verify_backend_listener(
    expected: &ProcessIdentity,
    deadline: Instant,
    recovery: &mut RecoveryControl<'_>,
) -> Result<()> {
    process_scope::verify_identity(expected)?;
    // This callback cannot borrow the qualification tick twice; each bounded observation
    // is surrounded by the qualification owner's freshness callbacks.
    let observation = listener_query(
        8000, ListenerFields::Records, true,
        cap(deadline, Duration::from_millis(500)), &mut || Ok(()), recovery,
    )?;
    ensure!(
        observation.listeners.len() == 1
            && observation.listeners[0].pid == expected.pid
            && observation.listeners[0].command.as_deref() == Some("omlx-server")
            && observation.listeners[0].endpoints == ["127.0.0.1:8000"],
        "backend is not the sole exact loopback listener with qualified title"
    );
    process_scope::verify_identity(expected)?;
    Ok(())
}

/// The restored launcher is observed before its exec barrier is released.
/// Darwin cannot enroll an arbitrary escaped fork atomically: that uncertainty
/// remains sticky even when its known PID/group has been removed.
struct DetachedWatch {
    #[cfg(target_os = "macos")]
    queue: std::fs::File,
    pid: Option<u32>,
    failure: Option<String>,
}
impl DetachedWatch {
    fn new() -> Result<Self> {
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::{AsRawFd, FromRawFd};
            let fd = unsafe { libc::kqueue() };
            ensure!(fd >= 0, "creating detached process observation failed");
            let queue = above_stdio(unsafe { std::fs::File::from_raw_fd(fd) })?;
            ensure!(
                unsafe { libc::fcntl(queue.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) } == 0,
                "detached observation close-on-exec failed"
            );
            Ok(Self {
                queue,
                pid: None,
                failure: None,
            })
        }
        #[cfg(not(target_os = "macos"))]
        anyhow::bail!("detached process observation requires Darwin");
    }
    fn enroll(&mut self, pid: u32) -> Result<()> {
        #[cfg(target_os = "macos")]
        {
            use std::os::fd::AsRawFd;
            let event = libc::kevent {
                ident: pid as usize,
                filter: libc::EVFILT_PROC,
                flags: libc::EV_ADD | libc::EV_ENABLE | libc::EV_CLEAR,
                fflags: libc::NOTE_FORK | libc::NOTE_EXEC | libc::NOTE_EXIT,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            ensure!(
                unsafe {
                    libc::kevent(
                        self.queue.as_raw_fd(),
                        &event,
                        1,
                        std::ptr::null_mut(),
                        0,
                        std::ptr::null(),
                    )
                } == 0,
                "enrolling detached pre-exec process observation failed"
            );
            self.pid = Some(pid);
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = pid;
            anyhow::bail!("detached process observation requires Darwin");
        }
    }
    fn poll(&mut self) -> Result<()> {
        let Some(pid) = self.pid else {
            return Ok(());
        };
        let result: Result<()> = (|| {
            #[cfg(target_os = "macos")]
            {
                use std::os::fd::AsRawFd;
                let mut events: [libc::kevent; 8] = unsafe { std::mem::zeroed() };
                let timeout = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 0,
                };
                let count = unsafe {
                    libc::kevent(
                        self.queue.as_raw_fd(),
                        std::ptr::null(),
                        0,
                        events.as_mut_ptr(),
                        events.len() as i32,
                        &timeout,
                    )
                };
                ensure!(
                    count >= 0 && (count as usize) < events.len(),
                    "detached process observation failed or saturated"
                );
                for event in &events[..count as usize] {
                    ensure!(
                        event.ident == pid as usize
                            && event.filter == libc::EVFILT_PROC
                            && event.flags & libc::EV_ERROR == 0,
                        "unexpected detached process event"
                    );
                    ensure!(
                        event.fflags & libc::NOTE_FORK == 0,
                        "detached launcher fork observed; arbitrary escaped-descendant absence remains unqualified"
                    );
                }
                Ok(())
            }
            #[cfg(not(target_os = "macos"))]
            {
                let _ = pid;
                anyhow::bail!("detached process observation requires Darwin");
            }
        })();
        if let Err(error) = &result {
            self.failure.get_or_insert_with(|| format!("{error:#}"));
        }
        result
    }
}

/// Double-fork only for restoring the EXTERNAL service. Experiments never use this path.
/// The pipe closes on successful exec; the guardian records the exact argv/cwd/env it supplied.
fn launch_detached(
    spec: &CommandSpec,
    expected_executable: &std::path::Path,
    deadline: Instant,
    tick: &mut dyn FnMut() -> Result<()>,
    recovery: &mut RecoveryControl<'_>,
) -> Result<ProcessIdentity> {
    use std::{
        ffi::CString,
        fs::File,
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::ffi::OsStrExt,
        },
    };
    spec.validate()?;
    check(deadline, tick)?;
    let executable = CString::new(spec.executable.as_os_str().as_bytes())?;
    let cwd = CString::new(spec.cwd.as_os_str().as_bytes())?;
    let mut argv = Vec::with_capacity(spec.args.len() + 1);
    argv.push(executable.clone());
    for arg in &spec.args {
        argv.push(CString::new(arg.as_bytes())?);
    }
    let env: Vec<CString> = spec
        .environment
        .iter()
        .map(|(k, v)| CString::new(format!("{k}={v}")))
        .collect::<std::result::Result<_, _>>()?;
    let mut argv_ptrs: Vec<_> = argv.iter().map(|a| a.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut env_ptrs: Vec<_> = env.iter().map(|a| a.as_ptr()).collect();
    env_ptrs.push(std::ptr::null());
    let null = above_stdio(
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/null")?,
    )?;
    fn pipe() -> Result<(File, File)> {
        let mut fds = [-1; 2];
        ensure!(
            unsafe { libc::pipe(fds.as_mut_ptr()) } == 0,
            "detached pipe failed"
        );
        let reader = above_stdio(unsafe { File::from_raw_fd(fds[0]) })?;
        let writer = above_stdio(unsafe { File::from_raw_fd(fds[1]) })?;
        for fd in [reader.as_raw_fd(), writer.as_raw_fd()] {
            ensure!(
                unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } == 0,
                "detached close-on-exec failed"
            );
        }
        #[cfg(target_os = "macos")]
        ensure!(
            unsafe {
                libc::fcntl(writer.as_raw_fd(), 73 /* F_SETNOSIGPIPE */, 1)
            } == 0,
            "protecting detached pipe from SIGPIPE failed"
        );
        Ok((reader, writer))
    }
    let (mut reader, writer) = pipe()?;
    let (control_reader, mut control_writer) = pipe()?;
    let (release_reader, release_writer) = pipe()?;
    ensure!(
        unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } == 0,
        "detached nonblocking failed"
    );
    let max_fd = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    ensure!(
        (4..=1_048_576).contains(&max_fd),
        "cannot bound detached descriptor closure"
    );
    let mut watch = DetachedWatch::new()?;
    check(deadline, tick)?;
    let timeout = deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .min(i32::MAX as u128) as i32;
    let child = unsafe { libc::fork() };
    ensure!(child >= 0, "detached first fork failed");
    if child == 0 {
        // No Rust allocation, unwinding or destructors after fork. Neither actor
        // can exec until the guardian has recorded its PID and birth identity.
        unsafe {
            libc::close(reader.as_raw_fd());
            libc::close(control_writer.as_raw_fd());
            if !detached_token(control_reader.as_raw_fd(), b'F', timeout) {
                libc::_exit(0);
            }
            let grandchild = libc::fork();
            if grandchild < 0 {
                libc::_exit(125);
            }
            if grandchild > 0 {
                libc::close(release_reader.as_raw_fd());
                let sent = libc::write(
                    writer.as_raw_fd(),
                    (&grandchild as *const libc::pid_t).cast(),
                    4,
                ) == 4;
                let setup = b'S';
                if sent {
                    libc::write(release_writer.as_raw_fd(), (&setup as *const u8).cast(), 1);
                }
                let release = sent && detached_token(control_reader.as_raw_fd(), b'E', timeout);
                if release {
                    let token = b'E';
                    if libc::write(release_writer.as_raw_fd(), (&token as *const u8).cast(), 1) == 1
                    {
                        libc::_exit(0);
                    }
                }
                // Abort closes the pre-exec barrier, then reaps our own child.
                libc::close(release_writer.as_raw_fd());
                let mut status = 0;
                if libc::waitpid(grandchild, &mut status, 0) == grandchild {
                    libc::_exit(0);
                }
                libc::_exit(125);
            }
            libc::close(control_reader.as_raw_fd());
            libc::close(release_writer.as_raw_fd());
            if !detached_token(release_reader.as_raw_fd(), b'S', timeout) {
                libc::_exit(125);
            }
            let fd = writer.as_raw_fd();
            let setup_ok = libc::setsid() >= 0
                && libc::chdir(cwd.as_ptr()) == 0
                && libc::dup2(null.as_raw_fd(), 0) >= 0
                && libc::dup2(null.as_raw_fd(), 1) >= 0
                && libc::dup2(null.as_raw_fd(), 2) >= 0;
            let setup_status = if setup_ok { 0u8 } else { 1u8 };
            libc::write(fd, (&setup_status as *const u8).cast(), 1);
            if !setup_ok || !detached_token(release_reader.as_raw_fd(), b'E', timeout) {
                libc::_exit(126);
            }
            for descriptor in 3..max_fd as i32 {
                if descriptor != fd {
                    libc::close(descriptor);
                }
            }
            libc::execve(executable.as_ptr(), argv_ptrs.as_ptr(), env_ptrs.as_ptr());
            let failure = 1u8;
            libc::write(fd, (&failure as *const u8).cast(), 1);
            libc::_exit(126);
        }
    }
    drop(writer);
    drop(control_reader);
    drop(release_reader);
    drop(release_writer);
    let index = {
        let mut budget = recovery.budget.borrow_mut();
        let index = budget.actors.len();
        budget.actors.push(ActorDisposition {
            kind: "detached launch".into(),
            pid: child as u32,
            identity: None,
            intermediate_pid: Some(child as u32),
            intermediate_reaped: false,
            intermediate_status: None,
            intermediate_identity: process_scope::observe(child as u32).ok().flatten(),
            launch_record: spec.clone(),
            settlement: None,
            complete: false,
            failure: None,
            descendant_uncertainty: None,
            known_absent: false,
        });
        index
    };
    let mut bytes = Vec::with_capacity(6);
    let mut released = false;
    let mut anchor = None;
    let result = (|| {
        check(deadline, tick)?;
        control_writer.write_all(b"F")?;
        loop {
            check(deadline, tick)?;
            let eof = detached_observe(&mut reader, &mut bytes, child, index, recovery)?;
            watch.poll()?;
            ensure!(
                bytes.len() <= 5 && bytes.get(4) != Some(&1),
                "detached exec/setup failed"
            );
            if bytes.len() == 5 && !released {
                let pid = recovery.budget.borrow().actors[index].pid;
                let identity = process_scope::observe(pid)?
                    .context("detached actor missing before release")?;
                ensure!(
                    identity.pgid == pid && identity.sid == pid as i32 && identity.cwd == spec.cwd,
                    "detached pre-exec binding mismatch"
                );
                recovery.budget.borrow_mut().actors[index].identity = Some(identity.clone());
                anchor = Some(identity);
                watch.enroll(pid)?;
                check(deadline, tick)?;
                // Treat even a failed write as possibly released.
                released = true;
                control_writer.write_all(b"E")?;
            }
            let entry = recovery.budget.borrow().actors[index].clone();
            if let Some(status) = entry.intermediate_status {
                ensure!(
                    libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                    "detached intermediate failed: {status}"
                );
            }
            if eof && entry.intermediate_reaped {
                ensure!(
                    released && bytes.len() == 5,
                    "detached launch lacks exec/PID handshake"
                );
                let identity = process_scope::observe(entry.pid)?
                    .context("detached backend exited before observation")?;
                ensure!(
                    identity.state != ProcessState::Zombie,
                    "detached backend exited during startup"
                );
                ensure!(
                    same_birth(anchor.as_ref().unwrap(), &identity),
                    "detached PID birth changed"
                );
                if identity.ppid == 1
                    && identity.pgid == identity.pid
                    && identity.sid == identity.pid as i32
                    && identity.cwd == spec.cwd
                    && identity.executable == expected_executable
                {
                    check(deadline, tick)?;
                    watch.poll()?;
                    let mut budget = recovery.budget.borrow_mut();
                    budget.actors[index].identity = Some(identity.clone());
                    budget.actors[index].complete = true;
                    return Ok(identity);
                }
            }
            pause(deadline, tick)?;
        }
    })();
    // Closing this channel cancels pre-exec work; it never releases an actor.
    drop(control_writer);
    if let Err(error) = result {
        let cleanup_end = recovery.deadline();
        let mut signalled = false;
        let cleanup: Result<()> = (|| {
            loop {
                check(cleanup_end, recovery.tick)?;
                detached_observe(&mut reader, &mut bytes, child, index, recovery)?;
                let _ = watch.poll(); // Sticky evidence; never prevents known-actor cleanup.
                let entry = recovery.budget.borrow().actors[index].clone();
                if released {
                    let expected = anchor
                        .as_ref()
                        .context("released actor lacks birth identity")?;
                    if entry.intermediate_reaped && bound_absent(expected)? {
                        break;
                    }
                    if !signalled && bytes.len() < 6 {
                        match process_scope::observe(expected.pid) {
                            Ok(Some(current)) => {
                                ensure!(
                                    same_birth(expected, &current),
                                    "detached cleanup birth changed"
                                );
                                check(cleanup_end, recovery.tick)?;
                                process_scope::signal_bound(
                                    &current,
                                    libc::SIGKILL,
                                    true,
                                    &mut || check(cleanup_end, recovery.tick),
                                )?;
                                signalled = true;
                            }
                            Ok(None) => {}
                            Err(observation_error) => {
                                // A zombie has no executable/cwd attestation.
                                // Never signal without one: keep observing the
                                // independent birth/group absence predicate.
                                recovery.budget.borrow_mut().actors[index].failure = Some(format!(
                                    "cleanup identity unavailable: {observation_error:#}"
                                ));
                            }
                        }
                    }
                } else if entry.intermediate_reaped {
                    let status = entry
                        .intermediate_status
                        .context("missing intermediate status")?;
                    ensure!(
                        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
                        "intermediate could not account for pre-exec child"
                    );
                    // Successful abort status means the supervisor reaped any
                    // grandchild, including errors before its PID was read.
                    break;
                }
                pause(cleanup_end, recovery.tick)?;
            }
            Ok(())
        })();
        let mut budget = recovery.budget.borrow_mut();
        let entry = &mut budget.actors[index];
        let _ = watch.poll();
        entry.descendant_uncertainty = if released {
            watch.failure.clone()
        } else {
            None
        };
        entry.complete = cleanup.is_ok() && entry.descendant_uncertainty.is_none();
        entry.known_absent = cleanup.is_ok();
        entry.failure = Some(format!(
            "{error:#}; cleanup: {cleanup:?}; descendant uncertainty: {:?}",
            entry.descendant_uncertainty
        ));
        return Err(error).context(format!(
            "detached pid {} intermediate {} cleanup complete={}: {cleanup:?}",
            entry.pid, child, entry.complete
        ));
    }
    result
}

fn same_birth(expected: &ProcessIdentity, current: &ProcessIdentity) -> bool {
    expected.pid == current.pid
        && expected.uid == current.uid
        && expected.start_seconds == current.start_seconds
        && expected.start_subseconds == current.start_subseconds
}

// Only async-signal-safe libc calls: used exclusively in the forked actors.
unsafe fn detached_token(fd: i32, expected: u8, timeout: i32) -> bool {
    let mut poll = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let mut token = 0u8;
    unsafe {
        libc::poll(&mut poll, 1, timeout) > 0
            && libc::read(fd, (&mut token as *mut u8).cast(), 1) == 1
            && token == expected
    }
}

fn detached_observe(
    reader: &mut std::fs::File,
    bytes: &mut Vec<u8>,
    child: i32,
    index: usize,
    recovery: &mut RecoveryControl<'_>,
) -> Result<bool> {
    let mut eof = false;
    let mut buffer = [0u8; 8];
    match reader.read(&mut buffer) {
        Ok(0) => eof = true,
        Ok(n) => {
            ensure!(bytes.len() + n <= 6, "detached handshake exceeds bound");
            bytes.extend_from_slice(&buffer[..n]);
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Err(error) => return Err(error.into()),
    }
    let mut budget = recovery.budget.borrow_mut();
    let entry = &mut budget.actors[index];
    if bytes.len() >= 4 {
        let pid = i32::from_ne_bytes(bytes[..4].try_into().unwrap());
        ensure!(pid > 1, "invalid detached PID");
        entry.pid = pid as u32;
        if entry.identity.is_none() {
            match process_scope::observe(entry.pid) {
                Ok(identity) => entry.identity = identity,
                Err(error) => {
                    entry.failure = Some(format!("early PID identity unavailable: {error:#}"))
                }
            }
        }
    }
    if !entry.intermediate_reaped {
        let mut status = 0;
        let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
        ensure!(waited >= 0, "detached intermediate wait failed");
        if waited == child {
            entry.intermediate_reaped = true;
            entry.intermediate_status = Some(status);
        }
    }
    Ok(eof)
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    fn command(executable: &str, args: &[&str], cwd: &std::path::Path) -> CommandSpec {
        CommandSpec {
            executable: executable.into(),
            args: args.iter().map(|arg| (*arg).into()).collect(),
            cwd: cwd.to_path_buf(),
            environment: BTreeMap::new(),
        }
    }
    // Independent test ownership is the last resort on either error or panic;
    // it is never passed to production as replacement execution authority.
    struct TestScope(Rc<RefCell<RecoveryBudget>>);
    impl TestScope {
        fn new() -> Self {
            Self(Rc::new(RefCell::new(RecoveryBudget::new(
                Duration::from_secs(3),
                Instant::now() + Duration::from_secs(10),
            ))))
        }
        fn control<'a>(&self, tick: &'a mut dyn FnMut() -> Result<()>) -> RecoveryControl<'a> {
            RecoveryControl::new(self.0.clone(), tick)
        }
    }

    fn studio_startup_case(change_cwd: bool) -> Result<serde_json::Value> {
        use std::{fs::File, os::{fd::OwnedFd, unix::net::UnixStream}};
        let directory = tempfile::tempdir()?;
        let directory = std::fs::canonicalize(directory.path())?;
        let ready = directory.join("ready");
        std::fs::create_dir(&ready)?;
        let scope = TestScope::new();
        let mut recovery_tick = || Ok(());
        let mut recovery = scope.control(&mut recovery_tick);
        let overall = Instant::now() + Duration::from_secs(6);
        let original = command("/bin/sleep", &["0.3"], &ready);
        let attempt = OwnedProcess::spawn_with_deadline(&original, overall, &mut || Ok(()))?;
        let mut actor = attempt.process;
        let index = recovery.enroll_actor(&actor, &original, "original CPU identity");
        let previous = (|| -> Result<ProcessIdentity> {
            ensure!(attempt.failure.is_none(), "original fixture launch failed");
            actor.identity()
        })();
        let natural = (|| -> Result<()> {
            while !actor.exited_unreaped()? { pause(overall, &mut || Ok(()))?; }
            Ok(())
        })();
        let cleanup = recovery.dispose(actor, index);
        let previous = previous?;
        natural?;
        cleanup?;

        let (reader, mut writer) = UnixStream::pair()?;
        let reader = File::from(OwnedFd::from(reader));
        let script = if change_cwd {
            "IFS= read -r token <&3; cd \"$1\"; exec /bin/sleep 1"
        } else {
            "IFS= read -r token <&3; exec /bin/sleep 1"
        };
        let replacement = command(
            "/bin/sh", &["-c", script, "startup-fixture", ready.to_str().context("fixture cwd")?],
            &directory,
        );
        let attempt = OwnedProcess::spawn_with_io(
            &replacement, overall, &mut || Ok(()),
            &[process_scope::InheritedFd { file: &reader, target: 3 }], None,
        )?;
        let mut actor = attempt.process;
        let index = recovery.enroll_actor(&actor, &replacement, "startup CPU replacement");
        drop(reader);
        let mut evidence = Vec::new();
        let mut calls = 0;
        let mut released = false;
        let observed = (|| -> Result<ProcessIdentity> {
            ensure!(attempt.failure.is_none(), "replacement fixture launch failed");
            wait_studio_replacement(
                actor.pid(), &previous,
                cap(overall, Duration::from_millis(if change_cwd { 700 } else { 150 })),
                &mut || {
                    calls += 1;
                    if calls == 3 {
                        writer.write_all(b"exec\n")?;
                        released = true;
                    }
                    Ok(())
                }, &mut evidence,
            )
        })();
        if !released { let _ = writer.write_all(b"finish\n"); }
        let natural = (|| -> Result<()> {
            while !actor.exited_unreaped()? { pause(overall, &mut || Ok(()))?; }
            Ok(())
        })();
        let cleanup = recovery.dispose(actor, index);
        natural?;
        cleanup?;
        ensure!(recovery.complete(), "original CPU actor accounting incomplete");
        ensure!(observed.is_ok() == change_cwd, "startup qualification outcome differs: {observed:?}");
        let evidence: serde_json::Value = serde_json::from_str(
            evidence.last().context("missing specific startup observation")?,
        )?;
        let actors = recovery.observations();
        ensure!(actors.iter().all(|actor| actor.settlement.as_ref().is_some_and(|s|
            s.complete && s.leader_reaped && s.group_absent && s.exit_code == Some(0)
                && !s.group_signalled)), "CPU actors lack original natural-exit settlement");
        eprintln!("{}", serde_json::json!({
            "kind":"owned_studio_startup_cpu_qualification",
            "case":if change_cwd {"exec_transition"} else {"persistent_cwd_mismatch"},
            "observation":evidence,"actors":actors,"native_service_effects":false,
        }));
        Ok(evidence)
    }

    #[test]
    fn studio_startup_exec_transition_requires_final_strict_binding() -> Result<()> {
        let evidence = studio_startup_case(true)?;
        ensure!(evidence["qualified"] == true, "exec transition not qualified");
        ensure!(evidence["first_observed"]["executable"] != evidence["expected_previous"]["executable"],
            "fixture did not expose the real startup executable");
        ensure!(evidence["first_observed"]["cwd"] != evidence["expected_previous"]["cwd"],
            "fixture did not expose the startup cwd transition");
        ensure!(evidence["last_observed"]["executable"] == evidence["expected_previous"]["executable"]
            && evidence["last_observed"]["cwd"] == evidence["expected_previous"]["cwd"]
            && evidence["last_observed"]["uid"] == evidence["expected_previous"]["uid"]
            && evidence["last_observed"]["state"] == "running"
            && evidence["last_observed"]["pid"] != evidence["expected_previous"]["pid"],
            "strict final replacement predicates were not established");
        Ok(())
    }

    #[test]
    fn studio_startup_persistent_mismatch_retains_exact_diagnostics() -> Result<()> {
        let evidence = studio_startup_case(false)?;
        ensure!(evidence["qualified"] == false
            && evidence["last_mismatch_fields"] == serde_json::json!(["cwd"]),
            "persistent cwd mismatch was not retained precisely");
        ensure!(evidence["last_observed"]["cwd"] != evidence["expected_previous"]["cwd"]
            && evidence["last_observed"]["executable"] == evidence["expected_previous"]["executable"]
            && evidence["failure"].as_str().is_some_and(|message| message.contains("deadline")),
            "bounded failure lacks observed mismatch/deadline evidence");
        Ok(())
    }
    #[test]
    fn unmanaged_callbacks_cannot_control_and_observation_failure_is_sticky() {
        let scope = TestScope::new();
        let mut recovery_tick = || Ok(());
        let mut recovery = scope.control(&mut recovery_tick);
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut service = ServiceHandle::enroll(
            &ServiceSpec::OmlxUnmanaged {
                purpose: ScopePurpose::Cpu,
                acknowledgement: UnmanagedAcknowledgement::AcceptUnverifiedOmlx,
            },
            ScopePurpose::Cpu,
            None,
            deadline,
            &mut || Ok(()),
            &mut recovery,
        ).unwrap();
        assert!(!service.is_absent_scope());
        assert!(service.stop(deadline, &mut || Ok(()), &mut recovery).is_err());
        assert!(service.restore(deadline, &mut || Ok(()), &mut recovery).is_err());
        let observation = service.observe_inhibited(
            deadline, &mut || Ok(()), &mut recovery,
        ).unwrap();
        assert!(!observation.inhibited && !observation.restored);
        assert!(observation.absence.is_none());
        assert!(observation.root.is_none() && observation.gui.is_none());
        assert!(observation.launch_record.is_none() && observation.actors.is_empty());
        assert!(observation.unmanaged.is_some());
        assert!(service.observe_inhibited(
            deadline, &mut || anyhow::bail!("controller lost"), &mut recovery,
        ).is_err());
        assert!(service.observe_inhibited(
            deadline, &mut || Ok(()), &mut recovery,
        ).is_err());
        assert_eq!(service.last_observation().failure.as_deref(), Some("controller lost"));
        service.finish_owned_cpu(&mut recovery).unwrap();
        assert!(scope.0.borrow().actors.is_empty());
        assert!(!service.last_observation().restored);
    }
    fn reap_finite_child(pid: u32, end: Instant) {
        while Instant::now() < end {
            let mut status = 0;
            let waited = unsafe { libc::waitpid(pid as i32, &mut status, libc::WNOHANG) };
            if waited == pid as i32
                || (waited < 0
                    && std::io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD))
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            std::thread::panicking(),
            "finite test child {pid} did not reap within enrolled outer ceiling"
        );
    }
    impl Drop for TestScope {
        fn drop(&mut self) {
            let end = self.0.borrow().ceiling;
            let actors = std::mem::take(&mut self.0.borrow_mut().retained);
            for mut actor in actors {
                let reaped = self
                    .0
                    .borrow()
                    .actors
                    .iter()
                    .rev()
                    .find(|entry| entry.pid == actor.pid())
                    .and_then(|entry| entry.settlement.as_ref().map(|s| s.leader_reaped));
                match reaped {
                    Some(true) => {}
                    Some(false) => reap_finite_child(actor.pid(), end),
                    None => {
                        if !actor
                            .settle(end, Duration::ZERO, &mut || Ok(()))
                            .is_ok_and(|s| s.leader_reaped)
                        {
                            reap_finite_child(actor.pid(), end);
                        }
                    }
                }
            }
            let pending = std::mem::take(&mut self.0.borrow_mut().pending);
            for (mut actor, _) in pending {
                if !actor
                    .settle(end, Duration::ZERO, &mut || Ok(()))
                    .is_ok_and(|s| s.leader_reaped)
                {
                    reap_finite_child(actor.pid(), end);
                }
            }
            for entry in self
                .0
                .borrow()
                .actors
                .iter()
                .filter(|entry| entry.intermediate_pid.is_some())
            {
                if let Some(expected) = &entry.identity
                    && let Ok(Some(current)) = process_scope::observe(expected.pid)
                    && same_birth(expected, &current)
                    && current.state != ProcessState::Zombie
                    && Instant::now() < end
                {
                    let _ = process_scope::signal_bound(
                        &current,
                        libc::SIGKILL,
                        current.pgid == current.pid && current.sid == current.pid as i32,
                        &mut || check(end, &mut || Ok(())),
                    );
                }
                let child = entry.intermediate_pid.unwrap() as i32;
                while Instant::now() < end {
                    let mut status = 0;
                    let waited = unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) };
                    if waited == 0 {
                        // An unreaped direct child pins this PID against reuse.
                        unsafe {
                            libc::kill(child, libc::SIGKILL);
                        }
                    }
                    let absent = process_scope::observe(entry.pid).ok().flatten().is_none();
                    if waited != 0 && absent {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
    }
    struct TestOwned(OwnedProcess, Instant);
    impl Drop for TestOwned {
        fn drop(&mut self) {
            if !self
                .0
                .settle(self.1, Duration::ZERO, &mut || Ok(()))
                .is_ok_and(|s| s.leader_reaped)
            {
                reap_finite_child(self.0.pid(), self.1);
            }
        }
    }
    struct TestHandle(ServiceHandle, Rc<RefCell<RecoveryBudget>>);
    impl Drop for TestHandle {
        fn drop(&mut self) {
            for actor in [self.0.cpu.take(), self.0.cpu_gui.take()]
                .into_iter()
                .flatten()
            {
                self.1.borrow_mut().retained.push(actor);
            }
        }
    }
    impl std::ops::Deref for TestHandle {
        type Target = ServiceHandle;
        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }
    impl std::ops::DerefMut for TestHandle {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    #[test]
    fn listener_parser_rejects_ambiguous_or_diagnostic_records() -> Result<()> {
        let records = parse_listener_output(0,
            "p42\ncserver\nn127.0.0.1:49152\nn[::1]:49152\np43\ncother\nn*:49152\n",
            ListenerFields::Records, 49152)?;
        ensure!(records.iter().map(|r| r.pid).collect::<Vec<_>>() == [42, 43]
            && records[0].endpoints == ["127.0.0.1:49152", "[::1]:49152"]
            && records[1].endpoints == ["*:49152"], "listener owners/addresses lost");
        ensure!(parse_listener_output(1, "", ListenerFields::Records, 49152)?.is_empty(),
            "empty selected-port observation rejected");
        for output in [
            "", "\n", "p42", "42\n", "p+42\n", "p042\n", "p1\n", "p2147483648\n",
            "p4294967296\n", "p42\np42\n", "p42\ncserver\n", "cserver\np42\nn*:49152\n",
            "p42\nn*:49152\ncserver\n", "p42\ncserver\ncserver\nn*:49152\n",
            "p42\ncserver\nn*:49152\nn*:49152\n", "p42\ncserver\nn*:49152\np42\ncother\nn*:49152\n",
            "p42\ncserver\nn*:49152\nwarning private\n", "p42\ncserver\nn*:49152\nf9\n",
            "p42\ncserver\nn*:49153\n", "p42\ncserver\nn127.0.0.1:49152->127.0.0.1:80\n",
            "p42\ncserver\nn127.0.0.1:+49152\n",
            "p42\ncserver\nn*:49152\n\n", "p42\r\ncserver\nn*:49152\n",
        ] {
            ensure!(parse_listener_output(0, output, ListenerFields::Records, 49152).is_err(),
                "ambiguous listener output admitted");
        }
        for status in [-1, 1, 2] {
            ensure!(parse_listener_output(status, "p42\ncserver\nn*:49152\n",
                ListenerFields::Records, 49152).is_err(), "invalid exit admitted");
        }
        ensure!(parse_listener_output(0, "p42\np43\n", ListenerFields::Pids, 49152)?
            .iter().map(|r| r.pid).collect::<Vec<_>>() == [42, 43], "PID selection lost");
        for output in ["42\n", "p42\np42\n", "p42\ncserver\n", "p42\nwarning\n"] {
            ensure!(parse_listener_output(0, output, ListenerFields::Pids, 49152).is_err(),
                "invalid PID-only observation admitted");
        }
        Ok(())
    }

    #[test]
    fn listener_capture_errors_retain_safe_exact_helper_accounting() -> Result<()> {
        let dir = tempfile::tempdir()?;
        // Secrets originate inside a private fixture file, never the public argv receipt.
        let scripts = [
            "printf 'p42\\ncserver\\nn*:49152\\n'; printf 'p42\\ncprivate-secret\\nn*:49152\\n' >&2",
            "trap \"printf 'warning private-secret\\n' >&2\" EXIT; printf 'p42\\ncserver\\nn*:49152\\n'",
            "printf 'p42\\ncserver\\nn*:49152\\nwarning private-secret\\n'",
            "printf 'p42\\ncserver\\nn*:49152\\n'; exit 1",
            "i=0; while [ \"$i\" -lt 70 ]; do printf '%1024s' x; i=$((i+1)); done",
        ];
        for (case, script) in scripts.iter().enumerate() {
            let path = dir.path().join(format!("helper-{case}.sh"));
            std::fs::write(&path, script)?;
            let spec = command("/bin/sh", &[path.to_str().context("fixture path")?], dir.path());
            let scope = TestScope::new();
            let mut recovery_tick = || Ok(());
            let mut recovery = scope.control(&mut recovery_tick);
            let started = Instant::now();
            let result = bounded_spec_read(&spec, started + Duration::from_millis(500),
                &mut || Ok(()), &mut recovery, CapturePolicy::StdoutOnly,
                |status, output| parse_listener_output(status, &output, ListenerFields::Records, 49152));
            let error = result.expect_err("invalid observation admitted");
            let entries = recovery.observations();
            eprintln!("listener helper case={case} elapsed={:?} error={error:#} accounting={entries:?}",
                started.elapsed());
            ensure!(!format!("{error:#}").contains("private-secret")
                && entries.len() == 1 && entries[0].complete
                && entries[0].settlement.as_ref().is_some_and(|s|
                    s.complete && s.leader_reaped && s.group_absent),
                "unsafe error or missing helper accounting");
            ensure!(!entries[0].failure.as_deref().unwrap_or("").contains("private-secret"),
                "raw diagnostics entered public failure");
            if case == 4 {
                ensure!(format!("{error:#}").contains("output exceeds bound"),
                    "overflow fixture did not reach capture byte bound");
            }
        }
        Ok(())
    }

    #[test]
    fn listener_nonfork_stalls_cancel_without_losing_ownership() -> Result<()> {
        let dir = tempfile::tempdir()?;
        for resist_term in [false, true] {
            let path = dir.path().join("finite.sh");
            std::fs::write(&path, if resist_term {
                "trap '' TERM; exec /bin/sleep 2"
            } else { "exec /bin/sleep 2" })?;
            let spec = command("/bin/sh", &[path.to_str().context("fixture path")?], dir.path());
            let scope = TestScope::new();
            let mut recovery_tick = || Ok(());
            let mut recovery = scope.control(&mut recovery_tick);
            let started = Instant::now();
            let result = bounded_spec_read(&spec, started + Duration::from_millis(500),
                &mut || Ok(()), &mut recovery, CapturePolicy::StdoutOnly,
                |status, output| parse_listener_output(status, &output, ListenerFields::Records, 49152));
            let entries = recovery.observations();
            ensure!(result.is_err() && entries.len() == 1 && entries[0].complete,
                "stalled helper escaped denied observation or complete accounting");
            let settlement = entries[0].settlement.as_ref().context("missing settlement")?;
            ensure!(settlement.complete && settlement.leader_reaped && settlement.group_absent,
                "stalled helper cleanup incomplete");
            eprintln!("listener nonfork resist_term={resist_term} elapsed={:?} accounting={entries:?}",
                started.elapsed());
        }
        Ok(())
    }

    #[test]
    fn listener_success_returns_settlement_without_growing_history() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("empty.sh");
        std::fs::write(&path, "exit 1")?;
        let spec = command("/bin/sh", &[path.to_str().context("fixture path")?], dir.path());
        let scope = TestScope::new();
        let mut recovery_tick = || Ok(());
        let mut recovery = scope.control(&mut recovery_tick);
        for _ in 0..3 {
            let (records, receipt) = bounded_spec_read(&spec,
                Instant::now() + Duration::from_millis(500), &mut || Ok(()),
                &mut recovery, CapturePolicy::StdoutOnly,
                |status, output| parse_listener_output(status, &output, ListenerFields::Records, 49152))?;
            ensure!(records.is_empty() && receipt.complete
                && receipt.settlement.as_ref().is_some_and(|s|
                    s.complete && s.leader_reaped && s.group_absent && s.exit_code == Some(1))
                && recovery.observations().is_empty(), "success receipt lost or history grew");
        }
        Ok(())
    }

    #[test]
    fn deadline_after_term_never_escalates() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let spec = command(
            "/bin/sh",
            &["-c", "trap '' TERM; exec /bin/sleep 2"],
            dir.path(),
        );
        let cleanup_end = Instant::now() + Duration::from_secs(5);
        let attempt = OwnedProcess::spawn_with_deadline(&spec, cleanup_end, &mut || Ok(()))?;
        let mut owner = TestOwned(attempt.process, cleanup_end);
        ensure!(attempt.failure.is_none(), "test actor spawn failed");
        let actor = &mut owner.0;
        loop {
            check(cleanup_end, &mut || Ok(()))?;
            if actor.identity()?.executable == std::path::Path::new("/bin/sleep") {
                break;
            }
            pause(cleanup_end, &mut || Ok(()))?;
        }
        actor.signal(libc::SIGSTOP)?;
        let root = actor.identity()?;
        let deadline = Instant::now() + Duration::from_millis(30);
        let result = terminate_bound(&root, deadline, &mut || {
            std::thread::sleep(Duration::from_millis(10));
            Ok(())
        });
        std::thread::sleep(Duration::from_millis(20));
        let killed = actor.exited_unreaped()?;
        let settlement = actor.settle(cleanup_end, Duration::ZERO, &mut || Ok(()));
        eprintln!(
            "TERM deadline probe: result={result:?}, exited_before_cleanup={killed}, cleanup={settlement:?}"
        );
        ensure!(settlement?.complete, "test actor cleanup incomplete");
        ensure!(
            result.is_err() && !killed,
            "KILL occurred after TERM deadline"
        );
        Ok(())
    }

    #[test]
    fn helper_authority_loss_retains_cleanup_disposition() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let record = dir.path().join("pid");
        let args = vec![
            "-c".into(),
            format!("echo $$ > '{}'; exec /bin/sleep 2", record.display()),
        ];
        let scope = TestScope::new();
        let mut recovery_tick = || Ok(());
        let mut recovery = scope.control(&mut recovery_tick);
        let mut marker_ticks = 0;
        let result = bounded_command_status(
            "/bin/sh",
            &args,
            Instant::now() + Duration::from_secs(3),
            &mut || {
                if record.exists() {
                    marker_ticks += 1;
                }
                ensure!(marker_ticks < 4, "execution authority revoked");
                Ok(())
            },
            &mut recovery,
        );
        let pid: u32 = std::fs::read_to_string(&record)?.trim().parse()?;
        let absent = process_scope::observe(pid)?.is_none();
        let entries = recovery.observations();
        eprintln!(
            "helper authority probe: pid={pid}, marker_ticks={marker_ticks}, absent={absent}, result={result:?}, accounting={entries:?}"
        );
        ensure!(
            result.is_err() && absent,
            "helper retained actor after authority loss"
        );
        ensure!(
            entries.iter().any(|entry| entry.pid == pid
                && entry.complete
                && entry
                    .settlement
                    .as_ref()
                    .is_some_and(|s| s.complete && s.leader_reaped && s.group_absent)),
            "helper omitted actual complete settlement"
        );
        Ok(())
    }

    #[test]
    fn deferred_helper_returns_owner_then_finishes_original_slot() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let marker = dir.path().join("pid");
        let args = vec![
            "-c".into(),
            format!("echo $$ > '{}'; exec /bin/sleep 2", marker.display()),
        ];
        let scope = TestScope::new();
        let recovery_calls = std::cell::Cell::new(0);
        let mut recovery_tick = || {
            recovery_calls.set(recovery_calls.get() + 1);
            Ok(())
        };
        let mut recovery = RecoveryControl::deferred(scope.0.clone(), &mut recovery_tick);
        let mut seen = 0;
        let result = bounded_command_status(
            "/bin/sh",
            &args,
            Instant::now() + Duration::from_secs(3),
            &mut || {
                if marker.exists() {
                    seen += 1;
                }
                ensure!(seen < 4, "active experiment authority revoked");
                Ok(())
            },
            &mut recovery,
        );
        let pid: u32 = std::fs::read_to_string(marker)?.trim().parse()?;
        let deadline = scope
            .0
            .borrow()
            .deadline
            .context("deferred cleanup did not start enrolled slot")?;
        ensure!(
            result.is_err()
                && recovery_calls.get() == 0
                && scope.0.borrow().pending.len() == 1
                && !recovery.complete()
                && process_scope::observe(pid)?.is_some(),
            "deferred helper blocked or lost ownership"
        );
        let mut recovery = scope.control(&mut recovery_tick);
        recovery.finish_pending()?;
        let entries = recovery.observations();
        eprintln!(
            "deferred helper probe: pid={pid}, recovery_calls={}, accounting={entries:?}",
            recovery_calls.get()
        );
        ensure!(
            recovery.deadline() == deadline
                && recovery.complete()
                && process_scope::observe(pid)?.is_none(),
            "pending cleanup did not settle original slot"
        );
        let calls = recovery_calls.get();
        recovery.finish_pending()?;
        ensure!(
            calls == recovery_calls.get(),
            "already attempted cleanup was retried"
        );
        Ok(())
    }

    #[test]
    fn helper_recovery_expiry_is_sticky_and_preserves_owner() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let marker = dir.path().join("pid");
        let args = vec![
            "-c".into(),
            format!("echo $$ > '{}'; exec /bin/sleep 2", marker.display()),
        ];
        let scope = TestScope::new();
        scope.0.borrow_mut().span = Duration::from_millis(20);
        let mut recovery_tick = || {
            std::thread::sleep(Duration::from_millis(30));
            Ok(())
        };
        let mut recovery = scope.control(&mut recovery_tick);
        let mut calls = 0;
        let result = bounded_command_status(
            "/bin/sh",
            &args,
            Instant::now() + Duration::from_secs(2),
            &mut || {
                if marker.exists() {
                    calls += 1;
                }
                ensure!(calls < 4, "execution authority revoked");
                Ok(())
            },
            &mut recovery,
        );
        let entries = recovery.observations();
        let fixed = recovery.deadline();
        let same = scope.control(&mut || Ok(())).deadline();
        eprintln!("expired recovery probe: result={result:?}, accounting={entries:?}");
        ensure!(
            result.is_err() && fixed == same && fixed <= Instant::now(),
            "recovery deadline was reset"
        );
        ensure!(
            !recovery.complete() && scope.0.borrow().retained.len() == 1,
            "failed cleanup dropped ownership"
        );
        let pid = entries.first().context("missing failed helper")?.pid;
        ensure!(
            process_scope::observe(pid)?.is_some(),
            "expired recovery had a late terminating effect"
        );
        Ok(())
    }

    fn detached_case(window: &str) -> Result<()> {
        let dir = tempfile::tempdir()?;
        let cwd = dir.path().canonicalize()?;
        let marker = cwd.join("executed");
        let mut spec = command(
            "/bin/sh",
            &[
                "-c",
                &format!("echo $$ > '{}'; exec /bin/sleep 2", marker.display()),
            ],
            &cwd,
        );
        if window == "setup" {
            spec.cwd = cwd.join("missing");
        }
        if window == "exec" {
            spec.executable = cwd.join("missing");
        }
        let scope = TestScope::new();
        let shared = scope.0.clone();
        let mut recovery_tick = || Ok(());
        let mut recovery = scope.control(&mut recovery_tick);
        let result = launch_detached(
            &spec,
            std::path::Path::new("/bin/sleep"),
            Instant::now() + Duration::from_secs(3),
            &mut || {
                let budget = shared.borrow();
                let entry = budget.actors.last();
                let revoke = match window {
                    "early" => entry.is_some(),
                    "pid" => entry.is_some_and(|e| Some(e.pid) != e.intermediate_pid),
                    "executed" => marker.exists(),
                    _ => false,
                };
                ensure!(!revoke, "execution authority revoked in {window} window");
                Ok(())
            },
            &mut recovery,
        );
        let entries = recovery.observations();
        eprintln!("detached {window} probe: result={result:?}, accounting={entries:?}");
        let entry = entries
            .last()
            .context("missing detached launch accounting")?;
        ensure!(
            result.is_err() && entry.complete && entry.intermediate_reaped,
            "detached cleanup incomplete"
        );
        ensure!(
            entry.intermediate_status.is_some(),
            "intermediate status missing"
        );
        ensure!(
            process_scope::observe(entry.intermediate_pid.unwrap())?.is_none(),
            "intermediate not reaped"
        );
        ensure!(
            process_scope::observe(entry.pid)?.is_none(),
            "launched actor remains"
        );
        if window == "executed" {
            let pid: u32 = std::fs::read_to_string(&marker)?.trim().parse()?;
            ensure!(
                entry.pid == pid && entry.identity.is_some(),
                "executed PID/birth identity forgotten"
            );
        }
        if window == "early" {
            ensure!(
                !marker.exists(),
                "pre-handshake cancellation released actor"
            );
        }
        Ok(())
    }
    #[test]
    fn detached_early_authority_loss_retains_cleanup_disposition() -> Result<()> {
        detached_case("early")
    }
    #[test]
    fn detached_pid_authority_loss_reaps_supervised_child() -> Result<()> {
        detached_case("pid")
    }
    #[test]
    fn detached_executed_authority_loss_disposes_bound_child() -> Result<()> {
        detached_case("executed")
    }
    #[test]
    fn detached_setup_failure_preserves_and_disposes_identities() -> Result<()> {
        detached_case("setup")
    }
    #[test]
    fn detached_exec_failure_preserves_and_disposes_identities() -> Result<()> {
        detached_case("exec")
    }

    #[test]
    fn detached_fork_uncertainty_blocks_complete_accounting() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let cwd = dir.path().canonicalize()?;
        let spec = command("/bin/sh", &["-c", "/bin/sleep 1 & exec /bin/sleep 2"], &cwd);
        let scope = TestScope::new();
        let mut recovery_tick = || Ok(());
        let mut recovery = scope.control(&mut recovery_tick);
        let result = launch_detached(
            &spec,
            std::path::Path::new("/bin/sleep"),
            Instant::now() + Duration::from_secs(3),
            &mut || Ok(()),
            &mut recovery,
        );
        let entries = recovery.observations();
        eprintln!("detached fork probe: result={result:?}, accounting={entries:?}");
        let entry = entries.last().context("missing detached fork accounting")?;
        ensure!(
            result.is_err()
                && !entry.complete
                && !recovery.complete()
                && entry.descendant_uncertainty.is_some(),
            "fork uncertainty was erased"
        );
        ensure!(
            entry.intermediate_reaped && entry.known_absent,
            "known detached actors were not disposed"
        );
        Ok(())
    }

    #[test]
    fn detached_success_preserves_session_launch_and_null_stdio() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let cwd = dir.path().canonicalize()?;
        let marker = cwd.join("verified");
        let script = format!(
            "test /dev/fd/0 -ef /dev/null && test /dev/fd/1 -ef /dev/null && test /dev/fd/2 -ef /dev/null && test \"$CPU_VALUE\" = exact && echo $$ > '{}'; exec /bin/sleep 2",
            marker.display()
        );
        let mut spec = command("/bin/sh", &["-c", &script], &cwd);
        spec.environment.insert("CPU_VALUE".into(), "exact".into());
        let scope = TestScope::new();
        let mut recovery_tick = || Ok(());
        let mut recovery = scope.control(&mut recovery_tick);
        let identity = launch_detached(
            &spec,
            std::path::Path::new("/bin/sleep"),
            Instant::now() + Duration::from_secs(3),
            &mut || Ok(()),
            &mut recovery,
        )?;
        let marker_pid: u32 = std::fs::read_to_string(marker)?.trim().parse()?;
        let entries = recovery.observations();
        eprintln!("detached success probe: identity={identity:?}, accounting={entries:?}");
        ensure!(
            marker_pid == identity.pid
                && identity.ppid == 1
                && identity.pgid == identity.pid
                && identity.sid == identity.pid as i32
                && identity.cwd == cwd,
            "detached launch identity/stdio/environment mismatch"
        );
        let entry = entries.last().unwrap();
        ensure!(
            entry.complete
                && entry.intermediate_reaped
                && serde_json::to_value(&entry.launch_record)? == serde_json::to_value(&spec)?,
            "detached launch record mismatch"
        );
        Ok(())
    }

    #[test]
    fn failed_cpu_replacement_keeps_same_gui_paused_and_blocks_retry() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let service = command("/bin/sleep", &["10"], dir.path());
        let spec = ServiceSpec::OwnedCpu {
            role: ServiceRole::Omlx,
            command: service.clone(),
            restore_command: command("/usr/bin/false", &[], dir.path()),
            gui_command: Some(service),
        };
        let deadline = Instant::now() + Duration::from_secs(8);
        let scope = TestScope::new();
        let mut recovery_tick = || Ok(());
        let mut recovery = scope.control(&mut recovery_tick);
        let mut tick = || Ok(());
        let mut handle = TestHandle(
            ServiceHandle::enroll(
                &spec,
                ScopePurpose::Cpu,
                None,
                deadline,
                &mut tick,
                &mut recovery,
            )?,
            scope.0.clone(),
        );
        let original_gui = handle.gui.clone().unwrap();
        handle.stop(deadline, &mut tick, &mut recovery)?;
        ensure!(
            handle.restore(deadline, &mut tick, &mut recovery).is_err(),
            "false replacement succeeded"
        );
        let failure = handle.failure.clone();
        ensure!(
            handle.restore(deadline, &mut tick, &mut recovery).is_err()
                && handle.failure == failure,
            "failure was not sticky"
        );
        ensure!(
            process_scope::verify_identity(&original_gui)?.state == ProcessState::Stopped,
            "failed restore resumed GUI"
        );
        handle.finish_owned_cpu(&mut recovery)?;
        ensure!(
            process_scope::observe(original_gui.pid)?.is_none(),
            "GUI disposal incomplete"
        );
        Ok(())
    }
    #[test]
    fn cpu_restore_replaces_backend_and_resumes_same_gui_once() -> Result<()> {
        let dir = tempfile::tempdir()?;
        let service = command("/bin/sleep", &["10"], dir.path());
        let spec = ServiceSpec::OwnedCpu {
            role: ServiceRole::Omlx,
            command: service.clone(),
            restore_command: service.clone(),
            gui_command: Some(service),
        };
        let deadline = Instant::now() + Duration::from_secs(8);
        let scope = TestScope::new();
        let mut recovery_tick = || Ok(());
        let mut recovery = scope.control(&mut recovery_tick);
        let mut tick = || Ok(());
        let mut handle = TestHandle(
            ServiceHandle::enroll(
                &spec,
                ScopePurpose::Cpu,
                None,
                deadline,
                &mut tick,
                &mut recovery,
            )?,
            scope.0.clone(),
        );
        let original = handle.root.clone().unwrap();
        let gui = handle.gui.clone().unwrap();
        ensure!(
            handle.stop(deadline, &mut tick, &mut recovery)?.inhibited,
            "service not inhibited"
        );
        ensure!(
            handle.stop(deadline, &mut tick, &mut recovery).is_err(),
            "stop retried"
        );
        let restored = handle.restore(deadline, &mut tick, &mut recovery)?;
        ensure!(
            restored.restored && !original.same_process(restored.root.as_ref().unwrap()),
            "backend not replaced"
        );
        ensure!(
            process_scope::verify_identity(&gui)?.state == ProcessState::Running,
            "GUI not resumed"
        );
        ensure!(
            handle.restore(deadline, &mut tick, &mut recovery).is_err(),
            "restore retried"
        );
        let replacement = handle.root.clone().unwrap();
        handle.finish_owned_cpu(&mut recovery)?;
        ensure!(
            process_scope::observe(replacement.pid)?.is_none()
                && process_scope::observe(gui.pid)?.is_none(),
            "fixture disposal incomplete"
        );
        Ok(())
    }
}

fn verify_gui_group(
    gui: &ProcessIdentity,
    expected: &[ProcessIdentity],
    state: Option<ProcessState>,
) -> Result<()> {
    process_scope::verify_identity(gui)?;
    let members = process_scope::group_members(gui.pgid)?;
    ensure!(
        members.len() == expected.len()
            && members
                .iter()
                .all(|member| expected.iter().any(|bound| bound.same_process(member))),
        "GUI group differs from exact reviewed scope"
    );
    if let Some(state) = state {
        ensure!(
            members.iter().all(|member| member.state == state),
            "GUI group state mismatch"
        );
    }
    Ok(())
}
fn above_stdio(file: std::fs::File) -> Result<std::fs::File> {
    use std::os::fd::{AsRawFd, FromRawFd};
    if file.as_raw_fd() > 2 {
        return Ok(file);
    }
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    ensure!(fd >= 3, "cannot isolate detached launch descriptor");
    Ok(unsafe { std::fs::File::from_raw_fd(fd) })
}
