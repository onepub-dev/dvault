use std::io;
use std::thread;

#[cfg(windows)]
use std::sync::mpsc::Sender;
#[cfg(any(windows, test))]
use std::sync::mpsc::{self, Receiver};

#[cfg(unix)]
type SleepHandler = Box<dyn FnMut(SleepEvent) + Send>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SleepEvent {
    SuspendRequested,
    Resumed,
}

pub(crate) struct SleepWatcher {
    #[cfg(any(windows, test))]
    receiver: Receiver<SleepEvent>,
}

pub(crate) struct SleepInhibitor {
    _inner: platform::SleepInhibitor,
}

/// Platform sleep/suspend capabilities used by the lockbox session agent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AgentSleepSupport {
    /// True when the agent can receive suspend/resume notifications.
    pub suspend_notifications: bool,
    /// True when active secret operations can request temporary sleep inhibition.
    pub sleep_inhibition: bool,
}

impl AgentSleepSupport {
    /// True when all sleep/suspend management features are available.
    pub fn supported(self) -> bool {
        self.suspend_notifications && self.sleep_inhibition
    }
}

/// Returns sleep/suspend capabilities compiled for the current platform.
pub fn agent_sleep_support() -> AgentSleepSupport {
    platform::agent_sleep_support()
}

impl SleepInhibitor {
    pub(crate) fn acquire_active(reason: &str) -> io::Result<Self> {
        platform::SleepInhibitor::acquire_active(reason).map(|inner| Self { _inner: inner })
    }
}

impl SleepWatcher {
    #[cfg(windows)]
    pub(crate) fn start() -> io::Result<Self> {
        let (sender, receiver) = mpsc::channel();
        platform::spawn(sender)?;
        Ok(Self { receiver })
    }

    #[cfg(unix)]
    pub(crate) fn start_handler(
        handler: impl FnMut(SleepEvent) + Send + 'static,
    ) -> io::Result<()> {
        platform::spawn_handler(Box::new(handler))
    }

    #[cfg(test)]
    pub(crate) fn drain(&self) -> Vec<SleepEvent> {
        let mut events = Vec::new();
        while let Ok(event) = self.receiver.try_recv() {
            events.push(event);
        }
        events
    }

    #[cfg(windows)]
    pub(crate) fn recv(&self) -> Result<SleepEvent, mpsc::RecvError> {
        self.receiver.recv()
    }

    #[cfg(test)]
    pub(crate) fn from_events(events: impl IntoIterator<Item = SleepEvent>) -> Self {
        let (sender, receiver) = mpsc::channel();
        for event in events {
            let _ = sender.send(event);
        }
        Self { receiver }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use dbus::arg::OwnedFd;
    use dbus::blocking::Connection;
    use dbus::blocking::Proxy;
    use dbus::message::MatchRule;
    use std::time::Duration;

    pub(super) fn spawn_handler(handler: SleepHandler) -> io::Result<()> {
        let connection =
            Connection::new_system().map_err(|err| io::Error::other(err.to_string()))?;
        let mut inhibitor = acquire_sleep_inhibitor(&connection).ok();
        let rule = MatchRule::new_signal("org.freedesktop.login1.Manager", "PrepareForSleep")
            .with_sender("org.freedesktop.login1")
            .with_path("/org/freedesktop/login1");
        let mut handler = handler;
        connection
            .add_match(rule, move |(sleeping,): (bool,), connection, _| {
                let event = if sleeping {
                    SleepEvent::SuspendRequested
                } else {
                    SleepEvent::Resumed
                };
                handler(event);
                if sleeping {
                    drop(inhibitor.take());
                } else {
                    inhibitor = acquire_sleep_inhibitor(connection).ok();
                }
                true
            })
            .map_err(|err| io::Error::other(err.to_string()))?;
        thread::Builder::new()
            .name("lockbox-sleep-watcher".to_string())
            .spawn(move || watch_logind(connection))
            .map(|_| ())
    }

    pub(super) fn agent_sleep_support() -> AgentSleepSupport {
        AgentSleepSupport {
            suspend_notifications: true,
            sleep_inhibition: true,
        }
    }

    pub(super) struct SleepInhibitor {
        _fd: OwnedFd,
    }

    impl SleepInhibitor {
        pub(super) fn acquire_active(reason: &str) -> io::Result<Self> {
            let connection =
                Connection::new_system().map_err(|err| io::Error::other(err.to_string()))?;
            acquire_logind_inhibitor(&connection, reason, "block")
                .map(|fd| Self { _fd: fd })
                .map_err(|err| io::Error::other(err.to_string()))
        }
    }

    fn watch_logind(connection: Connection) {
        loop {
            if connection.process(Duration::from_secs(60)).is_err() {
                return;
            }
        }
    }

    fn acquire_sleep_inhibitor(connection: &Connection) -> Result<OwnedFd, dbus::Error> {
        acquire_logind_inhibitor(
            connection,
            "Clear cached lockbox keys before system sleep",
            "delay",
        )
    }

    fn acquire_logind_inhibitor(
        connection: &Connection,
        reason: &str,
        mode: &str,
    ) -> Result<OwnedFd, dbus::Error> {
        let proxy = Proxy::new(
            "org.freedesktop.login1",
            "/org/freedesktop/login1",
            Duration::from_secs(5),
            connection,
        );
        let (fd,): (OwnedFd,) = proxy.method_call(
            "org.freedesktop.login1.Manager",
            "Inhibit",
            ("sleep", "lockbox", reason, mode),
        )?;
        Ok(fd)
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use objc2_core_foundation::{kCFRunLoopDefaultMode, CFRunLoop};
    use objc2_io_kit::{
        io_connect_t, io_object_t, io_service_t, kIOMessageCanSystemSleep,
        kIOMessageSystemHasPoweredOn, kIOMessageSystemWillSleep, IOAllowPowerChange,
        IONotificationPort, IONotificationPortRef, IORegisterForSystemPower,
    };
    use std::ffi::{c_char, c_void, CString};
    use std::ptr::null_mut;
    use std::sync::Mutex;

    struct CallbackContext {
        handler: Mutex<SleepHandler>,
        root_port: io_connect_t,
    }

    pub(super) fn spawn_handler(handler: SleepHandler) -> io::Result<()> {
        thread::Builder::new()
            .name("lockbox-sleep-watcher".to_string())
            .spawn(move || watch_iokit(handler))
            .map(|_| ())
    }

    pub(super) fn agent_sleep_support() -> AgentSleepSupport {
        AgentSleepSupport {
            suspend_notifications: true,
            sleep_inhibition: true,
        }
    }

    pub(super) struct SleepInhibitor {
        assertion_id: u32,
    }

    impl SleepInhibitor {
        pub(super) fn acquire_active(reason: &str) -> io::Result<Self> {
            let assertion_type = CfString::new("NoIdleSleepAssertion")?;
            let reason = CfString::new(reason)?;
            let mut assertion_id = 0u32;
            // SAFETY: The CFString references are valid for the duration of
            // this call and `assertion_id` is a writable out pointer.
            let result = unsafe {
                IOPMAssertionCreateWithName(
                    assertion_type.as_raw(),
                    K_IOPM_ASSERTION_LEVEL_ON,
                    reason.as_raw(),
                    &mut assertion_id,
                )
            };
            if result == 0 {
                Ok(Self { assertion_id })
            } else {
                Err(io::Error::from_raw_os_error(result))
            }
        }
    }

    impl Drop for SleepInhibitor {
        fn drop(&mut self) {
            // SAFETY: `assertion_id` was returned by
            // `IOPMAssertionCreateWithName` and is released exactly once.
            unsafe {
                IOPMAssertionRelease(self.assertion_id);
            }
        }
    }

    struct CfString {
        raw: *const c_void,
    }

    impl CfString {
        fn new(value: &str) -> io::Result<Self> {
            let value = CString::new(value).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "string contains NUL byte")
            })?;
            // SAFETY: `value` is a valid NUL-terminated C string and the
            // returned object is owned by this wrapper.
            let raw = unsafe {
                CFStringCreateWithCString(
                    std::ptr::null(),
                    value.as_ptr(),
                    K_CF_STRING_ENCODING_UTF8,
                )
            };
            if raw.is_null() {
                Err(io::Error::other("failed to allocate CFString"))
            } else {
                Ok(Self { raw })
            }
        }

        fn as_raw(&self) -> *const c_void {
            self.raw
        }
    }

    impl Drop for CfString {
        fn drop(&mut self) {
            // SAFETY: `raw` is a Core Foundation object owned by this wrapper.
            unsafe {
                CFRelease(self.raw);
            }
        }
    }

    const K_CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
    const K_IOPM_ASSERTION_LEVEL_ON: u32 = 255;

    #[link(name = "CoreFoundation", kind = "framework")]
    extern "C" {
        fn CFStringCreateWithCString(
            alloc: *const c_void,
            c_str: *const c_char,
            encoding: u32,
        ) -> *const c_void;
        fn CFRelease(cf: *const c_void);
    }

    #[link(name = "IOKit", kind = "framework")]
    extern "C" {
        fn IOPMAssertionCreateWithName(
            assertion_type: *const c_void,
            level: u32,
            reason: *const c_void,
            assertion_id: *mut u32,
        ) -> i32;
        fn IOPMAssertionRelease(assertion_id: u32) -> i32;
    }

    fn watch_iokit(handler: SleepHandler) {
        let mut notification_port: IONotificationPortRef = null_mut();
        let mut notifier: io_object_t = 0;
        let context = Box::new(CallbackContext {
            handler: Mutex::new(handler),
            root_port: 0,
        });
        let context_ptr = Box::into_raw(context);
        // SAFETY: `context_ptr`, `notification_port`, and `notifier` are valid
        // for this registration call. The watcher thread runs the Core
        // Foundation loop for the process lifetime of the agent.
        let root_port = unsafe {
            IORegisterForSystemPower(
                context_ptr.cast::<c_void>(),
                &mut notification_port,
                Some(sleep_callback),
                &mut notifier,
            )
        };
        if root_port == 0 || notification_port.is_null() {
            // SAFETY: Reclaims the boxed context when registration failed.
            unsafe {
                drop(Box::from_raw(context_ptr));
            }
            return;
        }
        // SAFETY: The context allocation remains owned by this thread for as
        // long as the run loop is active.
        unsafe {
            (*context_ptr).root_port = root_port;
        }
        // SAFETY: `notification_port` was returned by IOKit and produces a
        // valid run-loop source while the notification port remains alive.
        let Some(source) = (unsafe { IONotificationPort::run_loop_source(notification_port) })
        else {
            return;
        };
        let Some(run_loop) = CFRunLoop::current() else {
            return;
        };
        // SAFETY: Core Foundation provides this global run-loop mode constant
        // for process-wide read-only use.
        let default_mode = unsafe { kCFRunLoopDefaultMode };
        run_loop.add_source(Some(&source), default_mode);
        CFRunLoop::run();
    }

    unsafe extern "C-unwind" fn sleep_callback(
        refcon: *mut c_void,
        _service: io_service_t,
        message_type: u32,
        message_argument: *mut c_void,
    ) {
        let context = unsafe { &*(refcon.cast::<CallbackContext>()) };
        match message_type {
            event if event == kIOMessageCanSystemSleep => {
                IOAllowPowerChange(context.root_port, message_argument as isize);
            }
            event if event == kIOMessageSystemWillSleep => {
                if let Ok(mut handler) = context.handler.lock() {
                    handler(SleepEvent::SuspendRequested);
                }
                IOAllowPowerChange(context.root_port, message_argument as isize);
            }
            event if event == kIOMessageSystemHasPoweredOn => {
                if let Ok(mut handler) = context.handler.lock() {
                    handler(SleepEvent::Resumed);
                }
            }
            _ => {}
        }
    }
}

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ffi::c_void;
    use windows_sys::Win32::System::Power::{
        RegisterSuspendResumeNotification, SetThreadExecutionState,
        UnregisterSuspendResumeNotification, DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS, ES_CONTINUOUS,
        ES_SYSTEM_REQUIRED,
    };
    use windows_sys::Win32::UI::WindowsAndMessaging::{
        DEVICE_NOTIFY_CALLBACK, PBT_APMRESUMEAUTOMATIC, PBT_APMRESUMESUSPEND, PBT_APMSUSPEND,
    };

    pub(super) fn spawn(sender: Sender<SleepEvent>) -> io::Result<()> {
        thread::Builder::new()
            .name("lockbox-sleep-watcher".to_string())
            .spawn(move || watch_power_notifications(sender))
            .map(|_| ())
    }

    pub(super) fn agent_sleep_support() -> AgentSleepSupport {
        AgentSleepSupport {
            suspend_notifications: true,
            sleep_inhibition: true,
        }
    }

    pub(super) struct SleepInhibitor;

    impl SleepInhibitor {
        pub(super) fn acquire_active(_reason: &str) -> io::Result<Self> {
            // SAFETY: `SetThreadExecutionState` has no Rust-side memory
            // invariants and stores process/thread execution-state flags.
            let previous = unsafe { SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED) };
            if previous == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(Self)
            }
        }
    }

    impl Drop for SleepInhibitor {
        fn drop(&mut self) {
            // SAFETY: Restores the continuous execution state flag when the
            // inhibitor guard is dropped.
            unsafe {
                SetThreadExecutionState(ES_CONTINUOUS);
            }
        }
    }

    fn watch_power_notifications(sender: Sender<SleepEvent>) {
        let sender = Box::new(sender);
        let context = Box::into_raw(sender);
        let mut params = DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS {
            Callback: Some(power_callback),
            Context: context.cast::<c_void>(),
        };
        // SAFETY: `params` points to a valid subscription record while the
        // watcher thread parks below. The callback context is a boxed Sender
        // that also lives for the process lifetime of the agent.
        let registration = unsafe {
            RegisterSuspendResumeNotification(
                (&mut params as *mut DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS).cast(),
                DEVICE_NOTIFY_CALLBACK,
            )
        };
        if registration == 0 {
            // SAFETY: Reclaims the boxed sender when registration failed.
            unsafe {
                drop(Box::from_raw(context));
            }
            return;
        }
        loop {
            thread::park();
        }
        #[allow(unreachable_code)]
        unsafe {
            UnregisterSuspendResumeNotification(registration);
            drop(Box::from_raw(context));
        }
    }

    unsafe extern "system" fn power_callback(
        context: *const c_void,
        event_type: u32,
        _setting: *const c_void,
    ) -> u32 {
        if context.is_null() {
            return 0;
        }
        let sender = unsafe { &*(context.cast::<Sender<SleepEvent>>()) };
        match event_type {
            PBT_APMSUSPEND => {
                let _ = sender.send(SleepEvent::SuspendRequested);
            }
            PBT_APMRESUMESUSPEND | PBT_APMRESUMEAUTOMATIC => {
                let _ = sender.send(SleepEvent::Resumed);
            }
            _ => {}
        }
        0
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
mod platform {
    use super::*;

    pub(super) fn agent_sleep_support() -> AgentSleepSupport {
        AgentSleepSupport {
            suspend_notifications: false,
            sleep_inhibition: false,
        }
    }

    pub(super) struct SleepInhibitor;

    impl SleepInhibitor {
        pub(super) fn acquire_active(_reason: &str) -> io::Result<Self> {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "sleep inhibition is not supported on this platform",
            ))
        }
    }

    #[cfg(unix)]
    pub(super) fn spawn_handler(_handler: SleepHandler) -> io::Result<()> {
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "sleep notifications are not supported on this platform",
        ))
    }
}
