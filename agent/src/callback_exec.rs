#[cfg(windows)]
use winapi::um::threadpoolapiset::{CloseThreadpoolWork, CreateThreadpoolWork, SubmitThreadpoolWork};
#[cfg(windows)]
use winapi::um::winnt::{PTP_CALLBACK_INSTANCE, PVOID, PTP_WORK, WT_EXECUTEINTIMERTHREAD};
#[cfg(windows)]
use winapi::um::winuser::{EnumChildWindows, FindWindowA};
#[cfg(windows)]
use winapi::um::threadpoollegacyapiset::{CreateTimerQueueTimer, DeleteTimerQueueTimer};
#[cfg(windows)]
use winapi::um::synchapi::WaitForSingleObject;
#[cfg(windows)]
use winapi::um::winnls::EnumSystemLocalesEx;
#[cfg(windows)]
use winapi::shared::minwindef::{BOOL, LPARAM, TRUE, FALSE};
#[cfg(windows)]
use winapi::shared::ntdef::HANDLE;

pub enum CallbackType {
    ThreadpoolWork,
    EnumChildWindows,
    CreateTimerQueueTimer,
    EnumSystemLocalesA,
}

#[cfg(windows)]
extern "system" fn threadpool_callback(_instance: PTP_CALLBACK_INSTANCE, context: PVOID, work: PTP_WORK) {
    if !context.is_null() {
        let closure: Box<Box<dyn FnOnce() + Send>> = unsafe { Box::from_raw(context as *mut _) };
        closure();
    }
    if !work.is_null() {
        unsafe { CloseThreadpoolWork(work) };
    }
}

#[cfg(windows)]
pub fn execute_in_threadpool<F>(f: F) -> Result<(), anyhow::Error>
where F: FnOnce() + Send + 'static {
    let closure: Box<Box<dyn FnOnce() + Send>> = Box::new(Box::new(f));
    let context = Box::into_raw(closure) as PVOID;
    unsafe {
        let work = CreateThreadpoolWork(Some(threadpool_callback), context, std::ptr::null_mut());
        if work.is_null() {
            let _ = Box::from_raw(context as *mut Box<dyn FnOnce() + Send>);
            anyhow::bail!("CreateThreadpoolWork failed");
        }
        SubmitThreadpoolWork(work);
    }
    Ok(())
}

#[cfg(windows)]
extern "system" fn child_windows_callback(_hwnd: winapi::shared::windef::HWND, lparam: LPARAM) -> BOOL {
    if lparam != 0 {
        let closure: Box<Box<dyn FnOnce() + Send>> = unsafe { Box::from_raw(lparam as *mut _) };
        closure();
    }
    FALSE // Stop enumeration
}

#[cfg(windows)]
pub fn execute_enum_child_windows<F>(f: F) -> Result<(), anyhow::Error>
where F: FnOnce() + Send + 'static {
    let closure: Box<Box<dyn FnOnce() + Send>> = Box::new(Box::new(f));
    let lparam = Box::into_raw(closure) as LPARAM;
    unsafe {
        let parent = FindWindowA(b"Shell_TrayWnd\0".as_ptr() as _, std::ptr::null());
        if !parent.is_null() {
            EnumChildWindows(parent, Some(child_windows_callback), lparam);
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
extern "system" fn timer_queue_callback(param: PVOID, _timer_or_wait_fired: winapi::um::winnt::BOOLEAN) {
    if param.is_null() { return; }
    // SAFETY: execute_timer_queue gives us sole ownership of this allocation;
    // Box::from_raw reclaims it when this function returns.
    let ctx = unsafe { Box::from_raw(param as *mut TimerQueueCtx) };
    // Run the user closure.
    if let Ok(mut g) = ctx.closure.lock() {
        if let Some(f) = g.take() { f(); }
    }
    // Spin-wait until execute_timer_queue writes the timer handle (the race
    // window is extremely narrow: dwDueTime=0 still requires a scheduler
    // round-trip before this thread runs).
    let mut h = 0usize;
    for _ in 0..10_000 {
        h = ctx.timer_handle.load(std::sync::atomic::Ordering::Acquire);
        if h != 0 { break; }
        std::hint::spin_loop();
    }
    // Delete the one-shot timer to release its kernel object.
    if h != 0 {
        unsafe {
            DeleteTimerQueueTimer(
                std::ptr::null_mut(),
                h as HANDLE,
                std::ptr::null_mut(),
            );
        }
    }
    // ctx is dropped here, freeing the heap allocation.
}

#[cfg(windows)]
pub fn execute_timer_queue<F>(f: F) -> Result<(), anyhow::Error>
where F: FnOnce() + Send + 'static {
    let ctx = Box::new(TimerQueueCtx {
        timer_handle: std::sync::atomic::AtomicUsize::new(0),
        closure: std::sync::Mutex::new(Some(Box::new(f) as Box<dyn FnOnce() + Send>)),
    });
    let ctx_ptr = Box::into_raw(ctx);
    unsafe {
        let mut handle: HANDLE = std::ptr::null_mut();
        if CreateTimerQueueTimer(&mut handle, std::ptr::null_mut(), Some(timer_queue_callback), ctx_ptr as PVOID, 0, 0, WT_EXECUTEINTIMERTHREAD) == 0 {
            // Reclaim the allocation since no callback will free it.
            drop(Box::from_raw(ctx_ptr));
            anyhow::bail!("CreateTimerQueueTimer failed");
        }
        // Store the handle so the callback can call DeleteTimerQueueTimer.
        (*ctx_ptr).timer_handle.store(handle as usize, std::sync::atomic::Ordering::Release);
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
where F: FnOnce() + Send + 'static {
    use winapi::um::winnls::EnumSystemLocalesEx;
    let closure: Box<Box<dyn FnOnce() + Send>> = Box::new(Box::new(f));
    let lparam = Box::into_raw(closure) as LPARAM;
    unsafe {
        // LOCALE_ALL = 0; EnumSystemLocalesEx passes lparam to the callback.
        if EnumSystemLocalesEx(Some(enum_locales_ex_callback), 0, lparam, std::ptr::null_mut()) == FALSE {
            // Reclaim the closure if the API failed before any callback.
            let _ = Box::from_raw(lparam as *mut Box<dyn FnOnce() + Send>);
            anyhow::bail!("EnumSystemLocalesEx failed");
        }
    }
    Ok(())
}

#[cfg(windows)]
pub fn execute_task<F>(cb_type: CallbackType, f: F) -> Result<(), anyhow::Error>
where F: FnOnce() + Send + 'static {
    match cb_type {
        CallbackType::ThreadpoolWork => execute_in_threadpool(f),
        CallbackType::EnumChildWindows => execute_enum_child_windows(f),
        CallbackType::CreateTimerQueueTimer => execute_timer_queue(f),
        CallbackType::EnumSystemLocalesA => execute_enum_system_locales(f),
    }
}
