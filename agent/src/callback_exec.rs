#[cfg(windows)]
use winapi::um::threadpoolapiset::{CloseThreadpoolWork, CreateThreadpoolWork, SubmitThreadpoolWork};
#[cfg(windows)]
use winapi::um::minwinbase::PTP_CALLBACK_INSTANCE;
#[cfg(windows)]
use winapi::um::winnt::PVOID;
#[cfg(windows)]
use winapi::um::minwinbase::PTP_WORK;

#[cfg(windows)]
extern "system" fn threadpool_callback(_instance: PTP_CALLBACK_INSTANCE, context: PVOID, _work: PTP_WORK) {
    if context.is_null() {
        return;
    }
    let closure: Box<Box<dyn FnOnce() + Send>> = unsafe { Box::from_raw(context as *mut _) };
    closure();
}

#[cfg(windows)]
pub fn execute_in_threadpool<F>(f: F) -> Result<(), anyhow::Error>
where
    F: FnOnce() + Send + 'static,
{
    let closure: Box<Box<dyn FnOnce() + Send>> = Box::new(Box::new(f));
    let context = Box::into_raw(closure) as PVOID;
    
    unsafe {
        let work = CreateThreadpoolWork(Some(threadpool_callback), context, std::ptr::null_mut());
        if work.is_null() {
            // reclaim memory to avoid leak
            let _ = Box::from_raw(context as *mut Box<dyn FnOnce() + Send>);
            anyhow::bail!("CreateThreadpoolWork failed");
        }
        
        SubmitThreadpoolWork(work);
        
        // We leak the work handle here unless we find a way to wait on it or clean it up,
        // Wait, standard practice is that we can close the work item immediately after submission
        // unless we want to wait for it. SubmitThreadpoolWork queues it. CloseThreadpoolWork 
        // releases the handle but the pending work item is still executed.
        // Actually, if we close it here, the system might not execute it?
        // No, CloseThreadpoolWork docs say "If there are outstanding callbacks, they will complete".
        CloseThreadpoolWork(work);
    }
    
    Ok(())
}

#[cfg(windows)]
pub fn execute_task<F>(f: F) -> Result<(), anyhow::Error>
where
    F: FnOnce() + Send + 'static,
{
    // Check config via a global or pass it? Here we just use the threadpool for everything.
    execute_in_threadpool(f)
}
