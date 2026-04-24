with open("agent/src/obfuscated_sleep.rs", "r") as f:
    c = f.read()

c = c.replace("DeleteTimerQueue", "DeleteTimerQueueEx")
c = c.replace("PVOID", "LPVOID")
c = c.replace("DeleteTimerQueueEx(h_timer_queue)", "DeleteTimerQueueEx(h_timer_queue, std::ptr::null_mut())")

with open("agent/src/obfuscated_sleep.rs", "w") as f:
    f.write(c)

