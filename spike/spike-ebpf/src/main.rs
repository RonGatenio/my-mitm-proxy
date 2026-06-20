#![no_std]
#![no_main]

use aya_ebpf::{bindings::TC_ACT_OK, macros::classifier, programs::TcContext};

#[classifier]
pub fn spike(_ctx: TcContext) -> i32 {
    TC_ACT_OK
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
