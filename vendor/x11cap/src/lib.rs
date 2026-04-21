// Patched for Rust 1.56+: replaced unstable `Unique<T>` with `NonNull<T>`.
// Original: https://crates.io/crates/x11cap 0.1.0 (MIT)

//! Capture the screen with xlib

#![allow(dead_code, non_upper_case_globals, non_camel_case_types)]

extern crate x11;
extern crate libc;

use ffi::*;
use x11::xlib;
use libc::c_int;
use std::ffi::CString;
use std::ptr::{self, NonNull};
use std::slice;

pub mod ffi;

#[derive(Debug, Eq, PartialEq, Clone, Copy)]
#[repr(C, packed)]
pub struct RGB8 {
    pub r: u8,
    pub g: u8,
    pub b: u8,
}

pub enum Display {
    Address(&'static str),
    Default,
}

#[derive(Clone, Copy)]
pub enum Screen {
    Specific(c_int),
    Default,
}

#[derive(Clone, Copy)]
pub enum Window {
    Window(xlib::Window),
    Desktop,
}

struct WindowConnection {
    display: NonNull<xlib::Display>,
    window: xlib::Window,
    width: u32,
    height: u32,
}

impl WindowConnection {
    fn new(display: Display, screen: Screen, window: Window) -> Result<WindowConnection, ()> {
        let raw = unsafe {
            xlib::XOpenDisplay(if let Display::Address(address) = display {
                match CString::new(address) {
                    Ok(s) => s.as_ptr(),
                    Err(_) => return Err(()),
                }
            } else {
                ptr::null()
            })
        };

        let display_ptr = match NonNull::new(raw) {
            Some(p) => p,
            None => return Err(()),
        };

        let screen_num = if let Screen::Specific(n) = screen {
            n
        } else {
            unsafe { xlib::XDefaultScreen(display_ptr.as_ptr()) }
        };

        let mut window_id = if let Window::Window(id) = window {
            id
        } else {
            unsafe { xlib::XRootWindow(display_ptr.as_ptr(), screen_num) }
        };

        let (mut window_width, mut window_height) = (0u32, 0u32);

        let ok = unsafe {
            xlib::XGetGeometry(
                display_ptr.as_ptr(),
                window_id,
                &mut window_id,
                &mut 0,
                &mut 0,
                &mut window_width,
                &mut window_height,
                &mut 0,
                &mut 0,
            ) != 0
        };

        if ok {
            Ok(WindowConnection {
                display: display_ptr,
                window: window_id,
                width: window_width,
                height: window_height,
            })
        } else {
            Err(())
        }
    }
}

impl Drop for WindowConnection {
    fn drop(&mut self) {
        unsafe {
            xlib::XCloseDisplay(self.display.as_ptr());
        }
    }
}

/// Possible errors when capturing
#[derive(Debug)]
pub enum CaptureError {
    Fail(&'static str),
}

pub struct Capturer {
    screen: Screen,
    window_conn: WindowConnection,
}

impl Capturer {
    pub fn new(screen: Screen) -> Result<Capturer, ()> {
        match WindowConnection::new(Display::Default, screen, Window::Desktop) {
            Ok(conn) => Ok(Capturer {
                screen,
                window_conn: conn,
            }),
            Err(_) => Err(()),
        }
    }

    fn connect(&mut self) -> Result<(), ()> {
        match WindowConnection::new(Display::Default, self.screen, Window::Desktop) {
            Ok(conn) => {
                self.window_conn = conn;
                Ok(())
            }
            Err(_) => Err(()),
        }
    }

    pub fn capture_frame(&mut self) -> Result<(Vec<RGB8>, (u32, u32)), CaptureError> {
        let image_ptr = unsafe {
            xlib::XGetImage(
                self.window_conn.display.as_ptr(),
                self.window_conn.window,
                0,
                0,
                self.window_conn.width,
                self.window_conn.height,
                AllPlanes,
                ZPixmap,
            )
        };

        if image_ptr.is_null() {
            return Err(CaptureError::Fail("XGetImage returned null pointer"));
        }

        let image = unsafe { &mut *image_ptr };

        unsafe {
            if image.depth == 24
                && image.bits_per_pixel == 32
                && image.red_mask == 0xFF0000
                && image.green_mask == 0xFF00
                && image.blue_mask == 0xFF
            {
                let raw_img_data = slice::from_raw_parts(
                    image.data as *mut (RGB8, u8),
                    image.width as usize * image.height as usize,
                )
                .iter()
                .map(|&(pixel, _)| pixel)
                .collect();

                xlib::XFree(image_ptr as *mut _);
                Ok((raw_img_data, (image.width as u32, image.height as u32)))
            } else {
                xlib::XFree(image_ptr as *mut _);
                Err(CaptureError::Fail("WRONG LAYOUT"))
            }
        }
    }
}
