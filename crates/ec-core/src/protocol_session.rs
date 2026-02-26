use crate::error::{EcError, EcResult};
use foreign_types::ForeignType;
use openssl::error::ErrorStack;
use openssl::ssl::Ssl;
use openssl_sys as ffi;
use std::ffi::c_uint;

pub(crate) fn apply_l3ip_session_id(ssl: &mut Ssl, session_version: i32) -> EcResult<()> {
    let sid = l3ip_session_id();
    let master_key = l3ip_master_key();
    unsafe {
        let session = ssl_session_new().ok_or_else(|| {
            EcError::Runtime(format!("create SSL_SESSION failed: {}", ErrorStack::get()))
        })?;

        let set_proto_rc = ssl_session_set_protocol_version(session, session_version);
        if set_proto_rc != 1 {
            ffi::SSL_SESSION_free(session);
            return Err(EcError::Runtime(format!(
                "SSL_SESSION_set_protocol_version failed: {}",
                ErrorStack::get()
            )));
        }

        let set_master_rc =
            ssl_session_set1_master_key(session, master_key.as_ptr(), master_key.len() as c_uint);
        if set_master_rc != 1 {
            ffi::SSL_SESSION_free(session);
            return Err(EcError::Runtime(format!(
                "SSL_SESSION_set1_master_key failed: {}",
                ErrorStack::get()
            )));
        }

        let set_id_rc = ssl_session_set1_id(session, sid.as_ptr(), sid.len() as c_uint);
        if set_id_rc != 1 {
            ffi::SSL_SESSION_free(session);
            return Err(EcError::Runtime(format!(
                "SSL_SESSION_set1_id failed: {}",
                ErrorStack::get()
            )));
        }

        let set_session_rc = ffi::SSL_set_session(ssl.as_ptr(), session);
        ffi::SSL_SESSION_free(session);
        if set_session_rc != 1 {
            return Err(EcError::Runtime(format!(
                "SSL_set_session failed: {}",
                ErrorStack::get()
            )));
        }
    }
    Ok(())
}

fn l3ip_session_id() -> [u8; 32] {
    let mut sid = [0u8; 32];
    sid[0] = b'L';
    sid[1] = b'3';
    sid[2] = b'I';
    sid[3] = b'P';
    sid
}

fn l3ip_master_key() -> [u8; 48] {
    let mut key = [0u8; 48];
    for (i, v) in key.iter_mut().enumerate() {
        *v = ((i as u8) ^ 0x5a).wrapping_add(0x11);
    }
    key
}

unsafe fn ssl_session_new() -> Option<*mut ffi::SSL_SESSION> {
    unsafe extern "C" {
        fn SSL_SESSION_new() -> *mut ffi::SSL_SESSION;
    }
    let ptr = unsafe { SSL_SESSION_new() };
    if ptr.is_null() { None } else { Some(ptr) }
}

unsafe fn ssl_session_set1_id(session: *mut ffi::SSL_SESSION, sid: *const u8, len: c_uint) -> i32 {
    unsafe extern "C" {
        fn SSL_SESSION_set1_id(s: *mut ffi::SSL_SESSION, sid: *const u8, sid_len: c_uint) -> i32;
    }
    if session.is_null() || sid.is_null() {
        return 0;
    }
    unsafe { SSL_SESSION_set1_id(session, sid, len) }
}

unsafe fn ssl_session_set_protocol_version(session: *mut ffi::SSL_SESSION, version: i32) -> i32 {
    unsafe extern "C" {
        fn SSL_SESSION_set_protocol_version(s: *mut ffi::SSL_SESSION, version: i32) -> i32;
    }
    if session.is_null() {
        return 0;
    }
    unsafe { SSL_SESSION_set_protocol_version(session, version) }
}

unsafe fn ssl_session_set1_master_key(
    session: *mut ffi::SSL_SESSION,
    key: *const u8,
    len: c_uint,
) -> i32 {
    unsafe extern "C" {
        fn SSL_SESSION_set1_master_key(
            sess: *mut ffi::SSL_SESSION,
            key: *const u8,
            len: c_uint,
        ) -> i32;
    }
    if session.is_null() || key.is_null() {
        return 0;
    }
    unsafe { SSL_SESSION_set1_master_key(session, key, len) }
}
