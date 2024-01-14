use std::ffi::CString;
use std::marker::PhantomData;
use std::net::IpAddr;
use std::os::unix::prelude::OsStrExt;
use std::path::Path;
use std::pin::Pin;
use std::ptr;

use anyhow::Context;
use autocxx::prelude::*;

include_cpp! {
    #include "modsecurity/modsecurity.h"
    #include "modsecurity/rules_set.h"
    #include "modsecurity/transaction.h"
    #include "modsecurity/intervention.h"
    safety!(unsafe)
    generate!("modsecurity::ModSecurity")
    generate!("modsecurity::RulesSet")
    generate!("modsecurity::Transaction")
    generate_pod!("modsecurity::ModSecurityIntervention_t")
}

#[repr(transparent)]
pub struct ModSecurity {
    inner: Pin<Box<ffi::modsecurity::ModSecurity>>,
}

#[repr(transparent)]
pub struct RulesSet {
    inner: Pin<Box<ffi::modsecurity::RulesSet>>,
}

#[repr(transparent)]
pub struct Transaction<'m, 'r> {
    inner: Pin<Box<ffi::modsecurity::Transaction>>,
    _modsec_phantom: PhantomData<&'m ModSecurity>,
    _rules_phantom: PhantomData<&'r RulesSet>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct Intervention {
    status: u16,
    pause: bool,
    url: String,
    log: String,
    disruptive: bool,
}

unsafe fn lossy_string_from_ptr(ptr: *mut i8) -> String {
    if !ptr.is_null() {
        CString::from_raw(ptr).to_string_lossy().to_string()
    } else {
        String::new()
    }
}

impl From<ffi::modsecurity::ModSecurityIntervention> for Intervention {
    fn from(o: ffi::modsecurity::ModSecurityIntervention) -> Self {
        Self {
            status: o.status as _,
            pause: o.pause != 0,
            disruptive: o.disruptive != 0,
            // # Safety: libmodsecurity must not reassign the pointer
            url: unsafe { lossy_string_from_ptr(o.url) },
            log: unsafe { lossy_string_from_ptr(o.log) },
        }
    }
}

impl<'m, 'r> Transaction<'m, 'r> {
    pub fn new(
        mod_security: &'m mut ModSecurity,
        rules_set: &'r mut RulesSet,
        id: Option<&str>,
    ) -> Self {
        // # Safety: libmodsecurity must not reassign the pointer
        let inner = unsafe {
            let modsec_ptr = mod_security.inner.as_mut().get_unchecked_mut() as *mut _;
            let ruleset_ptr = rules_set.inner.as_mut().get_unchecked_mut() as *mut _;
            match id {
                Some(id) => {
                    let id = CString::new(id).expect("Must not contain NULL");
                    let id_raw = id.into_raw();
                    let tx = ffi::modsecurity::Transaction::new1(
                        modsec_ptr,
                        ruleset_ptr,
                        id_raw,
                        ptr::null_mut(),
                    )
                    .within_box();
                    drop(CString::from_raw(id_raw));
                    tx
                }
                None => {
                    ffi::modsecurity::Transaction::new(modsec_ptr, ruleset_ptr, ptr::null_mut())
                        .within_box()
                }
            }
        };
        Self {
            inner,
            _modsec_phantom: PhantomData,
            _rules_phantom: PhantomData,
        }
    }

    pub fn process_connection(
        &mut self,
        client_ip: IpAddr,
        client_port: u16,
        server: &str,
        server_port: u16,
    ) -> anyhow::Result<()> {
        let client = CString::new(client_ip.to_string().as_bytes())?;
        let server = CString::new(server.as_bytes())?;
        // # Safety: libmodsecurity must not reassign inner pointer
        unsafe {
            self.inner.as_mut().processConnection(
                client.as_ptr(),
                (client_port as i32).into(),
                server.as_ptr(),
                (server_port as i32).into(),
            );
        }
        Ok(())
    }

    pub fn process_uri(
        &mut self,
        uri: &str,
        protocol: &str,
        http_version: &str,
    ) -> anyhow::Result<()> {
        let uri = CString::new(uri.as_bytes())?;
        let protocol = CString::new(protocol.as_bytes())?;
        let http_version = CString::new(http_version.as_bytes())?;
        // # Safety: libmodsecurity must not reassign inner pointer
        unsafe {
            self.inner
                .as_mut()
                .processURI(uri.as_ptr(), protocol.as_ptr(), http_version.as_ptr());
        }
        Ok(())
    }

    pub fn add_request_header(&mut self, key: &str, value: &str) -> anyhow::Result<()> {
        cxx::let_cxx_string!(key = key);
        cxx::let_cxx_string!(value = value);
        self.inner.as_mut().addRequestHeader(&key, &value);
        Ok(())
    }

    pub fn add_response_header(&mut self, key: &str, value: &str) -> anyhow::Result<()> {
        cxx::let_cxx_string!(key = key);
        cxx::let_cxx_string!(value = value);
        self.inner.as_mut().addResponseHeader(&key, &value);
        Ok(())
    }

    pub fn add_request_body(&mut self, body: &[u8]) -> anyhow::Result<()> {
        // # Safety: libmodsecurity must not reassign inner pointer
        unsafe {
            self.inner
                .as_mut()
                .appendRequestBody(body.as_ptr(), body.len());
        }
        Ok(())
    }

    pub fn add_response_body(&mut self, body: &[u8]) -> anyhow::Result<()> {
        // # Safety: libmodsecurity must not reassign inner pointer
        unsafe {
            self.inner
                .as_mut()
                .appendResponseBody(body.as_ptr(), body.len());
        }
        Ok(())
    }

    pub fn process_request_headers(&mut self) -> anyhow::Result<()> {
        self.inner.as_mut().processRequestHeaders();
        Ok(())
    }

    pub fn process_response_headers(&mut self, code: u16, protocol: &str) -> anyhow::Result<()> {
        cxx::let_cxx_string!(protocol = protocol);
        self.inner
            .as_mut()
            .processResponseHeaders((code as i32).into(), &protocol);
        Ok(())
    }

    pub fn process_request_body(&mut self) -> anyhow::Result<()> {
        self.inner.as_mut().processRequestBody();
        Ok(())
    }

    pub fn process_response_body(&mut self) -> anyhow::Result<()> {
        self.inner.as_mut().processResponseBody();
        Ok(())
    }

    pub fn intervention(&mut self) -> anyhow::Result<Intervention> {
        let mut it = ffi::modsecurity::ModSecurityIntervention {
            status: 200,
            pause: 0,
            url: std::ptr::null_mut(),
            log: std::ptr::null_mut(),
            disruptive: 0,
        };
        // # Safety: libmodsecurity must not reassign inner pointer
        unsafe {
            self.inner.as_mut().intervention(&mut it as _);
        }
        Ok(it.into())
    }

    pub fn process_logging(&mut self) -> anyhow::Result<()> {
        self.inner.as_mut().processLogging();
        Ok(())
    }
}

impl ModSecurity {
    pub fn new() -> Self {
        Self {
            inner: ffi::modsecurity::ModSecurity::new().within_box(),
        }
    }
}

impl Default for ModSecurity {
    fn default() -> Self {
        ModSecurity::new()
    }
}

impl RulesSet {
    pub fn from_paths<T>(paths: &[T]) -> anyhow::Result<Self>
    where
        T: AsRef<Path>,
    {
        let mut inner = ffi::modsecurity::RulesSet::new().within_box();

        for p in paths {
            let path_str_c = CString::new(p.as_ref().as_os_str().as_bytes())
                .context("Converting path to CString")?;
            // # Safety: libmodsecurity must not reassign inner pointer
            let r: i32 = unsafe { inner.as_mut().loadFromUri(path_str_c.as_ptr()).into() };
            if r < 0i32 {
                return Err(std::io::Error::from_raw_os_error(r))
                    .context(format!("Adding rule: {}", p.as_ref().display()));
            }
        }
        Ok(Self { inner })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn e2e() -> anyhow::Result<()> {
        let mut modsec = ModSecurity::new();
        let mut rules = RulesSet::from_paths(&["resource/sample-ruleset.conf"])?;
        let mut tx = Transaction::new(&mut modsec, &mut rules, Some("some-unique-id-here"));
        tx.process_connection("127.0.0.1".parse().unwrap(), 31337, "localhost", 80)?;
        tx.process_uri("/test.pl?param1=test&para2=test2", "GET", "1.1")?;
        tx.add_request_header("Host", "foo.bar")?;
        tx.process_request_headers()?;
        tx.process_request_body()?;
        let it = tx.intervention()?;
        assert_eq!(it.status, 403);
        assert!(!it.pause);
        assert!(it.disruptive);
        assert!(it.log.len() > 0);
        assert!(it.url.is_empty());
        tx.process_logging()?;
        Ok(())
    }
}
