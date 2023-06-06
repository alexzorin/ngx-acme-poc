use ngx::core::Buffer;
use ngx::ffi::{
    nginx_version, ngx_array_push, ngx_chain_t, ngx_command_t, ngx_conf_t, ngx_http_core_module,
    ngx_http_handler_pt, ngx_http_module_t, ngx_http_phases_NGX_HTTP_REWRITE_PHASE,
    ngx_http_request_t, ngx_int_t, ngx_module_t, ngx_str_t, ngx_uint_t, NGX_HTTP_MODULE,
    NGX_RS_MODULE_SIGNATURE,
};
use ngx::http::{HTTPStatus, MergeConfigError};
use ngx::{core, core::Status, http, http::HTTPModule};
use ngx::{http_request_handler, ngx_modules, ngx_null_command, ngx_string};
use std::os::raw::c_char;

struct NgxHttpAcmeCtx {
    thumbprint: ngx_str_t,
}

impl NgxHttpAcmeCtx {}

static mut ACME_CTX: NgxHttpAcmeCtx = NgxHttpAcmeCtx {
    thumbprint: ngx_string!("temporary-thumbprint"),
};

struct Module;

impl http::HTTPModule for Module {
    type MainConf = ();
    type SrvConf = ();
    type LocConf = ModuleConfig;

    unsafe extern "C" fn postconfiguration(cf: *mut ngx_conf_t) -> ngx_int_t {
        let cmcf = http::ngx_http_conf_get_module_main_conf(cf, &ngx_http_core_module);

        // Install ACME http-01 challenge response handler in rewrite phase.
        let h = ngx_array_push(
            &mut (*cmcf).phases[ngx_http_phases_NGX_HTTP_REWRITE_PHASE as usize].handlers,
        ) as *mut ngx_http_handler_pt;
        if h.is_null() {
            return core::Status::NGX_ERROR.into();
        }
        *h = Some(acme_http_challenge_handler);

        core::Status::NGX_OK.into()
    }
}

#[derive(Debug, Default)]
struct ModuleConfig {}

#[no_mangle]
static mut ngx_http_curl_commands: [ngx_command_t; 1] = [ngx_null_command!()];

#[no_mangle]
static ngx_http_acme_module_ctx: ngx_http_module_t = ngx_http_module_t {
    preconfiguration: Some(Module::preconfiguration),
    postconfiguration: Some(Module::postconfiguration),
    create_main_conf: Some(Module::create_main_conf),
    init_main_conf: Some(Module::init_main_conf),
    create_srv_conf: Some(Module::create_srv_conf),
    merge_srv_conf: Some(Module::merge_srv_conf),
    create_loc_conf: Some(Module::create_loc_conf),
    merge_loc_conf: Some(Module::merge_loc_conf),
};

ngx_modules!(ngx_http_acme_module);

#[no_mangle]
pub static mut ngx_http_acme_module: ngx_module_t = ngx_module_t {
    ctx_index: ngx_uint_t::max_value(),
    index: ngx_uint_t::max_value(),
    name: std::ptr::null_mut(),
    spare0: 0,
    spare1: 0,
    version: nginx_version as ngx_uint_t,
    signature: NGX_RS_MODULE_SIGNATURE.as_ptr() as *const c_char,

    ctx: &ngx_http_acme_module_ctx as *const _ as *mut _,
    commands: unsafe { &ngx_http_curl_commands[0] as *const _ as *mut _ },
    type_: NGX_HTTP_MODULE as ngx_uint_t,

    init_master: None,
    init_module: None,
    init_process: None,
    init_thread: None,
    exit_thread: None,
    exit_process: None,
    exit_master: None,

    spare_hook0: 0,
    spare_hook1: 0,
    spare_hook2: 0,
    spare_hook3: 0,
    spare_hook4: 0,
    spare_hook5: 0,
    spare_hook6: 0,
    spare_hook7: 0,
};

impl http::Merge for ModuleConfig {
    fn merge(&mut self, _prev: &ModuleConfig) -> Result<(), MergeConfigError> {
        Ok(())
    }
}

http_request_handler!(
    acme_http_challenge_handler,
    |request: &mut http::Request| {
        // Request must be GET
        if request.method() != http::Method::GET {
            return Status::NGX_DECLINED;
        }

        // Try parse the URL path into a Rust string. We need to do this
        // because we eventually need the challenge token as a UTF-8 string.
        let path: &str;
        match request.path().to_str() {
            Ok(p) => path = p,
            Err(_) => return Status::NGX_DECLINED,
        }

        // Must be an HTTP-01 challenge
        let prefix = "/.well-known/acme-challenge/";
        if path.len() == prefix.len() || !path.starts_with(prefix) {
            return Status::NGX_DECLINED;
        }

        // Calculate the key authorization response
        let token = &path[prefix.len()..];
        let key_authz = format!("{}.{}", token, unsafe { ACME_CTX.thumbprint.to_string() });

        // Set response headers
        request.add_header_out("Content-Type", "text/plain");
        request.set_content_length_n(key_authz.len());
        request.set_status(HTTPStatus::OK);

        // Send response headers
        if request.send_header() != Status::NGX_OK {
            return Status::NGX_ERROR;
        }

        // Allocate and pass on the response.
        let mut resp_buf = request
            .pool()
            .create_buffer_from_str(&key_authz)
            .expect("allocating key_authz buffer");
        resp_buf.set_last_in_chain(true);
        resp_buf.set_last_buf(true);

        unsafe {
            let chain = request
                .pool()
                .alloc_type::<ngx_chain_t>()
                .as_mut()
                .expect("chain as mut");

            (*chain).buf = resp_buf.as_ngx_buf_mut();
            (*chain).next = std::ptr::null_mut();
            return request.output_filter(chain);
        }
    }
);
