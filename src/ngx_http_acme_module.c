#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event_connect.h>
#include "cJSON.h"
#include "llhttp/llhttp.h"
#include "uthash.h"

// Callback type for when a request to the ACME client is complete.
typedef void (*ngx_http_acme_request_parse_pt)(void *data);

// Stores the PEM representation of the certificate and certificate private key.
typedef struct
{
    u_char *cert;
    u_char *cert_key;
} ngx_http_acme_cert_and_key;

// uthash hashtable storing server_name against a certificate and private key.
typedef struct
{
    char *server_name;
    ngx_http_acme_cert_and_key *value;
    UT_hash_handle hh;
} ngx_http_acme_certs_hash;

// ngx_http_acme_request_t encapsulates work we do with the ACME client (e.g. /set-servers request).
typedef struct
{
    u_char name[64];                         // For logging.
    ngx_pool_t *pool;                        // Per-request pool makes this easier to dealllocate.
    ngx_uint_t interval_msec;                // Interval between repeating this request.
    ngx_str_t body;                          // The HTTP request body to send for this ACME request type
    ngx_http_acme_request_parse_pt callback; // Callback to invoke when the request is complete.
    ngx_event_t ev;                          // The event (timer) used to perform this request.
    struct sockaddr_in addr;                 // Dial adderss for the ACME client.
    ngx_peer_connection_t pc;                // The connection to the ACME client.
    ngx_buf_t recv;                          // Request recieve buffer.
    ngx_buf_t send;                          // Request send buffer.
    ngx_buf_t resp_body;                     // Used for buffering the HTTP response body when it is received.
} ngx_http_acme_request_t;

// ngx_http_acme_conf_t is the global context for this module.
typedef struct
{
    ngx_pool_t *pool; // Memory allocator we'll use for the module (available after worker init)
    ngx_log_t *log;   // Logger for the module

    ngx_http_acme_certs_hash *certs; // Hash table of certificates and keys for each server name

    ngx_http_acme_request_t set_servers_req; // The POST /set-servers work
    ngx_http_acme_request_t get_certs_req;   // The GET /certificates work

    llhttp_settings_t parser_settings; // HTTP parser settings
    llhttp_t parser;                   // The HTTP parser for talking to the ACME client
} ngx_http_acme_conf_t;

// The module context is available statically globally for convenience.
static ngx_http_acme_conf_t *acme_ctx = NULL;

static void *ngx_http_acme_create_conf(ngx_conf_t *cf);
static char *ngx_http_acme_init_conf(ngx_conf_t *cf, void *conf);
static void ngx_http_acme_cleanup(void *data);

static ngx_int_t ngx_http_acme_preconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_acme_postconfiguration(ngx_conf_t *cf);
static ngx_int_t ngx_http_acme_add_variables(ngx_conf_t *cf);

static ngx_int_t ngx_http_acme_init_process(ngx_cycle_t *cycle);
static void ngx_http_acme_init_parser();
static ngx_int_t ngx_http_acme_init_acme_requests(ngx_pool_t *pool, char *servers_json);
static void ngx_http_acme_init_events();
static void ngx_http_acme_init_event(ngx_http_acme_request_t *req, const char *name,
                                     ngx_http_acme_request_parse_pt callback,
                                     ngx_uint_t interval);

// The 'acme on'; directive.
static char *ngx_http_acme(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_str_t nginx_acme_cert_var_name = ngx_string("acme_certificate");
static ngx_str_t nginx_acme_cert_key_var_name = ngx_string("acme_certificate_key");
static ngx_int_t ngx_http_acme_cert_variable_get_handler(ngx_http_request_t *r,
                                                         ngx_http_variable_value_t *v,
                                                         uintptr_t data);
static ngx_int_t ngx_http_acme_cert_key_variable_get_handler(ngx_http_request_t *r,
                                                             ngx_http_variable_value_t *v,
                                                             uintptr_t data);
static void ngx_http_acme_ev_begin(ngx_event_t *event);
static void ngx_http_acme_ev_request_send_handler(ngx_event_t *event);
static void ngx_http_acme_ev_request_recv_handler(ngx_event_t *event);
static void ngx_http_acme_ev_empty_handler(ngx_event_t *event);
static void ngx_http_acme_ev_reset(ngx_http_acme_request_t *req);

static int ngx_http_acme_on_body(llhttp_t *http, const char *at, size_t length);
static int ngx_http_acme_http_on_message_complete(llhttp_t *http);
static void ngx_http_acme_parse_http_response(ngx_http_acme_request_t *req);

static void ngx_http_acme_process_certificates_response(void *udata);

cJSON *ngx_str_to_cJSON(ngx_str_t str, ngx_pool_t *pool);

static ngx_command_t ngx_http_acme_commands[] = {

    // The 'acme on;' directive opts a server block into using the module.
    {ngx_string("acme"),
     NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
     ngx_http_acme,
     NGX_HTTP_SRV_CONF_OFFSET,
     0,
     NULL},

    ngx_null_command};

static ngx_http_module_t ngx_http_acme_module_ctx = {
    ngx_http_acme_preconfiguration,  /* preconfiguration */
    ngx_http_acme_postconfiguration, /* postconfiguration */

    ngx_http_acme_create_conf, /* create main configuration */
    ngx_http_acme_init_conf,   /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

ngx_module_t ngx_http_acme_module = {
    NGX_MODULE_V1,
    &ngx_http_acme_module_ctx,  /* module context */
    ngx_http_acme_commands,     /* module directives */
    NGX_HTTP_MODULE,            /* module type */
    NULL,                       /* init master */
    NULL,                       /* init module */
    ngx_http_acme_init_process, /* init process */
    NULL,                       /* init thread */
    NULL,                       /* exit thread */
    NULL,                       /* exit process */
    NULL,                       /* exit master */
    NGX_MODULE_V1_PADDING};

static void *
ngx_http_acme_create_conf(ngx_conf_t *cf)
{
    ngx_pool_cleanup_t *cln;
    ngx_http_acme_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_acme_conf_t));
    if (conf == NULL)
    {
        return NULL;
    }

    conf->certs = NULL; // uthash requires this to be initialized to NULL.

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL)
    {
        return NULL;
    }
    cln->handler = ngx_http_acme_cleanup;
    cln->data = conf;

    return conf;
}

static char *
ngx_http_acme(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    // When the `acme on;` directive appears in a server block, the module
    // will set $ssl_certificate and $ssl_certificate_key to be resolved
    // using the $acme_* variables of the same name managed by this module.
    ngx_http_ssl_srv_conf_t *ssl_conf;
    ngx_http_complex_value_t *cv;
    ngx_http_compile_complex_value_t ccv;

    ngx_str_t *cert, *key;

    // The server block must be SSL-enabled.
    ssl_conf = ngx_http_conf_get_module_srv_conf(cf, ngx_http_ssl_module);
    if (!ssl_conf)
    {
        ngx_log_error(NGX_LOG_ERR, cf->log, 0, "the acme directive is only allowed in SSL contexts");
        return NGX_CONF_ERROR;
    }

    // Set ssl_certificate and ssl_certificate key.
    ssl_conf->certificates = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
    if (ssl_conf->certificates == NULL)
    {
        return NGX_CONF_ERROR;
    }
    ((ngx_str_t *)ssl_conf->certificates->elts)[0] = (ngx_str_t)ngx_string("data:$acme_certificate");
    cert = ssl_conf->certificates->elts;

    ssl_conf->certificate_keys = ngx_array_create(cf->pool, 1, sizeof(ngx_str_t));
    if (ssl_conf->certificate_keys == NULL)
    {
        return NGX_CONF_ERROR;
    }
    ((ngx_str_t *)ssl_conf->certificate_keys->elts)[0] = (ngx_str_t)ngx_string("data:$acme_certificate_key");
    key = ssl_conf->certificate_keys->elts;

    // Variable support in $ssl_certificate[_key] requires use of ngx_http_complex_value_t,
    // so here we set those up using the contents of $ssl_certificate and $ssl_certificate_key.
    ssl_conf->certificate_values = ngx_array_create(cf->pool, 1,
                                                    sizeof(ngx_http_complex_value_t));
    if (ssl_conf->certificate_values == NULL)
    {
        return NGX_CONF_ERROR;
    }
    ssl_conf->certificate_key_values = ngx_array_create(cf->pool, 1,
                                                        sizeof(ngx_http_complex_value_t));
    if (ssl_conf->certificate_key_values == NULL)
    {
        return NGX_CONF_ERROR;
    }

    cv = ngx_array_push(ssl_conf->certificate_values);
    if (cv == NULL)
    {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &cert[0];
    ccv.complex_value = cv;
    ccv.zero = 1;
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    cv = ngx_array_push(ssl_conf->certificate_key_values);
    if (cv == NULL)
    {
        return NGX_CONF_ERROR;
    }
    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &key[0];
    ccv.complex_value = cv;
    ccv.zero = 1;
    if (ngx_http_compile_complex_value(&ccv) != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}

static char *
ngx_http_acme_init_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_acme_conf_t *acme_conf = conf;

    // Here we are making the module conf available as a static global
    // for the workers.
    acme_ctx = acme_conf;

    return NGX_CONF_OK;
}

static void
ngx_http_acme_cleanup(void *data)
{
}

static ngx_int_t
ngx_http_acme_postconfiguration(ngx_conf_t *cf)
{
    // In postconfiguration, we compile every server block's server_name(s)
    // and store it as a JSON string that workers will use to initialize the
    // ACME client to the state of the server configuration.
    ngx_http_core_main_conf_t *cmcf;
    ngx_uint_t i, j;
    ngx_http_core_srv_conf_t **cscfp;
    ngx_http_core_srv_conf_t *cscf;
    ngx_http_server_name_t *name;
    char *set_servers;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cscfp = cmcf->servers.elts;

    cJSON *json_root = cJSON_CreateObject();
    cJSON *json_servers_array = cJSON_CreateArray();
    cJSON_AddItemToObject(json_root, "servers", json_servers_array);

    for (i = 0; i < cmcf->servers.nelts; i++)
    {
        cscf = cscfp[i]->ctx->srv_conf[ngx_http_core_module.ctx_index];

        cJSON *json_server = cJSON_CreateObject();
        cJSON *json_server_names_array = cJSON_CreateArray();
        cJSON_AddItemToObject(json_server, "server_names", json_server_names_array);

        name = cscf->server_names.elts;
        for (j = 0; j < cscf->server_names.nelts; j++)
        {
            cJSON *json_server_name = ngx_str_to_cJSON(name[j].name, cf->pool);
            cJSON_AddItemToArray(json_server_names_array, json_server_name);
        }

        cJSON_AddItemToArray(json_servers_array, json_server);
    }

    set_servers = (char *)cJSON_Print(json_root);
    cJSON_Delete(json_root);

    // Initialize the ACME client requests
    if (ngx_http_acme_init_acme_requests(cf->pool, set_servers) != NGX_OK)
    {
        return NGX_ERROR;
    }
    free(set_servers);

    return NGX_OK;
}

static ngx_int_t ngx_http_acme_preconfiguration(ngx_conf_t *cf)
{
    return ngx_http_acme_add_variables(cf);
}

static ngx_int_t ngx_http_acme_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t *var;
    var = ngx_http_add_variable(cf, &nginx_acme_cert_var_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL)
    {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_acme_cert_variable_get_handler;

    var = ngx_http_add_variable(cf, &nginx_acme_cert_key_var_name, NGX_HTTP_VAR_NOCACHEABLE);
    if (var == NULL)
    {
        return NGX_ERROR;
    }
    var->get_handler = ngx_http_acme_cert_key_variable_get_handler;

    return NGX_OK;
}

// The 'get' handler for $acme_certificate. It looks up the server_name from the request
// scope, then tries to find a matching certificate in the certs uthash. If it can't find
// one, an empty value is returned, and the SSL handshake will fail.
static ngx_int_t
ngx_http_acme_cert_variable_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v,
                                        uintptr_t data)
{
    ngx_http_core_srv_conf_t *srv_conf;
    ngx_http_acme_certs_hash *cert;

    srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    // srv_conf->server_name is not null-terminated, so we need to copy it before we can
    // look it up in the hash.
    char server_name[srv_conf->server_name.len + 1];
    strncpy(server_name, (const char *)srv_conf->server_name.data, srv_conf->server_name.len);
    server_name[srv_conf->server_name.len] = '\0';

    cert = NULL;
    HASH_FIND_STR(acme_ctx->certs, (const char *)server_name, cert);
    if (cert)
    {
        v->data = cert->value->cert;
    }
    else
    {
        v->data = NULL;
    }

    v->len = v->data ? strlen((const char *)v->data) : 0;
    v->no_cacheable = 1;
    v->not_found = 0;
    return NGX_OK;
}

// See ngx_http_acme_cert_variable_get_handler.
static ngx_int_t
ngx_http_acme_cert_key_variable_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v,
                                            uintptr_t data)
{
    ngx_http_core_srv_conf_t *srv_conf;
    ngx_http_acme_certs_hash *cert = NULL;

    srv_conf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);

    // srv_conf->server_name is not null-terminated, so we need to copy it before we can
    // look it up in the hash.
    char server_name[srv_conf->server_name.len + 1];
    strncpy(server_name, (const char *)srv_conf->server_name.data, srv_conf->server_name.len);
    server_name[srv_conf->server_name.len] = '\0';

    HASH_FIND_STR(acme_ctx->certs, (const char *)server_name, cert);
    if (cert)
    {
        v->data = cert->value->cert_key;
    }
    else
    {
        v->data = NULL;
    }

    v->len = v->data ? strlen((const char *)v->data) : 0;
    v->no_cacheable = 1;
    v->not_found = 0;
    return NGX_OK;
}

static ngx_int_t ngx_http_acme_init_process(ngx_cycle_t *cycle)
{
    // We are now in the worker process and everything is ready to begin communicating
    // with the ACME client.
    //
    // We will kick this off with two requests to the ACME client:
    // 1. Set the servers that this worker will be serving.
    // 2. Get the available set of certificates that we can use in this worker.
    //
    // We will use the nginx event loop to perform the work.
    acme_ctx->pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, ngx_cycle->log);
    acme_ctx->log = ngx_cycle->log;

    ngx_http_acme_init_parser();
    ngx_http_acme_init_events();

    return NGX_OK;
}

// ngx_http_acme_init_events fires off the background work to talk to the ACME client.
static void ngx_http_acme_init_events()
{
    // Set up one request to sync the nginx server list to the ACME client
    ngx_http_acme_init_event(&acme_ctx->set_servers_req, "POST /set-servers", NULL, 0);
    // Set up a second recurring request to sync the certificate list from
    // the ACME client to this nginx worker.
    ngx_http_acme_init_event(&acme_ctx->get_certs_req, "GET /certificates",
                             ngx_http_acme_process_certificates_response,
                             5000);
}

// Initializes the ngx_http_acme_request_t and fires it off immediately using a timer.
static void ngx_http_acme_init_event(ngx_http_acme_request_t *req, const char *name,
                                     ngx_http_acme_request_parse_pt callback,
                                     ngx_uint_t interval)
{
    ngx_sprintf(req->name, name);

    req->pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, acme_ctx->log);
    if (!req->pool)
    {
        ngx_log_error(NGX_LOG_ERR, acme_ctx->log, 0, "ngx_create_pool failed");
        return;
    }

    req->ev.handler = ngx_http_acme_ev_begin;
    req->ev.timer_set = 0;
    req->ev.log = acme_ctx->log;
    req->ev.data = req;
    req->callback = callback;
    req->interval_msec = interval;
    ngx_add_timer(&req->ev, 0);
}

static void ngx_http_acme_ev_begin(ngx_event_t *event)
{
    ngx_http_acme_request_t *req = (ngx_http_acme_request_t *)event->data;

    if (req->pool == NULL)
    {
        req->pool = ngx_create_pool(NGX_DEFAULT_POOL_SIZE, acme_ctx->log);
        if (!req->pool)
        {
            ngx_log_error(NGX_LOG_ERR, acme_ctx->log, 0, "ngx_create_pool failed");
            return;
        }
    }

    ngx_peer_connection_t *pc = &req->pc;
    pc->get = ngx_event_get_peer;
    pc->log = event->log;
    pc->log_error = NGX_ERROR_ERR;
    pc->connection = NULL;
    pc->cached = 0;
    pc->sockaddr = (struct sockaddr *)&req->addr;
    pc->socklen = sizeof(struct sockaddr_in);
    ngx_str_t pc_name = (ngx_str_t)ngx_string("localhost");
    pc->name = &pc_name;

    int rc = ngx_event_connect_peer(pc);
    if (rc == NGX_ERROR || rc == NGX_DECLINED)
    {
        ngx_http_acme_ev_reset(req);
        return;
    }

    ngx_connection_t *c = pc->connection;
    c->log = event->log;
    c->sendfile = 0;
    c->read->log = c->log;
    c->write->log = c->log;
    c->idle = 1;
    c->write->handler = ngx_http_acme_ev_request_send_handler;
    c->read->handler = ngx_http_acme_ev_request_recv_handler;
    c->data = req;

    if (rc == NGX_OK)
    {
        c->write->handler(c->write);
    }
}

// Send the HTTP request.
static void ngx_http_acme_ev_request_send_handler(ngx_event_t *event)
{
    ngx_http_acme_request_t *req;
    ngx_connection_t *c;
    ngx_buf_t *send;
    ssize_t size;

    c = (ngx_connection_t *)event->data;
    req = (ngx_http_acme_request_t *)c->data;
    send = &req->send;
    size = 0;

    send->pos = (u_char *)req->body.data;
    send->last = send->pos + req->body.len;
    while (send->pos < send->last)
    {
        size = c->send(
            c, send->pos, send->last - send->pos);

        if (size > 0)
        {
            send->pos += size;
        }
        else if (size == 0 || size == NGX_AGAIN)
        {
            return;
        }
        else
        {
            c->error = 1;
            goto send_fail;
        }
    }

    c->write->handler = ngx_http_acme_ev_empty_handler;
    return;

send_fail:
    ngx_http_acme_ev_reset(req);
}

// Receive the HTTP response, pass it on the the parser, and optionally the callback.
static void ngx_http_acme_ev_request_recv_handler(ngx_event_t *event)
{
    ngx_connection_t *c;
    ngx_http_acme_request_t *req;
    ngx_buf_t *recv;
    ssize_t n, size;
    u_char *resized_buf;

    c = (ngx_connection_t *)event->data;
    req = (ngx_http_acme_request_t *)c->data;

    recv = &req->recv;
    if (recv->start == NULL)
    {
        recv->start = ngx_pcalloc(req->pool, ngx_pagesize);
        if (recv->start == NULL)
        {
            ngx_log_error(NGX_LOG_ERR, event->log, 0, "ngx_pcalloc failed");
            goto recv_fail;
        }
        recv->last = recv->pos = recv->start;
        recv->end = recv->start + ngx_pagesize;
    }

    while (1)
    {
        n = recv->end - recv->last;
        if (n == 0)
        {
            size = recv->end - recv->start;
            resized_buf = ngx_pcalloc(req->pool, size * 2);
            if (resized_buf == NULL)
            {
                ngx_log_error(NGX_LOG_ERR, event->log, 0, "ngx_pcalloc failed");
                goto recv_fail;
            }
            ngx_memcpy(resized_buf, recv->start, size);
            recv->pos = recv->start = resized_buf;
            recv->last = resized_buf + size;
            recv->end = resized_buf + size * 2;
            n = recv->end - recv->last;
        }

        size = c->recv(c, recv->last, n);
        if (size > 0)
        {
            recv->last += size;
        }
        else if (size == 0)
        {
            break;
        }
        else if (size == NGX_AGAIN)
        {
            return;
        }
        else
        {
            c->error = 1;
            ngx_log_error(NGX_LOG_ERR, event->log, 0, "Exit ngx_http_acme_ev_request_recv_handler in error");
            goto recv_fail;
        }
    }

    ngx_http_acme_parse_http_response(req);

    if (req->callback != NULL)
    {
        req->callback(req);
    }

    c->read->handler = ngx_http_acme_ev_empty_handler;

    // TODO: we may want to relaunch this work, if it is configured as recurring.

    return;

recv_fail:
    ngx_log_error(NGX_LOG_ERR, event->log, 0, "ngx_http_acme_ev_request_recv_handler failed");
    ngx_http_acme_ev_reset(req);
}

static void ngx_http_acme_ev_empty_handler(ngx_event_t *event)
{
}

// Initializes llhttp to parse our HTTP responses.
static void ngx_http_acme_init_parser()
{
    llhttp_settings_init(&acme_ctx->parser_settings);
    acme_ctx->parser_settings.on_message_complete = ngx_http_acme_http_on_message_complete;
    acme_ctx->parser_settings.on_body = ngx_http_acme_on_body;
    llhttp_init(&acme_ctx->parser, HTTP_RESPONSE, &acme_ctx->parser_settings);
}

static int ngx_http_acme_http_on_message_complete(llhttp_t *http)
{
    return 0;
}

// Buffers up the HTTP response body (not including headers) into the request's resp_body buffer.
static int ngx_http_acme_on_body(llhttp_t *http, const char *at, size_t length)
{
    ngx_http_acme_request_t *req = (ngx_http_acme_request_t *)http->data;
    ngx_buf_t *b = &req->resp_body;

    // resp_body is lazily alllocated.
    if (b->start == NULL)
    {
        ngx_uint_t buf_size = ngx_pagesize * 4;
        ngx_buf_t *buf = &req->resp_body;
        buf->start = ngx_pcalloc(req->pool, buf_size);
        if (buf->start == NULL)
        {
            ngx_log_error(NGX_LOG_ERR, acme_ctx->log, 0, "ngx_pcalloc failed");
            return 1;
        }
        buf->last = buf->pos = buf->start;
        buf->end = buf->start + (buf_size);
    }

    ngx_uint_t capacity = b->end - b->last;
    if (length > capacity)
    {
        ngx_log_error(NGX_LOG_ERR, acme_ctx->log, 0, "ngx_http_acme_on_body: buffer overflow");
        return 1;
    }
    ngx_memcpy(b->last, at, length);
    b->last += length;
    return 0;
}

// Takes a raw HTTP response (stored in the request's recv buffer) and invokes the HTTP parser.
static void ngx_http_acme_parse_http_response(ngx_http_acme_request_t *req)
{
    char *buf;
    enum llhttp_errno err;

    buf = (char *)req->recv.pos;

    req->resp_body.last = req->resp_body.pos = req->resp_body.start; // Reset the buffer
    llhttp_reset(&acme_ctx->parser);
    acme_ctx->parser.data = req;
    err = llhttp_execute(&acme_ctx->parser, buf, ngx_strlen(buf));
    if (err != HPE_OK)
    {
        ngx_log_error(NGX_LOG_ERR, acme_ctx->log, 0, "llhttp_execute failed: %s", llhttp_errno_name(err));
        return;
    }
}

// Initializes the HTTP requests that we will need to send off during the lifecycle of
// this module.
static ngx_int_t ngx_http_acme_init_acme_requests(ngx_pool_t *pool, char *servers_json)
{
    // POST /set-servers
    ngx_http_acme_request_t *req = &acme_ctx->set_servers_req;
    req->body.data = ngx_pcalloc(pool, ngx_pagesize);
    req->body.len = ((strlen(servers_json) + ngx_pagesize - 1) / ngx_pagesize) * ngx_pagesize;
    req->body.data = ngx_pcalloc(pool, req->body.len);
    if (req->body.data == NULL)
    {
        return NGX_ERROR;
    }
    ngx_sprintf(
        req->body.data,
        "POST /set-servers HTTP/1.0\r\nAccept: */*\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %d\r\n\r\n%s\0",
        strlen(servers_json),
        servers_json);
    req->body.len = strlen((char *)req->body.data);
    ngx_memzero(&req->addr, sizeof(req->addr));
    req->addr.sin_family = AF_INET;
    req->addr.sin_port = htons(41934);
    req->addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    // GET /certificates
    req = &acme_ctx->get_certs_req;
    req->body.len = ngx_pagesize;
    req->body.data = ngx_pcalloc(pool, req->body.len);
    if (req->body.data == NULL)
    {
        return NGX_ERROR;
    }
    ngx_sprintf(req->body.data,
                "GET /certificates HTTP/1.0\r\nAccept: application/json\r\n\r\n");
    req->body.len = strlen((char *)req->body.data);
    ngx_memzero(&req->addr, sizeof(req->addr));
    req->addr.sin_family = AF_INET;
    req->addr.sin_port = htons(41934);
    req->addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    return NGX_OK;
}

// We have all the response from GET /certificates, so we can parse it and store it in
// the certs hashtable, available for lookup during the SSL handshake.
static void ngx_http_acme_process_certificates_response(void *udata)
{
    ngx_http_acme_request_t *req;
    char *certs_json;
    cJSON *json, *json_certs, *json_domain, *json_cert, *json_cert_key;
    ngx_http_acme_certs_hash *certs;
    ngx_http_acme_cert_and_key *cert;

    req = (ngx_http_acme_request_t *)udata;
    certs_json = (char *)req->resp_body.pos;

    json = cJSON_Parse(certs_json);
    if (!json)
    {
        ngx_log_error(NGX_LOG_ERR, acme_ctx->log, 0, "JSON parse failed");
        return;
    }
    json_certs = cJSON_GetObjectItemCaseSensitive(json, "certificates");
    if (!json_certs)
    {
        ngx_log_error(NGX_LOG_ERR, acme_ctx->log, 0, "certificates JSON item missing");
        cJSON_free(json);
        return;
    }
    cJSON_ArrayForEach(json_domain, json_certs)
    {
        if (json_domain->string == NULL)
        {
            continue;
        }
        if (cJSON_GetArraySize(json_domain) != 2)
        {
            ngx_log_error(NGX_LOG_ERR, acme_ctx->log, 0,
                          "Invalid certificate entry for %s", json_domain->string);
            continue;
        }

        json_cert = cJSON_GetArrayItem(json_domain, 0);
        json_cert_key = cJSON_GetArrayItem(json_domain, 1);

        // If an entry doesn't exist, allocate it and add it.
        HASH_FIND_STR(acme_ctx->certs, json_domain->string, certs);
        if (certs == NULL)
        {
            // We intentionally use the global acme_ctx->pool in this scope rather than
            // req->pool, because we want this memory to stick around for the entire
            // lifecycle of the module.

            certs = ngx_pcalloc(acme_ctx->pool, sizeof(ngx_http_acme_certs_hash));
            if (!certs)
            {
                ngx_log_error(NGX_LOG_ERR, acme_ctx->log, 0,
                              "Failed to allocate memory for ngx_http_acme_certs_hash");
                continue;
            }
            certs->server_name = strdup(json_domain->string); // We never free this.

            cert = ngx_pcalloc(acme_ctx->pool, sizeof(ngx_http_acme_cert_and_key));
            if (!cert)
            {
                ngx_log_error(NGX_LOG_ERR, acme_ctx->log, 0,
                              "Failed to allocate memory for ngx_http_acme_cert_and_key");
                continue;
            }

            cert->cert = (u_char *)strdup(json_cert->valuestring);
            cert->cert_key = (u_char *)strdup(json_cert_key->valuestring);

            certs->value = cert;

            HASH_ADD_KEYPTR(hh, acme_ctx->certs, certs->server_name, strlen(certs->server_name), certs);
        }
        // Otherwise just update the cert and cert key of the existing entry.
        else
        {
            free(certs->value->cert);
            free(certs->value->cert_key);
            certs->value->cert = (u_char *)strdup(json_cert->valuestring);
            certs->value->cert_key = (u_char *)strdup(json_cert_key->valuestring);
        }
    }
    cJSON_free(json);
}

// ngx_http_acme_ev_reset is called when an error occurs during the request. It will
// clear its state and immediately relaunch the request.
static void ngx_http_acme_ev_reset(ngx_http_acme_request_t *req)
{
    if (req->pc.connection != NULL)
    {
        ngx_close_connection(req->pc.connection);
        req->pc.connection = NULL;
    }

    if (req->pool)
    {
        ngx_destroy_pool(req->pool);
        req->pool = NULL;
    }

    req->recv.start = NULL;
    req->resp_body.start = NULL;

    ngx_add_timer(&req->ev, 1000);
}

cJSON *ngx_str_to_cJSON(ngx_str_t str, ngx_pool_t *pool)
{
    // An ngx_str_t may or may not be NULL-terminated. If it is, that's easy.
    if (str.data[str.len] == '\0')
    {
        return cJSON_CreateStringReference((const char *)str.data);
    }

    // Otherwise, we need to copy the string into a NULL-terminated buffer.
    u_char *data = ngx_palloc(pool, str.len + 1);
    ngx_memcpy(data, str.data, str.len);
    str.data[str.len] = '\0';
    cJSON *json = cJSON_CreateString((const char *)data);
    ngx_pfree(pool, data);
    return json;
}