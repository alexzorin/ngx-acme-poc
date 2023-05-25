#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event_connect.h>
#include "cJSON.h"

typedef struct
{
    ngx_str_t cert;
    ngx_str_t cert_key;
    char *set_servers_request;
} ngx_http_acme_conf_t;

static ngx_http_acme_conf_t *acme_ctx = NULL;

static ngx_int_t ngx_http_acme_preconfiguration(ngx_conf_t *cf);
static void *ngx_http_acme_create_conf(ngx_conf_t *cf);
static char *ngx_http_acme_init_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_acme(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_http_acme_cleanup(void *data);
static ngx_int_t ngx_http_acme_postconfiguration(ngx_conf_t *cf);
static ngx_str_t nginx_acme_cert_var_name = ngx_string("acme_certificate");
static ngx_str_t nginx_acme_cert_key_var_name = ngx_string("acme_certificate_key");
static ngx_int_t ngx_http_acme_add_variables(ngx_conf_t *cf);
static ngx_int_t ngx_http_acme_cert_variable_get_handler(ngx_http_request_t *r,
                                                         ngx_http_variable_value_t *v,
                                                         uintptr_t data);
static ngx_int_t ngx_http_acme_cert_key_variable_get_handler(ngx_http_request_t *r,
                                                             ngx_http_variable_value_t *v,
                                                             uintptr_t data);
static ngx_int_t ngx_http_acme_init_process(ngx_cycle_t *cycle);
cJSON *ngx_str_to_cJSON(ngx_str_t str, ngx_pool_t *pool);

// Snakeoil key and certificate is temporarily used as the default value of $acme_certificate_key
// and $acme_certificate, respectively, before the real value is obtained from the ACME client.
// Instead of doing this, the module potentially block the configuration process until the values
// are bootstrapped.
static const char SNAKEOIL_KEY[] = "-----BEGIN EC PRIVATE KEY-----\n"
                                   "MHcCAQEEICPT+ahCJ7N6tXzpWFHiCiHWF/gEcjNc6/GUdSFi0YV0oAoGCCqGSM49\n"
                                   "AwEHoUQDQgAELPBER10XsjGV35+p0cKdLLkMaY8+QEsEVb6+h3Mz1vufmGKj34y9\n"
                                   "rZtdfM+uyoSSt6aRGwHkQ4C9XJadHIbcSg==\n"
                                   "-----END EC PRIVATE KEY-----";
static const char SNAKEOIL_CERT[] = "-----BEGIN CERTIFICATE-----\n"
                                    "MIIBLTCB1AIJAJBSUn/gBmZkMAoGCCqGSM49BAMCMB8xHTAbBgNVBAMMFHNuYWtl\n"
                                    "b2lsLmV4YW1wbGUuY29tMB4XDTIzMDUyNTAyNTQzNVoXDTI0MDUyNDAyNTQzNVow\n"
                                    "HzEdMBsGA1UEAwwUc25ha2VvaWwuZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggq\n"
                                    "hkjOPQMBBwNCAAQs8ERHXReyMZXfn6nRwp0suQxpjz5ASwRVvr6HczPW+5+YYqPf\n"
                                    "jL2tm118z67KhJK3ppEbAeRDgL1clp0chtxKMAoGCCqGSM49BAMCA0gAMEUCIDUf\n"
                                    "ag6aHpON1iQU1HrkeTJ5cr70qKciUKMoJCP/AjpJAiEA0pcb4/HlNh4vHedWV0N4\n"
                                    "mtAFIeW9HJjyu1OBkk+olJs=\n"
                                    "-----END CERTIFICATE-----";

static ngx_command_t ngx_http_acme_commands[] = {

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

    conf->cert.data = (u_char *)SNAKEOIL_CERT;
    conf->cert.len = sizeof(SNAKEOIL_CERT) - 1;
    conf->cert_key.data = (u_char *)SNAKEOIL_KEY;
    conf->cert_key.len = sizeof(SNAKEOIL_KEY) - 1;

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

    acme_ctx->set_servers_request = cJSON_Print(json_root);
    cJSON_Delete(json_root);

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

static ngx_int_t
ngx_http_acme_cert_variable_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v,
                                        uintptr_t data)
{
    v->data = acme_ctx->cert.data;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->len = acme_ctx->cert.len;
    return NGX_OK;
}

static ngx_int_t
ngx_http_acme_cert_key_variable_get_handler(ngx_http_request_t *r, ngx_http_variable_value_t *v,
                                            uintptr_t data)
{
    // Get the server_name from the ngx_http_request_t
    v->data = acme_ctx->cert_key.data;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->len = acme_ctx->cert_key.len;
    return NGX_OK;
}

static ngx_int_t ngx_http_acme_init_process(ngx_cycle_t *cycle)
{
    return NGX_OK;
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