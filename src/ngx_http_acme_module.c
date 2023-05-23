#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct
{
} ngx_acme_conf_t;

static void *ngx_http_acme_create_conf(ngx_conf_t *cf);
static char *ngx_http_acme_init_conf(ngx_conf_t *cf, void *conf);
static char *ngx_http_acme(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static void ngx_http_acme_cleanup(void *data);
static ngx_int_t ngx_http_acme_init(ngx_conf_t *cf);

static ngx_command_t ngx_http_acme_commands[] = {

    {ngx_string("acme"),
     NGX_HTTP_SRV_CONF | NGX_CONF_FLAG,
     ngx_http_acme,
     NGX_HTTP_SRV_CONF_OFFSET,
     0,
     NULL},

    ngx_null_command};

static ngx_http_module_t ngx_http_acme_module_ctx = {
    NULL,               /* preconfiguration */
    ngx_http_acme_init, /* postconfiguration */

    ngx_http_acme_create_conf, /* create main configuration */
    ngx_http_acme_init_conf,   /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL  /* merge location configuration */
};

ngx_module_t ngx_http_acme_module = {
    NGX_MODULE_V1,
    &ngx_http_acme_module_ctx, /* module context */
    ngx_http_acme_commands,    /* module directives */
    NGX_HTTP_MODULE,           /* module type */
    NULL,                      /* init master */
    NULL,                      /* init module */
    NULL,                      /* init process */
    NULL,                      /* init thread */
    NULL,                      /* exit thread */
    NULL,                      /* exit process */
    NULL,                      /* exit master */
    NGX_MODULE_V1_PADDING};

static void *
ngx_http_acme_create_conf(ngx_conf_t *cf)
{
    ngx_pool_cleanup_t *cln;
    ngx_acme_conf_t *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_acme_conf_t));
    if (conf == NULL)
    {
        return NULL;
    }

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
    // ngx_acme_conf_t *gcf = conf;
    return NGX_CONF_OK;
}

static char *
ngx_http_acme_init_conf(ngx_conf_t *cf, void *conf)
{
    // ngx_acme_conf_t *gcf = conf;
    return NGX_CONF_OK;
}

static void
ngx_http_acme_cleanup(void *data)
{
}

static ngx_int_t
ngx_http_acme_init(ngx_conf_t *cf)
{
    return NGX_OK;
}