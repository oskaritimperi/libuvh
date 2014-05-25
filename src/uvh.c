#include "uvh.h"
#include "sds.h"
#include "http_parser.h"

#ifndef offsetof
#ifdef __GNUC__
#define offsetof(type, member)  __builtin_offsetof (type, member)
#endif
#endif

#ifndef container_of
#ifdef __GNUC__
#define member_type(type, member) __typeof__ (((type *)0)->member)
#else
#define member_type(type, member) const void
#endif

#define container_of(ptr, type, member) ((type *)( \
    (char *)(member_type(type, member) *){ ptr } - offsetof(type, member)))
#endif

#define LOG(LEVEL, FMT, args...) \
    fprintf(stderr, FMT "\n" , ##args)

#define LOG_DEBUG(FMT, args...)   LOG(0, "DEBUG   " FMT , ##args)
#define LOG_WARNING(FMT, args...) LOG(0, "WARNING " FMT , ##args)
#define LOG_ERROR(FMT, args...)   LOG(0, "ERROR   " FMT , ##args)
#define LOG_INFO(FMT, args...)    LOG(0, "INFO    " FMT , ##args)

struct http_status_code_def
{
    int code;
    const char *str;
};

static struct http_status_code_def http_status_code_defs[] =
{
#define XX(CODE, NAME, STR) { CODE, STR },
    HTTP_STATUS_CODE_MAP(XX)
#undef XX
    { -1, NULL }
};

static void on_connection(uv_stream_t *stream, int status);
static uv_buf_t alloc_cb(uv_handle_t *, size_t size);
static void read_cb(uv_stream_t *stream, ssize_t nread, uv_buf_t buf);

static int on_message_begin(http_parser *parser);
static int on_url(http_parser *parser, const char *at, size_t len);
static int on_status(http_parser *parser, const char *at, size_t len);
static int on_header_field(http_parser *parser, const char *at,
    size_t len);
static int on_header_value(http_parser *parser, const char *at,
    size_t len);
static int on_headers_complete(http_parser *parser);
static int on_body(http_parser *parser, const char *at, size_t len);
static int on_message_complete(http_parser *parser);

struct uvh_server_private
{
    struct uvh_server server;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    uv_loop_t *loop;
    struct http_parser_settings http_parser_settings;
    uv_tcp_t stream;
};

struct uvh_request_private
{
    struct uvh_request req;
    struct http_parser parser;
    uv_tcp_t stream;
    sds header_name;
    sds header_value;
    int header_state;
};

struct uvh_server *uvh_server_init(uv_loop_t *loop, void *data,
    uvh_request_handler_cb request_handler)
{
    struct uvh_server_private *server;
    int rc;

    server = calloc(1, sizeof(*server));

    if (!server)
        goto error;

    server->loop = loop;
    server->server.data = data;
    server->server.request_handler = request_handler;

    rc = uv_tcp_init(loop, &server->stream);

    if (rc < 0)
        goto error;

    server->stream.data = server;

    server->http_parser_settings.on_message_begin = on_message_begin;
    server->http_parser_settings.on_url = on_url;
    server->http_parser_settings.on_status = on_status;
    server->http_parser_settings.on_header_field = on_header_field;
    server->http_parser_settings.on_header_value = on_header_value;
    server->http_parser_settings.on_headers_complete = on_headers_complete;
    server->http_parser_settings.on_body = on_body;
    server->http_parser_settings.on_message_complete = on_message_complete;

    return &server->server;

error:

    if (server)
    {
        free(server);
    }

    return NULL;
}

int uvh_server_listen(struct uvh_server *server, const char *address,
    short port)
{
    struct uvh_server_private *serverp = container_of(server,
        struct uvh_server_private, server);
    struct sockaddr_in addr = uv_ip4_addr(address, port);

    memcpy(&serverp->addr, &addr, sizeof(addr));
    serverp->addr_len = sizeof(addr);

    uv_tcp_bind(&serverp->stream, addr);

    int r = uv_listen((uv_stream_t *) &serverp->stream, 128,
        on_connection);

    if (r)
        return r;

    return 0;
}

static void on_connection(uv_stream_t *stream, int status)
{
    struct uvh_server_private *priv = container_of((uv_tcp_t *) stream,
        struct uvh_server_private, stream);

    LOG_DEBUG("%s", __FUNCTION__);

    if (status == -1)
    {
        LOG_WARNING("on_connection: status = -1");
        return;
    }

    struct uvh_request_private *req = calloc(1, sizeof(*req));
    req->req.server = &priv->server;
    req->header_state = 0;

    http_parser_init(&req->parser, HTTP_REQUEST);
    req->parser.data = req;

    if (uv_tcp_init(priv->loop, &req->stream))
    {
        LOG_WARNING("failed to initialize uv_tcp_t");
        goto error;
    }

    req->stream.data = req;

    if (uv_accept(stream, (uv_stream_t *) &req->stream) == 0)
    {
        uv_read_start((uv_stream_t *) &req->stream, alloc_cb,
            read_cb);
        return;
    }
    else
    {
        uv_close((uv_handle_t *) &req->stream, NULL);
        LOG_WARNING("failed to accept");
    }

error:

    if (req)
    {
        free(req);
    }
}

static uv_buf_t alloc_cb(uv_handle_t *handle, size_t size)
{
    (void) handle;
    return uv_buf_init(calloc(1, size), size);
}

static void read_cb(uv_stream_t *stream, ssize_t nread, uv_buf_t buf)
{
    struct uvh_request_private *req;
    struct uvh_server_private *serverp;

    req = (struct uvh_request_private *) stream->data;
    serverp = container_of(req->req.server, struct uvh_server_private,
        server);

    LOG_DEBUG("read_cb: nread: %zd, buf.len: %zd", nread, buf.len);

    if (nread < 0)
    {
        uv_err_t err = uv_last_error(stream->loop);

        if (buf.base)
            free(buf.base);

        if (err.code == UV_EOF)
        {
            LOG_DEBUG("EOF");
            http_parser_execute(&req->parser,
                &serverp->http_parser_settings, NULL, 0);
        }

        uv_close((uv_handle_t *) stream, NULL);

        return;
    }

    if (nread == 0)
    {
        free(buf.base);
        return;
    }

    int nparsed = http_parser_execute(&req->parser,
        &serverp->http_parser_settings,
        buf.base, nread);

    LOG_DEBUG("nparsed:%d", nparsed);

    if (nparsed != nread)
    {
        LOG_ERROR("http parse error, closing connection");
        uv_close((uv_handle_t *) stream, NULL);
    }

    free(buf.base);
}

static int on_message_begin(http_parser *parser)
{
    struct uvh_request_private *priv;
    priv = (struct uvh_request_private *) parser->data;
    priv->req.content = (const char *) sdsempty();
    return 0;
}

static int on_url(http_parser *parser, const char *at, size_t len)
{
    struct uvh_request_private *priv;
    priv = (struct uvh_request_private *) parser->data;

    LOG_DEBUG("on_url: <%.*s>", (int) len, at);

    if (!priv->req.url.full)
    {
        priv->req.url.full = sdsnewlen(at, len);
    }
    else
    {
        priv->req.url.full = sdscatlen((sds) priv->req.url.full,
            at, len);
    }

    return 0;
}

static int on_status(http_parser *parser, const char *at, size_t len)
{
    LOG_DEBUG("on_status: <%.*s>", (int) len, at);
    return 0;
}

static int on_header_field(http_parser *parser, const char *at,
    size_t len)
{
    struct uvh_request_private *priv;
    struct uvh_request *req;

    priv = (struct uvh_request_private *) parser->data;
    req = &priv->req;

    if (priv->header_state == 0)
    {
        priv->header_name = sdsnewlen(at, len);
    }
    else if (priv->header_state == 1)
    {
        priv->header_name = sdscatlen(priv->header_name, at, len);
    }
    else if (priv->header_state == 2)
    {
        req->headers[req->header_count].name = priv->header_name;
        req->headers[req->header_count].value = priv->header_value;
        req->header_count += 1;

        priv->header_name = sdsnewlen(at, len);
        priv->header_value = NULL;
    }

    priv->header_state = 1;

    return 0;
}

static int on_header_value(http_parser *parser, const char *at,
    size_t len)
{
    struct uvh_request_private *priv;

    priv = (struct uvh_request_private *) parser->data;

    if (priv->header_state == 1)
    {
        priv->header_value = sdsnewlen(at, len);
    }
    else if (priv->header_state == 2)
    {
        priv->header_value = sdscatlen(priv->header_value, at, len);
    }

    priv->header_state = 2;

    return 0;
}

static int on_headers_complete(http_parser *parser)
{
    struct uvh_request_private *priv;
    struct uvh_request *req;
    struct http_parser_url url;
    const char *full;

    priv = (struct uvh_request_private *) parser->data;
    req = &priv->req;
    full = req->url.full;

    if (priv->header_state == 2)
    {
        req->headers[req->header_count].name = priv->header_name;
        req->headers[req->header_count].value = priv->header_value;
        req->header_count += 1;
    }

    LOG_DEBUG("on_headers_complete");

    http_parser_parse_url(req->url.full, sdslen((sds) req->url.full),
        1, &url);

#define UF_OFFSET(X) url.field_data[X].off
#define UF_LEN(X) url.field_data[X].len
#define UF_SET(X) (url.field_set & (1 << (X)))
#define UF_CHECK_AND_SET(X, DST) \
    if (UF_SET(X)) \
        (DST) = sdsnewlen(full + UF_OFFSET(X), UF_LEN(X))

    UF_CHECK_AND_SET(UF_SCHEMA, req->url.schema);
    UF_CHECK_AND_SET(UF_HOST, req->url.host);
    UF_CHECK_AND_SET(UF_PORT, req->url.port);
    UF_CHECK_AND_SET(UF_PATH, req->url.path);
    UF_CHECK_AND_SET(UF_QUERY, req->url.query);
    UF_CHECK_AND_SET(UF_FRAGMENT, req->url.fragment);
    UF_CHECK_AND_SET(UF_USERINFO, req->url.userinfo);

#undef UF_CHECK_AND_SET
#undef UF_SET
#undef UF_LEN
#undef UF_OFFSET

    return 0;
}

static int on_body(http_parser *parser, const char *at, size_t len)
{
    struct uvh_request_private *priv;
    priv = (struct uvh_request_private *) parser->data;
    priv->req.content = (const char *) sdscatlen((sds) priv->req.content,
        at, len);
    return 0;
}

static int on_message_complete(http_parser *parser)
{
    struct uvh_request_private *priv;

    priv = (struct uvh_request_private *) parser->data;

    LOG_DEBUG("on_message_complete");

    if (priv->req.content)
        priv->req.content_length = sdslen((sds) priv->req.content);
    else
        priv->req.content_length = 0;

    priv->req.method = sdsnew(http_method_str(parser->method));

    priv->req.version = sdsempty();
    priv->req.version = sdscatprintf((sds) priv->req.version,
        "HTTP/%d.%d", parser->http_major, parser->http_minor);

    if (priv->req.server->request_handler)
        priv->req.server->request_handler(&priv->req);

    return 0;
}

struct uvh_write_request
{
    uv_buf_t buf;
    uv_write_t wreq;
    struct uvh_request_private *req;
};

static void after_request_write(uv_write_t *req, int status)
{
    struct uvh_write_request *wreq = container_of(req, struct uvh_write_request,
        wreq);
    sdsfree((sds) wreq->buf.base);
    free(wreq);
}

static void uvh_request_write_sds(struct uvh_request *req, sds data)
{
    struct uvh_request_private *p = container_of(req,
        struct uvh_request_private, req);
    struct uvh_write_request *wreq = calloc(1, sizeof(*wreq));

    wreq->buf.base = (char *) data;
    wreq->buf.len = sdslen(data);

    wreq->req = p;

    uv_write(&wreq->wreq, (uv_stream_t *) &p->stream, &wreq->buf, 1,
        &after_request_write);
}

void uvh_request_write(struct uvh_request *req,
    const char *data, size_t len)
{
    uvh_request_write_sds(req, sdsnewlen(data, len));
}

void uvh_request_writef(struct uvh_request *req, const char *fmt, ...)
{
    va_list ap;
    sds result;

    va_start(ap, fmt);
    result = sdscatvprintf(sdsempty(), fmt, ap);
    va_end(ap);

    uvh_request_write_sds(req, result);
}

void uvh_request_write_status(struct uvh_request *req, int status)
{
    uvh_request_writef(req, "%s %d %s\r\n", req->version, status,
        http_status_code_str(status));
}

void uvh_request_write_header(struct uvh_request *req,
    const char *name, const char *value)
{
    uvh_request_writef(req, "%s: %s\r\n", name, value);
}

const char *http_status_code_str(int code)
{
    struct http_status_code_def *def = http_status_code_defs;
    while (def->code != -1)
    {
        if (def->code == code)
        {
            return def->str;
        }
        ++def;
    }

    return NULL;
}

const char *uvh_request_get_header(struct uvh_request *req,
    const char *name)
{
    int i;

    for (i = 0; i < req->header_count; ++i)
    {
        if (strcasecmp(name, req->headers[i].name) == 0)
            return req->headers[i].value;
    }

    return NULL;
}
