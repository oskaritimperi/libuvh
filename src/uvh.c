#include "uvh.h"
#include "sds.h"
#include "http_parser.h"

#include <sys/queue.h>

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
static void close_cb(uv_handle_t *handle);

static int on_message_begin(http_parser *parser);
static int on_url(http_parser *parser, const char *at, size_t len);
// static int on_status(http_parser *parser, const char *at, size_t len);
static int on_header_field(http_parser *parser, const char *at,
    size_t len);
static int on_header_value(http_parser *parser, const char *at,
    size_t len);
static int on_headers_complete(http_parser *parser);
static int on_body(http_parser *parser, const char *at, size_t len);
static int on_message_complete(http_parser *parser);

static void uvh_request_write_chunk(struct uvh_request *req, sds chunk);

static struct http_parser_settings parser_settings =
{
    &on_message_begin,
    &on_url,
    NULL,
    &on_header_field,
    &on_header_value,
    &on_headers_complete,
    &on_body,
    &on_message_complete
};

struct uvh_request_private;
struct uvh_connection;

struct uvh_server
{
    uv_tcp_t stream;
    struct sockaddr_storage addr;
    socklen_t addr_len;
    uv_loop_t *loop;
    char stop;
    uvh_request_handler_cb request_handler;
    void *userdata;
    SLIST_HEAD(connection_list, uvh_connection) connections;
};

struct uvh_connection
{
    uv_tcp_t stream;
    struct uvh_server *server;
    struct http_parser parser;
    SLIST_ENTRY(uvh_connection) siblings;
    SLIST_HEAD(request_list, uvh_request_private) requests;
};

struct uvh_request_private
{
    struct uvh_request req;
    struct uvh_connection *connection;
    char keepalive;
    int send_status;
    sds send_headers;
    sds send_body;
    int streaming;
    uvh_stream_cb stream_cb;
    void *stream_userdata;
    SLIST_ENTRY(uvh_request_private) siblings;
};

static struct uvh_request_private *uvh_request_new(struct uvh_connection *conn);
static void uvh_request_free(struct uvh_request_private *req);

static struct uvh_connection *uvh_connection_new(struct uvh_server *server);
static void uvh_connection_free(struct uvh_connection *conn);

UVH_EXTERN struct uvh_server *uvh_server_init(uv_loop_t *loop, void *data,
    uvh_request_handler_cb request_handler)
{
    struct uvh_server *server;
    int rc;

    server = calloc(1, sizeof(*server));

    if (!server)
        goto error;

    server->loop = loop;
    server->userdata = data;
    server->request_handler = request_handler;

    SLIST_INIT(&server->connections);

    rc = uv_tcp_init(loop, &server->stream);

    if (rc < 0)
        goto error;

    server->stream.data = server;

    return server;

error:

    if (server)
    {
        free(server);
    }

    return NULL;
}

UVH_EXTERN void uvh_server_free(struct uvh_server *server)
{
    free(server);
}

UVH_EXTERN int uvh_server_listen(struct uvh_server *server, const char *address,
    short port)
{
    struct sockaddr_in addr = uv_ip4_addr(address, port);

    memcpy(&server->addr, &addr, sizeof(addr));
    server->addr_len = sizeof(addr);

    uv_tcp_bind(&server->stream, addr);

    int r = uv_listen((uv_stream_t *) &server->stream, 128,
        on_connection);

    if (r)
        return r;

    return 0;
}

static void on_server_close(uv_handle_t *handle)
{
    struct uvh_server *server = (struct uvh_server *) handle;
    struct uvh_connection *conn;

    LOG_DEBUG("%s", __FUNCTION__);

    SLIST_FOREACH(conn, &server->connections, siblings)
    {
        uv_close((uv_handle_t *) &conn->stream, &close_cb);
    }
}

UVH_EXTERN void uvh_server_stop(struct uvh_server *server)
{
    server->stop = 1;
    uv_close((uv_handle_t *) &server->stream, &on_server_close);
}

static void on_connection(uv_stream_t *stream, int status)
{
    struct uvh_server *server = (struct uvh_server *) stream;
    struct uvh_connection *connection;
    uv_tcp_t *client;

    LOG_DEBUG("%s", __FUNCTION__);

    if (status == -1)
    {
        LOG_WARNING("on_connection: status = -1");
        return;
    }

    if (server->stop)
    {
        LOG_WARNING("on_connection: stop bit set");
        goto close_conn;
    }

    connection = uvh_connection_new(server);

    if (!connection)
        goto close_conn;

    SLIST_INSERT_HEAD(&server->connections, connection, siblings);

    if (uv_accept(stream, (uv_stream_t *) &connection->stream) == 0)
    {
        LOG_DEBUG("starting read on connection %p", connection);
        uv_read_start((uv_stream_t *) &connection->stream, alloc_cb, read_cb);
    }
    else
    {
        // TODO: free the connection
        uv_close((uv_handle_t *) &connection->stream, NULL);
        LOG_WARNING("failed to accept");
    }

    return;

close_conn:

    client = calloc(1, sizeof(*client));
    uv_tcp_init(server->loop, client);
    uv_accept(stream, (uv_stream_t *) client);
    // TODO: free the client
    uv_close((uv_handle_t *) client, NULL);
}

static uv_buf_t alloc_cb(uv_handle_t *handle, size_t size)
{
    (void) handle;
    return uv_buf_init(calloc(1, size), size);
}

static void read_cb(uv_stream_t *stream, ssize_t nread, uv_buf_t buf)
{
    struct uvh_connection *connection = (struct uvh_connection *) stream;
    size_t nparsed;

    LOG_DEBUG("read_cb: nread: %d, buf.len: %d", (int)nread, (int)buf.len);

    if (nread == 0)
        goto out;

    if (nread < 0)
    {
        uv_err_t err = uv_last_error(stream->loop);

        if (err.code == UV_EOF)
        {
            LOG_DEBUG("EOF");
            nread = 0;
        }
        else
        {
            uv_close((uv_handle_t *) stream, &close_cb);
            goto out;
        }
    }

    nparsed = http_parser_execute(&connection->parser,
        &parser_settings,
        buf.base, nread);

    LOG_DEBUG("nparsed:%d", (int) nparsed);

    if ((ssize_t) nparsed != nread)
    {
        LOG_ERROR("http parse error, closing connection");
        uv_close((uv_handle_t *) stream, &close_cb);
    }
    else if (nread == 0)
    {
        uv_close((uv_handle_t *) stream, &close_cb);
    }

out:

    free(buf.base);
}

static void close_cb(uv_handle_t *handle)
{
    struct uvh_connection *connection = (struct uvh_connection *) handle;
    struct uvh_server *server = connection->server;

    LOG_DEBUG("%s", __FUNCTION__);

    SLIST_REMOVE(&server->connections, connection, uvh_connection, siblings);

    uvh_connection_free(connection);
}

static int on_message_begin(http_parser *parser)
{
    struct uvh_connection *connection = (struct uvh_connection *) parser->data;
    struct uvh_request_private *req;

    LOG_DEBUG("%s", __FUNCTION__);

    req = uvh_request_new(connection);

    SLIST_INSERT_HEAD(&connection->requests, req, siblings);

    return 0;
}

static int on_url(http_parser *parser, const char *at, size_t len)
{
    struct uvh_connection *connection = (struct uvh_connection *) parser->data;
    struct uvh_request_private *req = SLIST_FIRST(&connection->requests);

    LOG_DEBUG("%s", __FUNCTION__);

    if (!req->req.url.full)
    {
        req->req.url.full = sdsnewlen(at, len);
    }
    else
    {
        req->req.url.full = sdscatlen((sds) req->req.url.full, at, len);
    }

    return 0;
}

#define HEADER_COUNT req->req.header_count
#define CURRENT_HEADER req->req.headers[HEADER_COUNT]

static int on_header_field(http_parser *parser, const char *at, size_t len)
{
    struct uvh_connection *connection = (struct uvh_connection *) parser->data;
    struct uvh_request_private *req = SLIST_FIRST(&connection->requests);

    LOG_DEBUG("%s", __FUNCTION__);

start:

    if (!CURRENT_HEADER.name)
    {
        CURRENT_HEADER.name = sdsnewlen(at, len);
    }
    else
    {
        if (!CURRENT_HEADER.value)
        {
            CURRENT_HEADER.name = sdscatlen((sds) CURRENT_HEADER.name, at, len);
        }
        else
        {
            ++HEADER_COUNT;
            goto start;
        }
    }

    return 0;
}

static int on_header_value(http_parser *parser, const char *at, size_t len)
{
    struct uvh_connection *connection = (struct uvh_connection *) parser->data;
    struct uvh_request_private *req = SLIST_FIRST(&connection->requests);

    LOG_DEBUG("%s", __FUNCTION__);

    if (!CURRENT_HEADER.value)
    {
        CURRENT_HEADER.value = sdsnewlen(at, len);
    }
    else
    {
        CURRENT_HEADER.value = sdscatlen((sds) CURRENT_HEADER.value, at, len);
    }

    return 0;
}

#undef CURRENT_HEADER
#undef HEADER_COUNT

static int on_headers_complete(http_parser *parser)
{
    struct uvh_connection *connection = (struct uvh_connection *) parser->data;
    struct uvh_request_private *priv = SLIST_FIRST(&connection->requests);
    struct uvh_request *req = &priv->req;
    struct http_parser_url url;
    const char *full = req->url.full;

    LOG_DEBUG("%s", __FUNCTION__);

    ++req->header_count;

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
    struct uvh_connection *connection = (struct uvh_connection *) parser->data;
    struct uvh_request_private *req = SLIST_FIRST(&connection->requests);

    LOG_DEBUG("%s", __FUNCTION__);

    if (!req->req.content)
    {
        req->req.content = sdsnewlen(at, len);
    }
    else
    {
        req->req.content = sdscatlen((sds) req->req.content, at, len);
    }

    return 0;
}

static int on_message_complete(http_parser *parser)
{
    struct uvh_connection *connection = (struct uvh_connection *) parser->data;
    struct uvh_request_private *req = SLIST_FIRST(&connection->requests);

    LOG_DEBUG("%s", __FUNCTION__);

    req->keepalive = http_should_keep_alive(parser);

    if (req->req.content)
        req->req.content_length = sdslen((sds) req->req.content);
    else
        req->req.content_length = 0;

    req->req.method = sdsnew(http_method_str(parser->method));

    req->req.version = sdsempty();
    req->req.version = sdscatprintf((sds) req->req.version,
        "HTTP/%d.%d", parser->http_major, parser->http_minor);

    if (req->req.server->request_handler)
        req->req.server->request_handler(&req->req);

    return 0;
}

static struct uvh_request_private *uvh_request_new(struct uvh_connection *conn)
{
    struct uvh_request_private *req = calloc(1, sizeof(*req));
    req->connection = conn;
    req->req.server = conn->server;
    req->req.data = conn->server->userdata;
    req->send_body = sdsempty();
    req->send_headers = sdsempty();
    req->send_status = HTTP_OK;
    return req;
}

static void uvh_request_free(struct uvh_request_private *req)
{
    int i;

    LOG_DEBUG("%s", __FUNCTION__);

    for (i = 0; i < req->req.header_count; ++i)
    {
        sdsfree((sds) req->req.headers[i].name);
        sdsfree((sds) req->req.headers[i].value);
    }

    sdsfree((sds) req->req.method);
    sdsfree((sds) req->req.version);

    sdsfree((sds) req->req.url.full);
    sdsfree((sds) req->req.url.schema);
    sdsfree((sds) req->req.url.host);
    sdsfree((sds) req->req.url.port);
    sdsfree((sds) req->req.url.path);
    sdsfree((sds) req->req.url.query);
    sdsfree((sds) req->req.url.fragment);
    sdsfree((sds) req->req.url.userinfo);

    sdsfree((sds) req->req.content);

    // TODO: what about send_body, send_headers

    free(req);
}

static struct uvh_connection *uvh_connection_new(struct uvh_server *server)
{
    struct uvh_connection *connection = calloc(1, sizeof(*connection));
    connection->server = server;

    http_parser_init(&connection->parser, HTTP_REQUEST);
    connection->parser.data = connection;

    SLIST_INIT(&connection->requests);

    if (uv_tcp_init(server->loop, &connection->stream) < 0)
    {
        LOG_WARNING("failed to initialize uv_tcp_t");
        goto error;
    }

    return connection;

error:

    if (connection)
        uvh_connection_free(connection);

    return NULL;
}

static void uvh_connection_free(struct uvh_connection *conn)
{
    struct uvh_request_private *req;

    LOG_DEBUG("%s", __FUNCTION__);

    SLIST_FOREACH(req, &conn->requests, siblings)
    {
        uvh_request_free(req);
    }

    free(conn);
}

struct uvh_write_request
{
    uv_write_t wreq;
    uv_buf_t buf;
    struct uvh_request_private *req;
};

static void uvh_write_request_free(struct uvh_write_request *req)
{
    sdsfree((sds) req->buf.base);
    free(req);
}

static void after_request_write(uv_write_t *req, int status)
{
    LOG_DEBUG("%s", __FUNCTION__);
    struct uvh_write_request *wreq = (struct uvh_write_request *) req;
    (void) status;
    uvh_write_request_free(wreq);
}

static void uvh_request_write_sds(struct uvh_request *req, sds data,
    uv_write_cb cb)
{
    struct uvh_request_private *p = container_of(req,
        struct uvh_request_private, req);

    struct uvh_write_request *wreq = calloc(1, sizeof(*wreq));

    wreq->buf.base = (char *) data;
    wreq->buf.len = sdslen(data);

    wreq->req = p;

    uv_write(&wreq->wreq, (uv_stream_t *) &p->connection->stream, &wreq->buf,
        1, cb);
}

UVH_EXTERN void uvh_request_write(struct uvh_request *req,
    const char *data, size_t len)
{
    struct uvh_request_private *p = container_of(req,
        struct uvh_request_private, req);

    if (p->streaming)
    {
        uvh_request_write_chunk(req, sdsnewlen(data, len));
    }
    else
        p->send_body = sdscatlen(p->send_body, data, len);
}

UVH_EXTERN void uvh_request_writef(struct uvh_request *req, const char *fmt,
    ...)
{
    struct uvh_request_private *p = container_of(req,
        struct uvh_request_private, req);

    va_list ap;
    sds result;

    va_start(ap, fmt);
    result = sdscatvprintf(sdsempty(), fmt, ap);
    va_end(ap);

    if (p->streaming)
    {
        uvh_request_write_chunk(req, result);
    }
    else
        p->send_body = sdscatsds(p->send_body, result);

    sdsfree(result);
}

UVH_EXTERN void uvh_request_write_status(struct uvh_request *req, int status)
{
    struct uvh_request_private *p = container_of(req,
        struct uvh_request_private, req);

    p->send_status = status;
}

UVH_EXTERN void uvh_request_write_header(struct uvh_request *req,
    const char *name, const char *value)
{
    struct uvh_request_private *p = container_of(req,
        struct uvh_request_private, req);

    if (p->streaming)
        return;

    p->send_headers = sdscatprintf(p->send_headers, "%s: %s\r\n", name, value);
}

UVH_EXTERN const char *http_status_code_str(int code)
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

UVH_EXTERN const char *uvh_request_get_header(struct uvh_request *req,
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

UVH_EXTERN void uvh_request_end(struct uvh_request *req)
{
    LOG_DEBUG("%s", __FUNCTION__);

    struct uvh_request_private *p = container_of(req,
        struct uvh_request_private, req);

    uvh_request_write_sds(req, sdscatprintf(sdsempty(),
        "%s %d %s\r\n", p->req.version, p->send_status,
        http_status_code_str(p->send_status)), &after_request_write);

    if (!p->streaming)
    {
        sds content_len = sdscatprintf(sdsempty(), "%d", (int)sdslen(p->send_body));
        uvh_request_write_header(req, "Content-Length", content_len);
        sdsfree(content_len);
    }

    LOG_DEBUG("keepalive: %d", p->keepalive);

    if (!p->keepalive)
    {
        uvh_request_write_header(req, "Connection", "close");
    }

    uvh_request_write_sds(req, p->send_headers, &after_request_write);
    uvh_request_write_sds(req, sdsnew("\r\n"), &after_request_write);

    if (!p->streaming)
        uvh_request_write_sds(req, p->send_body, &after_request_write);
    else
        sdsfree(p->send_body);

    if (!p->streaming)
    {
        struct uvh_connection *connection = p->connection;
        SLIST_REMOVE(&connection->requests, p, uvh_request_private, siblings);
        uvh_request_free(p);
    }
}

static void after_last_chunk_write(uv_write_t *req, int status)
{
    LOG_DEBUG("%s", __FUNCTION__);

    struct uvh_write_request *wreq = container_of(req, struct uvh_write_request,
        wreq);

    (void)status;

    SLIST_REMOVE(&wreq->req->connection->requests, wreq->req,
        uvh_request_private, siblings);
    uvh_request_free(wreq->req);

    uvh_write_request_free(wreq);
}

static void after_chunk_write(uv_write_t *req, int status)
{
    LOG_DEBUG("%s", __FUNCTION__);

    (void)status;

    struct uvh_write_request *wreq = container_of(req, struct uvh_write_request,
        wreq);

    struct uvh_request_private *p = wreq->req;

    uvh_write_request_free(wreq);

    if (p->stream_cb)
    {
        char *chunk;

        int chunklen = p->stream_cb(&chunk, p->stream_userdata);

        if (chunklen == 0)
        {
            uvh_request_write_chunk(&p->req, NULL);
        }
        else
        {
            uvh_request_write_chunk(&p->req, sdsnewlen(chunk, chunklen));
            free(chunk);
        }
    }
}

static void uvh_request_write_chunk(struct uvh_request *req, sds chunk)
{
    unsigned int len = chunk != NULL ? sdslen(chunk) : 0;

    LOG_DEBUG("%s len:%u", __FUNCTION__, len);

    sds chunklen = sdscatprintf(sdsempty(), "%X\r\n", len);

    uvh_request_write_sds(req, chunklen, &after_request_write);

    uv_write_cb callback;

    if (len > 0)
    {
        uvh_request_write_sds(req, chunk, &after_request_write);
        callback = &after_chunk_write;
    }
    else
    {
        sdsfree(chunk);
        callback = &after_last_chunk_write;
    }

    uvh_request_write_sds(req, sdsnew("\r\n"), callback);
}

UVH_EXTERN void uvh_request_stream(struct uvh_request *req, uvh_stream_cb cb,
    void *data)
{
    struct uvh_request_private *p = container_of(req,
        struct uvh_request_private, req);

    uvh_request_write_header(req, "Transfer-Encoding", "chunked");

    p->streaming = 1;
    p->stream_cb = cb;
    p->stream_userdata = data;

    uvh_request_end(req);

    if (cb)
    {
        char *chunk;
        int chunklen = cb(&chunk, data);
        uvh_request_write_chunk(req, sdsnewlen(chunk, chunklen));
        free(chunk);
    }
}
