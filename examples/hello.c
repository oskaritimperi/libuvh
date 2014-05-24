#include <uvh.h>

int request_handler(struct uvh_request *req)
{
    int i;

    printf("%s\n", __PRETTY_FUNCTION__);

    for (i = 0; i < req->header_count; ++i)
    {
        printf("%s: %s\n", req->headers[i].name, req->headers[i].value);
    }

    printf("--\n");
    printf("full: %s\n", req->url.full);
    printf("schema: %s\n", req->url.schema);
    printf("host: %s\n", req->url.host);
    printf("port: %s\n", req->url.port);
    printf("path: %s\n", req->url.path);
    printf("query: %s\n", req->url.query);
    printf("fragment: %s\n", req->url.fragment);
    printf("userinfo: %s\n", req->url.userinfo);
    printf("--\n");

    printf("request content length: %d\n", req->content_length);

    uvh_request_write_status(req, 418);
    uvh_request_write_header(req, "Content-Length", "7");
    uvh_request_write_header(req, "X-FOOBAR", "whee");
    uvh_request_write_header(req, "Connection", "close");
    uvh_request_write(req, "\r\nfoobar\n", 9);
    return 0;
}

int main()
{
    struct uvh_server *server = uvh_server_init(uv_default_loop(),
        NULL, &request_handler);

    if (!server)
        goto error;

    if (uvh_server_listen(server, "127.0.0.1", 9898))
        goto error;

    uv_run(uv_default_loop(), UV_RUN_DEFAULT);

    return 0;

error:

    fprintf(stderr, "error: %s\n",
        uv_strerror(uv_last_error(uv_default_loop())));

    return 1;
}
