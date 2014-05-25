#include <uvh.h>

#define MAX_CHUNK 100

struct chunker
{
    FILE *fp;
};

int stream_cb(char **chunk, void *data)
{
    printf("%s\n", __FUNCTION__);

    struct chunker *chunker = (struct chunker *) data;

    if (!chunker->fp)
    {
        free(chunker);
        return 0;
    }

    *chunk = malloc(MAX_CHUNK);
    size_t read = fread(*chunk, 1, MAX_CHUNK, chunker->fp);

    if (read < MAX_CHUNK || feof(chunker->fp))
    {
        fclose(chunker->fp);
        chunker->fp = NULL;
    }

    if (read == 0)
    {
        free(chunker);
    }

    return read;
}

int request_handler(struct uvh_request *req)
{
    printf("%s\n", __FUNCTION__);

    FILE *fp = fopen(req->url.path, "r");
    if (!fp)
    {
        uvh_request_write_status(req, HTTP_NOT_FOUND);
        uvh_request_end(req);
        return;
    }

    struct chunker *chunker = calloc(1, sizeof(*chunker));
    chunker->fp = fp;

    uvh_request_stream(req, stream_cb, chunker);

    return 0;
}

void ctrlc_handler(uv_signal_t *handle, int signum)
{
    struct uvh_server *server = handle->data;
    uvh_server_stop(server);
    uv_close((uv_handle_t *) handle, NULL);
    (void) signum;
}

int main()
{
    uv_signal_t sig;
    struct uvh_server *server = uvh_server_init(uv_default_loop(),
        NULL, &request_handler);

    if (!server)
        goto error;

    if (uvh_server_listen(server, "127.0.0.1", 9898))
        goto error;

    uv_signal_init(uv_default_loop(), &sig);
    sig.data = server;
    uv_signal_start(&sig, &ctrlc_handler, SIGINT);

    uv_run(uv_default_loop(), UV_RUN_DEFAULT);

    printf("done\n");

    return 0;

error:

    fprintf(stderr, "error: %s\n",
        uv_strerror(uv_last_error(uv_default_loop())));

    return 1;
}
