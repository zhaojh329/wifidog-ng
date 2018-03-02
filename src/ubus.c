#include <libubox/ulog.h>
#include <libubus.h>
#include "utils.h"
#include "ping.h"
#include "counters.h"

static struct ubus_context *ctx;

enum {
	STATUS_INTERNET,
	__STATUS_MAX
};

static const struct blobmsg_policy status_policy[] = {
	[STATUS_INTERNET] = { .name = "internet", .type = BLOBMSG_TYPE_BOOL },
};

static int server_status(struct ubus_context *ctx, struct ubus_object *obj,
			 struct ubus_request_data *req, const char *method,
			 struct blob_attr *msg)
{
	struct blob_attr *tb[__STATUS_MAX];

	blobmsg_parse(status_policy, ARRAY_SIZE(status_policy), tb, blob_data(msg), blob_len(msg));

	if (tb[STATUS_INTERNET]) {
		if (blobmsg_get_bool(tb[STATUS_INTERNET])) {			
			start_heartbeat();
    		start_counters();

    		ULOG_INFO("Internet became online\n");
		} else {
			stop_heartbeat();
			stop_counters();

			ULOG_INFO("Internet became offline\n");
		}
	}
	return 0;
}

static const struct ubus_method server_methods[] = {
	UBUS_METHOD("status", server_status, status_policy)
};

static struct ubus_object_type server_object_type =
	UBUS_OBJECT_TYPE("wifidog", server_methods);

static struct ubus_object server_object = {
	.name = "wifidog",
	.type = &server_object_type,
	.methods = server_methods,
	.n_methods = ARRAY_SIZE(server_methods),
};

int ubus_init()
{
	int ret;

	ctx = ubus_connect(NULL);
	if (!ctx) {
		ULOG_ERR("Failed to connect to ubus\n");
		return -1;
	}

	ret = ubus_add_object(ctx, &server_object);
	if (ret) {
		ULOG_ERR("Failed to add server object: %s\n", ubus_strerror(ret));
		return -1;
	}
	return 0;
}