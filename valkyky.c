#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <fcntl.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#ifndef SIZE_MAX
	#define SIZE_MAX (~((size_t)0))
#endif // SIZE_MAX
#define UNUSED(X) ((void)(X))

#define MAX_CONNECTIONS 1

#define COMM_ERROR_LENGTH 128

typedef enum EventFlag {
	EVENT_FLAG_ERROR = 1 << 3,
	EVENT_FLAG_READABLE = 1 << 2,
	EVENT_FLAG_DROP = 1 << 1,
	EVENT_FLAG_WRITABLE = 1 << 0
} event_flag_t;

typedef enum CommandId {
	COMMAND_UNKNOWN = 0,
	COMMAND_PING,
	COMMAND_SET,
	COMMANDS_LENGTH,
} command_id_t;

typedef enum ProtocolRet {
	PROTOCOL_ERR_OOM = -128,
	PROTOCOL_ERR_BULK_PREFIX_MISSING,
	PROTOCOL_ERR_BULK_LENGTH_ZERO,
	PROTOCOL_ERR_COMMAND_PREFIX_MISSING,
	PROTOCOL_ERR_COMMAND_UNKNOWN,
	PROTOCOL_ERR_COMMAND_ARITY_TOO_SMALL,
	PROTOCOL_ERR_COMMAND_ARITY_TOO_BIG,
	PROTOCOL_ERR_LENGTH_EMPTY,
	PROTOCOL_ERR_LENGTH_UNTERMINATED,
	PROTOCOL_ERR_LENGTH_OVERFLOW,
	PROTOCOL_ERR_LENGTH_UNPARSEABLE,
	PROTOCOL_ERR_DATA_UNTERMINATED,
	PROTOCOL_ERR_TYPE_UNEXPECTED,
	PROTOCOL_OK = 0,
	PROTOCOL_EXEC,
} protocol_ret_t;

typedef enum QueryState {
	QUERY_PARSING_TYPE = 0,
	QUERY_PARSING_LENGTH,
	QUERY_PARSING_LENGTH_END,
	QUERY_PARSING_DATA,
	QUERY_PARSING_DATA_END,
} query_state_t;

typedef struct String {
	size_t cap, len;
	char *data;
} string_t;

typedef struct DaString {
	size_t cap, len;
	string_t *data;
} da_string_t;

typedef struct Arity {
	unsigned int min;
	unsigned int max;
} arity_t;

typedef struct Kv {
	struct Kv *next;
	string_t key, value;
} kv_t;

typedef struct KvStore {
	size_t size, nbuckets;
	kv_t **buckets;
} kv_store_t;

#define EVENTSTREAM_LENGTH (1 + MAX_CONNECTIONS)
typedef struct EvenStream {
	int pending;
	size_t pos, nfds;
	struct pollfd fds[EVENTSTREAM_LENGTH];
} event_stream_t;

typedef struct Event {
	int fd, flags;
} event_t;

typedef struct Client {
	int fd;
	// query specific data
	query_state_t query_state;
	command_id_t query_cmd;
	da_string_t query_args;
	string_t query_buf;
	// output buffer
	string_t out;
} client_t;

typedef struct TcpServer {
	int fd;
	kv_store_t *store;
	client_t clients[MAX_CONNECTIONS];
	event_stream_t stream;
} tcp_server_t;

typedef struct ValkykyOpts {
	char *port;
} valkyky_opts_t;

const string_t commandNames[COMMANDS_LENGTH] = {
	[COMMAND_UNKNOWN] = {0,0,NULL},
	[COMMAND_PING] = {5,4,"PING"},
	[COMMAND_SET] = {4,3,"SET"},
};

const arity_t commandArities[COMMANDS_LENGTH] = {
	[COMMAND_UNKNOWN] = {0,0},
	[COMMAND_PING] = {0,1},
	[COMMAND_SET] = {2,2},
};

#define min(X, Y) ((X) <= (Y) ? (X) : (Y))

#define daInit(DA) ((DA)->cap = (DA)->len = 0, (void)((DA)->data = NULL))

#define daDrop(DA) (_daDrop(&((DA)->cap), &((DA)->len), (void **)&((DA)->data)))
void _daDrop(size_t *cap, size_t *len, void **data) {
	if (0 < *cap) {
		assert(NULL != *data);
		free(*data);
	}
	*cap = *len = 0;
	*data = NULL;
	return;
}

#define daClear(DA) (_daClear(&((DA)->cap), &((DA)->len),\
			(void **)&((DA)->data), sizeof((DA)->data[0])))
void _daClear(const size_t *cap, size_t *len, void **data, size_t el_size) {
	UNUSED(cap);
	if (0 < *len) {
		assert(NULL != *data);
		memset(*data, 0, el_size * (*len));
	}
	*len = 0;
	return;
}

#define daGrow(DA, CAP) (_daGrow(&((DA)->cap), &((DA)->len),\
			(void **)&((DA)->data), sizeof((DA)->data[0]), (CAP)))
int _daGrow(size_t *cap, const size_t *len, void **data, size_t el_size, size_t new_cap) {
	void *new_data;
	assert(*cap < new_cap);
	new_data = malloc(el_size * new_cap);
	if (!new_data)
		return -1;
	memset(new_data, 0, el_size * new_cap);

	if (0 < *len) {
		assert(NULL != *data);
		memcpy(new_data, *data, el_size * (*len));
	}
	if (0 < *cap) {
		assert(NULL != *data);
		free(*data);
	}
	*data = new_data;
	*cap = new_cap;
	return 0;
}

#define daPut(DA, EL) (assert((DA)->len < (DA)->cap),\
		(DA)->data[(DA)->len] = (EL), (void)(DA)->len++)

#define daPutN(DA, ELS, N) (_daPutN(&((DA)->cap), &((DA)->len),\
			(void **)&((DA)->data), sizeof((DA)->data[0]),\
			(ELS), (N)))
void _daPutN(const size_t *cap, size_t *len, void **data, size_t el_size, const void *buffer, size_t n) {
	assert(*len <= SIZE_MAX - n);
	assert(*len + n <= *cap);
	memcpy(((char *)*data) + el_size * (*len), buffer, el_size * n);
	*len += n;
	return;
}

int stringAppend(string_t *str, const char *buffer, size_t len) {
	assert(str->len <= SIZE_MAX - len);
	if (str->cap < str->len + len) {
		size_t new_cap;

		new_cap = str->cap + len;
		if (4 >= new_cap)
			new_cap = 8;
		else
			new_cap = new_cap + new_cap/2;
		if (daGrow(str, new_cap) != 0)
			return -1;
	}

	assert(NULL != str->data);
	memcpy(str->data + str->len, buffer, len);
	str->len += len;
	return 0;
}

int stringCmp(string_t left, string_t right) {
	if (left.len != right.len) {
		int cmp;

		if (0 == left.len)
			return -1;
		if (0 == right.len)
			return 1;
		assert(NULL != left.data);
		assert(NULL != right.data);
		cmp = memcmp(left.data, right.data, min(left.len, right.len));
		if (0 != cmp)
			return cmp;
		
		if (left.len < right.len)
			return -1;
		return 1;
	}
	if (0 == left.len)
		return 0;
	assert(NULL != left.data);
	assert(NULL != right.data);
	return memcmp(left.data, right.data, left.len);
}

int stringToSize(string_t str, size_t *out) {
	if (0 == str.len)
		return -1;
	if (9 < str.len)
		return -1;
	// disallow leading zeros
	assert(NULL != str.data);
	if (1 < str.len && *str.data == '0')
		return -1;

	*out = 0;
	for (size_t i = 0; i < str.len; ++i) {
		if (!isdigit(str.data[i]))
			return -1;
		if (*out > SIZE_MAX / 10)
			return -1;
		if (10 * (*out) > SIZE_MAX - ((size_t)str.data[i] - '0'))
			return -1;
		*out = 10 * (*out) + ((size_t)str.data[i] - '0');
	}
	return 0;
}

// uses Fowler-Noll-Vo hash function
// link: https://en.wikipedia.org/wiki/Fowler%E2%80%93Noll%E2%80%93Vo_hash_function
size_t stringHash(string_t str) {
	static const size_t fnv_prime64 = 0x00000100000001b3;
	static const size_t fnv_offset_basis64 = 0xcbf29ce484222325;
	size_t hash;

	hash = fnv_offset_basis64;

	for (size_t i = 0; i < str.len; ++i) {
		hash = hash * fnv_prime64;
		hash = hash ^ str.data[i];
	}
	return hash;
}

void kvStoreInit(kv_store_t *store) {
	store->nbuckets = store->size = 0;
	store->buckets = NULL;
	return;
}

int kvStoreGrow(kv_store_t *store, size_t new_nbuckets) {
	kv_t **new_buckets;
	assert(store->nbuckets < new_nbuckets);

	new_buckets = malloc(new_nbuckets * sizeof(*new_buckets));
	if (!new_nbuckets)
		return -1;
	for (size_t i = 0; i < new_nbuckets; ++i)
		new_buckets[i] = NULL;

	if (0 == store->nbuckets) {
		store->buckets = new_buckets;
		store->nbuckets = new_nbuckets;
		return 0;
	}

	kv_t *node, *last;
	size_t offset;
	for (size_t i = 0; i < store->nbuckets; ++i) {
		node = store->buckets[i];

		while (node) {
			offset = stringHash(node->key) % new_nbuckets;

			if (NULL == new_buckets[offset]) {
				new_buckets[offset] = node;
				node = node->next;
				new_buckets[offset]->next = NULL;
				continue;
			}

			for (last = new_buckets[offset]; last; last = last->next) {}
			last->next = node;
			node = node->next;
			last->next->next = NULL;
		}
	}
	
	free(store->buckets);
	store->buckets = new_buckets;
	store->nbuckets = new_nbuckets;
	return 0;
}

string_t *kvStoreGet(kv_store_t *store, string_t key) {
	if (0 == store->size)
		return NULL;
	assert(NULL != store->buckets);

	size_t offset;
	
	offset = stringHash(key) % store->nbuckets;
	for (kv_t *node = store->buckets[offset]; node; node = node->next) {
		if (stringCmp(node->key, key) == 0)
			return &node->value;
	}
	return NULL;
}

int kvStoreSet(kv_store_t *store, string_t key, string_t value, string_t *old_value) {
	kv_t *new_node, *node, *prev;
	size_t offset;
	assert(0 < store->nbuckets);

	offset = stringHash(key) % store->nbuckets;
	node = store->buckets[offset];

	if (NULL == node) {
		new_node = malloc(sizeof(*new_node));
		if (!new_node)
			return -1;

		new_node->key = key;
		new_node->value = value;
		new_node->next = NULL;
		old_value = NULL;

		store->buckets[offset] = new_node;
		store->size++;
		return 0;
	}
	
	prev = NULL;
	while (node) {
		if (stringCmp(node->key, key) == 0) {
			old_value->cap = node->value.cap;
			old_value->len = node->value.len;
			old_value->data = node->value.data;

			node->value = value;
			store->size++;
			return 0;
		}
		prev = node;
		node = node->next;
	}
	assert(NULL != prev);
	assert(NULL == prev->next);

	new_node = malloc(sizeof(*new_node));
	if (!new_node)
		return -1;

	new_node->key = key;
	new_node->value = value;
	new_node->next = NULL;
	old_value = NULL;

	prev->next = new_node;
	store->size++;
	return 0;
}

void eventStreamInit(event_stream_t *stream) {
	stream->pending = 0;
	stream->pos = stream->nfds = 0;
	for (size_t i = 0; i < EVENTSTREAM_LENGTH; ++i) {
		stream->fds[i].fd = -1;
		stream->fds[i].events = 0;
		stream->fds[i].revents = 0;
	}
	return;
}

void eventStreamWatch(event_stream_t *stream, int fd, int flags) {
	assert(EVENTSTREAM_LENGTH > stream->nfds);
	assert(-1 == stream->fds[stream->nfds].fd);
	assert(0 == stream->fds[stream->nfds].events);
	assert(0 == stream->fds[stream->nfds].revents);
	assert(0 <= fd);

	stream->fds[stream->nfds].fd = fd;
	if (flags & EVENT_FLAG_READABLE)
		stream->fds[stream->nfds].events |= POLLIN;
	if (flags & EVENT_FLAG_WRITABLE)
		stream->fds[stream->nfds].events |= POLLOUT;
	stream->nfds++;
	return;
}

void eventStreamUnwatchCurrent(event_stream_t *stream) {
	assert(0 < stream->nfds);
	assert(0 < stream->pos);

	stream->pos--;
	stream->nfds--;
	memmove(stream->fds + stream->pos,
		stream->fds + stream->nfds,
		sizeof(stream->fds[0]));
	stream->fds[stream->nfds].fd = -1;
	stream->fds[stream->nfds].events = 0;
	stream->fds[stream->nfds].revents = 0;
	return;
}

int eventStreamPoll(event_stream_t *stream, int timeout) {
	stream->pos = 0;
	stream->pending = poll(stream->fds, stream->nfds, timeout);
	if (0 > stream->pending) {
		if (EAGAIN == errno || EINTR == errno) {
			stream->pending = 0;
			return 0;
		}
		return -1;
	}
	return 0;
}

int eventStreamNext(event_stream_t *stream, event_t *event) {
	if (0 >= stream->pending)
		return 0;

	for (; stream->pos < stream->nfds; ++stream->pos) {
		if (stream->fds[stream->pos].revents)
			break;
	}
	assert(stream->fds[stream->pos].revents);

	event->fd = stream->fds[stream->pos].fd;
	event->flags = 0;

	if (stream->fds[stream->pos].revents & POLLERR)
		event->flags |= EVENT_FLAG_ERROR;
	if (stream->fds[stream->pos].revents & POLLIN)
		event->flags |= EVENT_FLAG_READABLE;
	if (stream->fds[stream->pos].revents & POLLHUP)
		event->flags |= EVENT_FLAG_DROP;
	if (stream->fds[stream->pos].revents & POLLOUT)
		event->flags |= EVENT_FLAG_WRITABLE;
	stream->pending--;
	stream->pos++;
	return 1;
}

int commNonBlock(char *err, int fd) {
	int flags;

	if ((flags = fcntl(fd, F_GETFL)) < 0) {
		snprintf(err, COMM_ERROR_LENGTH,
			"fcntl(F_GETFL): %s", strerror(errno));
		return -1;
	}
	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) {
		snprintf(err, COMM_ERROR_LENGTH,
			"fcntl(F_SETFL): %s", strerror(errno));
		return -1;
	}
	return 0;
}

int commListenTcp(char *err, const char *port) {
	const int yes = 1;
	const int no = 0;
	int fd, status;
	struct addrinfo *head, *info, *node;
	struct addrinfo hints = {
		.ai_family = AF_UNSPEC,
		.ai_socktype = SOCK_STREAM,
		.ai_protocol = IPPROTO_TCP,
		.ai_flags = AI_PASSIVE
	};

	assert(':' == *port);
	if ((status = getaddrinfo(NULL, port + 1, &hints, &head)) != 0) {
		if (EAI_SYSTEM == status)
			snprintf(err, COMM_ERROR_LENGTH,
				"getaddrinfo: %s", strerror(errno));
		else
			snprintf(err, COMM_ERROR_LENGTH,
				"getaddrinfo: %s", gai_strerror(status));
		return -1;
	}
	info = NULL;
	for (node = head; node; node = node->ai_next) {
		if (AF_INET6 == node->ai_family) {
			info = node;
			break;
		} else if (AF_INET6 == node->ai_family) {
			info = node;
		}
	}
	assert(NULL != info);
	fd = socket(info->ai_family, info->ai_socktype, info->ai_protocol);
	if (0 > fd) {
		snprintf(err, COMM_ERROR_LENGTH, "socket: %s", strerror(errno));
		goto freeaddrinfo;
	}
	if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) != 0) {
		snprintf(err, COMM_ERROR_LENGTH,
			"setsockopt(SO_REUSEADDR): %s", strerror(errno));
		goto close;
	}
	if (commNonBlock(err, fd) != 0)
		goto close;
	if (AF_INET6 == info->ai_family && setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &no, sizeof(no)) != 0) {
		snprintf(err, COMM_ERROR_LENGTH,
			"setsockopt(IPV6_V6ONLY): %s", strerror(errno));
		goto close;
	}
	if (bind(fd, info->ai_addr, info->ai_addrlen) != 0) {
		snprintf(err, COMM_ERROR_LENGTH, "bind: %s", strerror(errno));
		goto close;
	}
	if (listen(fd, 4) != 0) {
		snprintf(err, COMM_ERROR_LENGTH, "listen: %s", strerror(errno));
		goto close;
	}
	goto freeaddrinfo;
close:
	close(fd);
	fd = -1;
freeaddrinfo:
	freeaddrinfo(head);
	return fd;
}

// TODO: this function silently discards errors EWOULDBLOCK while in reality if
// done right this error should never occur
int commAcceptTcp(char *err, int fd) {
	fd = accept(fd, NULL, NULL);
	if (0 > fd) {
		if (EAGAIN == errno || EWOULDBLOCK == errno || EINTR == errno)
			return -1;
		snprintf(err, COMM_ERROR_LENGTH, "accept: %s", strerror(errno));
		return -1;
	}
	return fd;
}

command_id_t commandId(string_t str) {
	for (size_t id = 1; id < COMMANDS_LENGTH; ++id) {
		if (stringCmp(str, commandNames[id]) == 0)
			return id;
	}
	return COMMAND_UNKNOWN;
}

int commandArityRangeCmp(command_id_t cmd, size_t target) {
	if (target < commandArities[cmd].min)
		return -1;
	if (target > commandArities[cmd].max)
		return 1;
	return 0;
}

void clientInit(client_t *client) {
	client->fd = -1;
	client->query_state = QUERY_PARSING_TYPE;
	client->query_cmd = COMMAND_UNKNOWN;
	daInit(&client->query_args);
	daInit(&client->query_buf);
	daInit(&client->out);
	return;
}

void clientReset(client_t *client) {
	client->query_state = QUERY_PARSING_TYPE;
	client->query_cmd = COMMAND_UNKNOWN;
	daDrop(&client->query_args);
	daDrop(&client->query_buf);
	return;
}

protocol_ret_t clientParseCh(client_t *client, const char *buffer, int *offset, int len) {
	char ch;
	assert(0 < len);
	assert(*offset < len);

	ch = buffer[*offset];
	switch (client->query_state) {
	case QUERY_PARSING_TYPE:
		if (0 == client->query_args.cap) {
			if ('*' != ch)
				return PROTOCOL_ERR_BULK_PREFIX_MISSING;
		} else if (COMMAND_UNKNOWN == client->query_cmd) {
			if ('$' != ch)
				return PROTOCOL_ERR_BULK_PREFIX_MISSING;
		} else {
			// TODO: currently only bulk strings are supported
			if ('$' != ch)
				return PROTOCOL_ERR_TYPE_UNEXPECTED;
		}
		client->query_state = QUERY_PARSING_LENGTH;
		return PROTOCOL_OK;
	case QUERY_PARSING_LENGTH:
		if (!isdigit(ch)) {
			if (0 == client->query_buf.len)
				return PROTOCOL_ERR_LENGTH_EMPTY;
			if ('\r' != ch)
				return PROTOCOL_ERR_LENGTH_UNTERMINATED;
			client->query_state = QUERY_PARSING_LENGTH_END;
			return PROTOCOL_OK;
		}

		if (0 == client->query_buf.cap) {
			if (daGrow(&client->query_buf, 9) != 0)
				return PROTOCOL_ERR_OOM;
		}
		assert(9 <= client->query_buf.cap);
		if (9 <= client->query_buf.len)
			return PROTOCOL_ERR_LENGTH_OVERFLOW;
		daPut(&client->query_buf, ch);
		return PROTOCOL_OK;
	case QUERY_PARSING_LENGTH_END:
		if ('\n' != ch)
			return PROTOCOL_ERR_LENGTH_UNTERMINATED;

		size_t parsed;
		if (stringToSize(client->query_buf, &parsed) != 0)
			return PROTOCOL_ERR_LENGTH_UNPARSEABLE;

		if (0 == client->query_args.cap) {
			// TODO: upper limit on arity
			assert(255 >= parsed);
			if (daGrow(&client->query_args, parsed) != 0)
				return PROTOCOL_ERR_OOM;
			daClear(&client->query_buf);

			client->query_state = QUERY_PARSING_TYPE;
			return PROTOCOL_OK;
		} else if (COMMAND_UNKNOWN == client->query_cmd) {
			// TODO: validate command length
			assert(255 >= parsed);
			daDrop(&client->query_buf);

			if (daGrow(&client->query_buf, parsed) != 0)
				return PROTOCOL_ERR_OOM;

			client->query_state = QUERY_PARSING_DATA;
			return PROTOCOL_OK;
		}
		// TODO: limit on query arg?
		assert(255 >= parsed);
		daDrop(&client->query_buf);

		if (daGrow(&client->query_buf, parsed) != 0)
			return PROTOCOL_ERR_OOM;

		client->query_state = QUERY_PARSING_DATA;
		return PROTOCOL_OK;
	case QUERY_PARSING_DATA:
		if (client->query_buf.len == client->query_buf.cap) {
			if ('\r' != ch)
				return PROTOCOL_ERR_DATA_UNTERMINATED;
			client->query_state = QUERY_PARSING_DATA_END;
			return PROTOCOL_OK;
		}

		size_t consumed;

		consumed = min(client->query_buf.cap - client->query_buf.len,
				(size_t)(len - *offset));
		daPutN(&client->query_buf, buffer + *offset, consumed);
		*offset = *offset + consumed - 1;
		return PROTOCOL_OK;
	case QUERY_PARSING_DATA_END:
		if ('\n' != ch)
			return PROTOCOL_ERR_DATA_UNTERMINATED;

		if (COMMAND_UNKNOWN == client->query_cmd) {
			command_id_t cmd;
			int arity_ok;

			cmd = commandId(client->query_buf);
			if (COMMAND_UNKNOWN == cmd)
				return PROTOCOL_ERR_COMMAND_UNKNOWN;
			daDrop(&client->query_buf);
			client->query_cmd = cmd;

			arity_ok = commandArityRangeCmp(
					client->query_cmd,
					client->query_args.cap - 1);

			if (0 > arity_ok)
				return PROTOCOL_ERR_COMMAND_ARITY_TOO_SMALL;
			else if (0 < arity_ok)
				return PROTOCOL_ERR_COMMAND_ARITY_TOO_BIG;

			client->query_state = QUERY_PARSING_TYPE;
			if (0 == client->query_args.cap - 1)
				return PROTOCOL_EXEC;
			return PROTOCOL_OK;
		}

		daPut(&client->query_args, client->query_buf);
		// just forget the content of the string
		// if I'd change the data pointer, I would change the element
		// in the array
		daInit(&client->query_buf);
		client->query_state = QUERY_PARSING_TYPE;
		// query_args.cap is the full length including the command
		if (client->query_args.len < client->query_args.cap - 1)
			return PROTOCOL_OK;
		return PROTOCOL_EXEC;
	}
}

void tcpServerInit(tcp_server_t *server) {
	server->fd = -1;
	server->store = NULL;
	for (size_t i = 0; i < MAX_CONNECTIONS; ++i)
		clientInit(server->clients + i);
	eventStreamInit(&server->stream);
	return;
}

void tcpServerClose(tcp_server_t *server) {
	for (size_t i = 0; i < MAX_CONNECTIONS; ++i) {
		if (0 <= server->clients[i].fd && server->fd != server->clients[i].fd)
			close(server->clients[i].fd);
		
	}
	close(server->fd);
	return;
}

// TODO: avoid linear search
client_t *tcpServerGetClient(tcp_server_t *server, int fd) {
	for (size_t i = 0; i < MAX_CONNECTIONS; ++i) {
		if (-1 == server->clients[i].fd || server->clients[i].fd == fd)
			return server->clients + i;
	}
	return NULL;
}

size_t tcpServerClientCount(tcp_server_t *server) {
	if (1 >= server->stream.nfds)
		return 0;
	return server->stream.nfds - 1;
}

int tcpServerExecQuery(tcp_server_t *server, client_t *client) {
	int ok;

	switch (client->query_cmd) {
	case COMMAND_PING:
		if (0 >= client->query_args.len) {
			if (stringAppend(&client->out, "+PONG\r\n", 9) != 0)
				return PROTOCOL_ERR_OOM;
		} else {
			char buffer_bulk_length[9];
			string_t arg;
			int digits;
			assert(1 == client->query_args.len);
			arg = client->query_args.data[0];


			if (stringAppend(&client->out, "*1\r\n$", 7) != 0)
				return PROTOCOL_ERR_OOM;

			assert(1000000 > arg.len);
			digits = snprintf(buffer_bulk_length, sizeof(buffer_bulk_length),
				"%zu", arg.len);

			assert(0 <= digits);
			if (stringAppend(&client->out, buffer_bulk_length, (size_t)digits) != 0)
				return PROTOCOL_ERR_OOM;

			if (stringAppend(&client->out, "\r\n", 2) != 0)
				return PROTOCOL_ERR_OOM;
			if (stringAppend(&client->out, arg.data, arg.len) != 0)
				return PROTOCOL_ERR_OOM;
			if (stringAppend(&client->out, "\r\n", 2) != 0)
				return PROTOCOL_ERR_OOM;
		}
		break;
	case COMMAND_SET:
		assert(2 == client->query_args.len);

		fprintf(stderr, "SET {cap:%zu len:%zu data:%.*s} {cap:%zu len:%zu data:%.*s}\n",
			client->query_args.data[0].cap,
			client->query_args.data[0].len,
			(int)client->query_args.data[0].len,
			client->query_args.data[0].data,
			client->query_args.data[1].cap,
			client->query_args.data[1].len,
			(int)client->query_args.data[1].len,
			client->query_args.data[1].data);
		if (0 == server->store->nbuckets) {
			if (kvStoreGrow(server->store, 32) != 0)
				return PROTOCOL_ERR_OOM;
		}
		ok = kvStoreSet(server->store,
				client->query_args.data[0],
				client->query_args.data[1], NULL);
		if (0 != ok)
			return PROTOCOL_ERR_OOM;

		string_t *val = kvStoreGet(server->store, client->query_args.data[0]);
		fprintf(stderr, "GET {cap:%zu len:%zu data:%.*s}\n",
			val->cap,
			val->len,
			(int)val->len,
			val->data);

		if (stringAppend(&client->out, "+OK\r\n", 5) != 0)
			return PROTOCOL_ERR_OOM;
		break;
	case COMMAND_UNKNOWN:
	case COMMANDS_LENGTH:
		// command not allowed
		assert(0);
		break;
	}
	return PROTOCOL_OK;
}

int tcpServerParseAndExec(tcp_server_t *server, client_t *client, const char *buffer, int len) {
	protocol_ret_t ret;
	assert(0 < len);

	for (int i = 0; i < len; ++i) {
		ret = clientParseCh(client, buffer, &i, len);
		if (PROTOCOL_OK > ret) {
			return ret;
		} else if (PROTOCOL_EXEC == ret) {
			ret = tcpServerExecQuery(server, client);
			if (0 != ret)
				return ret;
			clientReset(client);
			continue;
		}
	}
	return 0;
}

int tcpServerHandle(tcp_server_t *server, event_t event) {
	char err[COMM_ERROR_LENGTH] = {0};
	client_t *client;

	if (event.fd == server->fd) {
		int cfd;

		if (event.flags & EVENT_FLAG_ERROR) {
			shutdown(server->fd, SHUT_RD);
			// TODO: get async socket error
			fprintf(stderr, "error on server socket\n");
			return -1;
		}
		assert(!(event.flags & EVENT_FLAG_WRITABLE));
		assert(!(event.flags & EVENT_FLAG_DROP));
		assert(event.flags & EVENT_FLAG_READABLE);

		cfd = commAcceptTcp((char *)err, server->fd);
		if (0 > cfd) {
			if (0 == *err)
				return 0;
			fprintf(stderr, "failed to accept: %s\n", err);
			shutdown(server->fd, SHUT_RD);
			return -1;
		}
		if (MAX_CONNECTIONS <= tcpServerClientCount(server)) {
			close(cfd);
			fprintf(stderr, "closed client immediately\n");
			return 0;
		}

		client = tcpServerGetClient(server, cfd);
		assert(NULL != client);
		assert(-1 == client->fd);
		eventStreamWatch(&server->stream,
				cfd, EVENT_FLAG_READABLE | EVENT_FLAG_WRITABLE);
		client->fd = cfd;
		return 0;
	} else {
		client = tcpServerGetClient(server, event.fd);
		assert(NULL != client);
		assert(event.fd == client->fd);

		if (event.flags & EVENT_FLAG_ERROR) {
			close(client->fd);
			// TODO: get async socket error
			fprintf(stderr, "error on client socket\n");
			return 0;
		}

		int closing = 0;

		if (event.flags & EVENT_FLAG_READABLE) {
			char buffer[1024];
			int nread;

			nread = read(client->fd, buffer, sizeof(buffer));
			if (0 > nread) {
				assert(EAGAIN != errno && EWOULDBLOCK != errno);
				if (EINTR == errno)
					return 0;
				shutdown(client->fd, SHUT_RDWR);
				fprintf(stderr, "failed to read: %s\n", strerror(errno));
				closing = 1;
			} else if (0 == nread) {
				shutdown(client->fd, SHUT_RDWR);
				fprintf(stderr, "client disconnected\n");
				closing = 1;
			} else {
				int status;

				status = tcpServerParseAndExec(server,
						client,
						buffer, nread);
				// TODO: send error to client
				if (0 > status) {
					shutdown(client->fd, SHUT_RDWR);
					fprintf(stderr, "parsing error: %d\n", status);
					closing = 1;
				}
			}
		}

		if (event.flags & EVENT_FLAG_DROP) {
			shutdown(client->fd, SHUT_RDWR);
			fprintf(stderr, "client disconnected during poll\n");
			closing = 1;
		}

		if (
			(event.flags & EVENT_FLAG_WRITABLE)
			&& client->out.len > 0
			&& !closing
		) {
			int nwritten;

			nwritten = write(client->fd,
					client->out.data, client->out.len);

			if (0 > nwritten) {
				// TODO: EAGAIN and EWOULDBLOCK?
				if (EAGAIN != errno
					&& EWOULDBLOCK != errno
					&& EINTR != errno) {
					shutdown(client->fd, SHUT_RDWR);
					fprintf(stderr,
						"failed to write: %s\n",
						strerror(errno));
					closing = 1;
				}
			} else if (0 == nwritten) {
				// TODO: this should be impossible
				assert(0);
			} else {
				assert(NULL != client->out.data);
				memmove(client->out.data,
					client->out.data + nwritten, nwritten);
				client->out.len -= nwritten;
			}
		}

		if (closing) {
			close(client->fd);
			clientReset(client);
			daDrop(&client->out);
			client->fd = -1;
			eventStreamUnwatchCurrent(&server->stream);
		}
		return 0;
	}
}

#if defined(VALKYKY_EXE)
kv_store_t valkyky;

int main(int argc, char **argv) {
	UNUSED(argc);
	UNUSED(argv);

	const char *port = ":12345";
	char err[COMM_ERROR_LENGTH] = {0};
	int fd;
	tcp_server_t server;
	event_t event;

	fd = commListenTcp((char *)err, port);
	if (0 > fd) {
		fprintf(stderr, "failed to listen: %s\n", err);
		return 2;
	}
	tcpServerInit(&server);
	server.fd = fd;
	server.store = &valkyky;
	kvStoreInit(&valkyky);
	eventStreamWatch(&server.stream, server.fd, EVENT_FLAG_READABLE);

	for (;;) {
		if (eventStreamPoll(&server.stream, 10) != 0) {
			fprintf(stderr, "failed to poll\n");
			goto close;
		}

		while (eventStreamNext(&server.stream, &event)) {
			if (tcpServerHandle(&server, event) != 0) {
				fprintf(stderr, "failed to handle\n");
				goto close;
			}
		}
	}

	return 0;
close:
	tcpServerClose(&server);
	return 1;
}
#endif // VALKYKY_EXE
