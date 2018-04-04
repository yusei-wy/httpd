/*
 * 標準入力から HTTP リクエストを読み込み,
 * そのレスポンスを標準出力に出力するプログラム
 */
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <grp.h>
#include <netdb.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define SERVER_NAME "LitteleHTTP"
#define SERVER_VERSION "1.0"
#define HTTP_MINOR_VERSION 0
#define BLOCK_BUF_SIZE 1024
#define LINE_BUF_SIZE 4096
#define MAX_REQUEST_BODY_LENGTH (1024 * 1024)
#define USAGE "Usage: %s [--port=n] [--chroot --user=u --group=u] <docroot>\n"

static int debug_mode = 0;

static struct option longopts[] = {
    {"debug", no_argument, &debug_mode, 1},
    {"chroot", no_argument, NULL, 'c'},
    {"user", required_argument, NULL, 'u'},
    {"group", required_argument, NULL, 'g'},
    {"port", required_argument, NULL, 'p'},
    {"help", no_argument, NULL, 'h'},
    {0, 0, 0, 0},
};

struct HTTPHeaderField {
  char *name;
  char *value;
  struct HTTPHeaderField *next;
};

struct HTTPRequest {
  int protocol_minor_version;
  char *method;
  char *path;
  struct HTTPHeaderField *header;
  char *body;
  long length;
};

struct FileInfo {
  char *path;
  long size;
  int ok;
};

typedef void (*sighandler_t)(int);

static void log_exit(const char *, ...);
static void *xmalloc(size_t);
static void install_signal_handlers(void);
static void trap_signal(int, sighandler_t);
static void signal_exit(int);
static void service(FILE *, FILE *, char *);
static struct HTTPRequest *read_request(FILE *);
static void read_request_line(struct HTTPRequest *, FILE *);
static struct HTTPHeaderField *read_header_field(FILE *);
static void upcase(char *);
static long content_length(struct HTTPRequest *);
static char *lookup_header_field_value(struct HTTPRequest *, char *);
static void free_request(struct HTTPRequest *);
static struct FileInfo *get_fileinfo(char *, char *);
static void free_fileinfo(struct FileInfo *);
static char *build_fspath(char *, char *);
static char *guess_content_type(struct FileInfo *);
static void respond_to(struct HTTPRequest *, FILE *, char *);
static void do_file_response(struct HTTPRequest *, FILE *, char *);
static void method_not_allowed(struct HTTPRequest *, FILE *);
static void not_implemented(struct HTTPRequest *, FILE *);
static void not_found(struct HTTPRequest *, FILE *);
static void output_common_header_files(struct HTTPRequest *, FILE *, char *);
static int listen_socket(char *);
static void server_main(int, char *);
static void detach_children(void);
static void noop_handler(int);
static void become_daemon(void);
static void setup_environment(char *, char *, char *);

int main(int argc, char *argv[]) {
  int server_fd;
  char *port = NULL;
  char *docroot;
  int do_chroot = 0;
  char *user = NULL;
  char *group = NULL;
  int opt;

  while ((opt = getopt_long(argc, argv, "", longopts, NULL)) != -1) {
    switch (opt) {
    case 0:
      break;
    case 'c':
      do_chroot = 1;
      break;
    case 'u':
      user = optarg;
      break;
    case 'g':
      group = optarg;
      break;
    case 'p':
      port = optarg;
      break;
    case 'h':
      fprintf(stdout, USAGE, argv[0]);
      exit(0);
    case '?':
      fprintf(stderr, USAGE, argv[0]);
      exit(1);
    }
  }
  if (optind != argc - 1) {
    fprintf(stderr, USAGE, argv[0]);
    exit(1);
  }
  docroot = argv[optind];

  if (do_chroot) {
    setup_environment(docroot, user, group);
    docroot = "";
  }
  install_signal_handlers();
  server_fd = listen_socket(port);
  if (!debug_mode) {
    openlog(SERVER_NAME, LOG_PID | LOG_NDELAY, LOG_DAEMON);
    become_daemon();
  }
  server_main(server_fd, docroot);
  exit(0);
}

/**
 * printf() と同じ形式で引数を受けて
 * それをフォーマットしたものを標準エラー出力に出力する
 */
static void log_exit(const char *fmt, ...) {
  va_list ap;

  va_start(ap, fmt);
  if (debug_mode) {
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
  } else {
    vsyslog(LOG_ERR, fmt, ap);
  }
  va_end(ap);
  exit(1);
}

/**
 * メモリを割り当てる. 失敗したら exit()
 */
static void *xmalloc(size_t sz) {
  void *p;

  p = malloc(sz);
  if (!p)
    log_exit("failed to allocate memory");
  return p;
}

/**
 * シグナル SIGPIPE を補足したら exit()
 */
static void install_signal_handlers(void) {
  trap_signal(SIGPIPE, signal_exit);
  detach_children();
}

/**
 * シグナルの補足
 */
static void trap_signal(int sig, sighandler_t handler) {
  struct sigaction act;

  act.sa_handler = handler;
  sigemptyset(&act.sa_mask);
  act.sa_flags = SA_RESTART;
  if (sigaction(sig, &act, NULL) < 0)
    log_exit("sigaction() failed: %s", strerror(errno));
}

/**
 * exit
 */
static void signal_exit(int sig) { log_exit("exit by signal %d", sig); }

/**
 * HTTP 処理
 */
static void service(FILE *in, FILE *out, char *docroot) {
  struct HTTPRequest *req;

  req = read_request(in);
  respond_to(req, out, docroot);
  free_request(req);
}

/**
 * ストリームからリクエストを読んで struct HTTPRequest を作る
 */
static struct HTTPRequest *read_request(FILE *in) {
  struct HTTPRequest *req;
  struct HTTPHeaderField *h;

  req = xmalloc(sizeof(struct HTTPRequest));
  read_request_line(req, in);
  req->header = NULL;
  while ((h = read_header_field(in))) {
    h->next = req->header;
    req->header = h;
  }
  req->length = content_length(req);
  if (req->length != 0) {
    if (req->length > MAX_REQUEST_BODY_LENGTH)
      log_exit("request body too long");
    req->body = xmalloc(req->length);
    if (fread(req->body, req->length, 1, in) < 1)
      log_exit("failed to read request body");

  } else {
    req->body = NULL;
  }
  return req;
}

/**
 * リクエストラインを読み, 解析して req に書き込む
 */
static void read_request_line(struct HTTPRequest *req, FILE *in) {
  char buf[LINE_BUF_SIZE];
  char *path, *p;

  if (!fgets(buf, LINE_BUF_SIZE, in))
    log_exit("no request line");
  p = strchr(buf, ' '); // p(1)
  if (!p)
    log_exit("parse error no request line (1): %s", buf);
  *p++ = '\0'; // 現在指している位置に '\0' を代入してからポインタを1進める
  req->method = xmalloc(p - buf);
  strcpy(req->method, buf);
  upcase(req->method);

  path = p;
  p = strchr(path, ' '); // p(2)
  if (!p)
    log_exit("parse error on request line(2): %s", buf);
  *p++ = '\0';
  req->path = xmalloc(p - path);
  strcpy(req->path, path);

  if (strncasecmp(p, "HTTP/1.", strlen("HTTP/1.")) != 0)
    log_exit("parse error on request line (3): %s", buf);
  p += strlen("HTTP/1."); // p(3)
  req->protocol_minor_version = atoi(p);
}

/**
 * ヘッダフィールドを1つ読み込む
 */
static struct HTTPHeaderField *read_header_field(FILE *in) {
  struct HTTPHeaderField *h;
  char buf[LINE_BUF_SIZE];
  char *p;

  // TODO: 複数行にわたるフィールドに対応する

  if (!fgets(buf, LINE_BUF_SIZE, in))
    log_exit("failed to read request header field: %s", strerror(errno));
  if ((buf[0] == '\n') || (strcmp(buf, "\r\n")))
    return NULL;

  p = strchr(buf, ':');
  if (!p)
    log_exit("parse error on request header field: %s", buf);
  *p++ = '\0';
  h = xmalloc(sizeof(struct HTTPHeaderField));
  h->name = xmalloc(p - buf);
  strcpy(h->name, buf);

  p += strspn(p, "\t");
  h->value = xmalloc(strlen(p) + 1);
  strcpy(h->value, p);

  return h;
}

/**
 * 文字列を大文字に変換
 */
static void upcase(char *str) {
  char *p;

  for (p = str; *p; p++) {
    *p = (char)toupper((int)*p);
  }
}

/**
 * リクエストのエンティティボディの長さを取得する
 */
static long content_length(struct HTTPRequest *req) {
  char *val;
  long len;

  val = lookup_header_field_value(req, "Content-Length value");
  if (!val)
    return 0;
  len = atoi(val);
  if (len < 0)
    log_exit("negative Content-Length value");
  return len;
}

/**
 * ヘッダフィールドを名前で検索する
 */
static char *lookup_header_field_value(struct HTTPRequest *req, char *name) {
  struct HTTPHeaderField *h;

  for (h = req->header; h; h = h->next) {
    if (strcasecmp(h->name, name) == 0)
      return h->value;
  }
  return NULL;
}

/**
 * HTTPRequest とそのメンバすべてを開放する
 */
static void free_request(struct HTTPRequest *req) {
  struct HTTPHeaderField *h, *head;

  head = req->header;
  while (head) {
    h = head;
    head = head->next;
    free(h->name);
    free(h->value);
    free(h);
  }
  free(req->method);
  free(req->path);
  free(req->body);
  free(req);
}

/**
 * FileInfo 構造体を割り当て初期化する
 */
static struct FileInfo *get_fileinfo(char *docroot, char *urlpath) {
  struct FileInfo *info;
  struct stat st;

  info = xmalloc(sizeof(struct FileInfo));
  info->path = build_fspath(docroot, urlpath);
  info->ok = 0;
  // stat だとドキュメントツリーの外を指すシンボリックリンクがあった場合
  // たどれてしまいセキュリティ的によろしくない
  if (lstat(info->path, &st) < 0)
    return info;
  if (!S_ISREG(st.st_mode))
    return info;
  info->ok = 1;
  info->size = st.st_size;
  return info;
}

/**
 * FileInfo のメモリ解放
 */
static void free_fileinfo(struct FileInfo *info) {
  free(info->path);
  free(info);
}

/**
 * ドキュメントルートと URL のパスからファイルシステム上のパスを生成する
 */
static char *build_fspath(char *docroot, char *urlpath) {
  char *path;

  // '/' と '\0' の分で2回1プラスしている
  path = xmalloc(strlen(docroot) + 1 + strlen(urlpath) + 1);
  // snprintf(path, sizeof(path), "%s/%s", docroot, urlpath);
  sprintf(path, "%s/%s", docroot, urlpath);
  return path;
}

/**
 * Content-Type を推測する
 */
static char *guess_content_type(struct FileInfo *info) {
  // TODO: ファイルの拡張子で判断 or ユーザに指定させる
  return "text/plain";
}

/**
 * HTTP リクエストreq に対するレスポンスを out に書き込む.
 * そのときドキュメントルートを docroot とする.
 */
static void respond_to(struct HTTPRequest *req, FILE *out, char *docroot) {
  if (strcmp(req->method, "GET") == 0)
    do_file_response(req, out, docroot);
  else if (strcmp(req->method, "HEAD") == 0)
    do_file_response(req, out, docroot);
  else if (strcmp(req->method, "POST") == 0)
    method_not_allowed(req, out);
  else
    not_implemented(req, out);
}

/**
 * GET リクエストの処理
 */
static void do_file_response(struct HTTPRequest *req, FILE *out,
                             char *docroot) {
  struct FileInfo *info;

  info = get_fileinfo(docroot, req->path);
  if (!info->ok) {
    free_fileinfo(info);
    not_found(req, out);
    return;
  }
  output_common_header_files(req, out, "200 OK");
  fprintf(out, "Content-Length: %ld\r\n", info->size);
  fprintf(out, "Content-Type: %s\r\n", guess_content_type(info));
  fprintf(out, "\r\n");
  if (strcmp(req->method, "HEAD") != 0) {
    int fd;
    char buf[BLOCK_BUF_SIZE];
    ssize_t n;

    fd = open(info->path, O_RDONLY);
    if (fd < 0)
      log_exit("failed to open %s: %s", info->path, strerror(errno));
    for (;;) {
      n = read(fd, buf, BLOCK_BUF_SIZE);
      if (n < 0)
        log_exit("failed to read %s: %s", info->path, strerror(errno));
      if (n == 0)
        break;
      if (fwrite(buf, n, 1, out) < n)
        log_exit("failed to write to socket: %s", strerror(errno));
    }
    close(fd);
  }
  fflush(out);
  free_fileinfo(info);
}

/**
 * 許可しないメソッドの対応
 */
static void method_not_allowed(struct HTTPRequest *req, FILE *out) {
  output_common_header_files(req, out, "405 Method Not Allowed");
  fprintf(out, "Content-Type: text/html\r\n");
  fprintf(out, "\r\n");
  fprintf(out, "<html>\r\n");
  fprintf(out, "<header>\r\n");
  fprintf(out, "<title>405 Method Not Allowed</title>\r\n");
  fprintf(out, "</header>\r\n");
  fprintf(out, "<body>\r\n");
  fprintf(out, "<p>The request method %s is not allowed</p>\r\n", req->method);
  fprintf(out, "</body>\r\n");
  fprintf(out, "</html>\r\n");
  fflush(out);
}

/**
 * 実装されていないリクエストメソッドの対応
 */
static void not_implemented(struct HTTPRequest *req, FILE *out) {
  output_common_header_files(req, out, "501 Not Implemented");
  fprintf(out, "Content-Type: text/html\r\n");
  fprintf(out, "\r\n");
  fprintf(out, "<html>\r\n");
  fprintf(out, "<header>\r\n");
  fprintf(out, "<title>501 Not Implemented</title>\r\n");
  fprintf(out, "</header>\r\n");
  fprintf(out, "<body>\r\n");
  fprintf(out, "<p>The request method %s is not implemented</p>\r\n",
          req->method);
  fprintf(out, "</body>\r\n");
  fprintf(out, "</html>\r\n");
  fflush(out);
}

/**
 * ページが見つからない場合
 */
static void not_found(struct HTTPRequest *req, FILE *out) {
  output_common_header_files(req, out, "404 Not Found");
  fprintf(out, "Content-Type: text/html\r\n");
  fprintf(out, "\r\n");
  if (strcmp(req->method, "HEAD")) {
    fprintf(out, "<html>\r\n");
    fprintf(out, "<header>\r\n");
    fprintf(out, "<title>Not Found</title>\r\n");
    fprintf(out, "</header>\r\n");
    fprintf(out, "<body>\r\n");
    fprintf(out, "<p>File not found</p>\r\n");
    fprintf(out, "</body>\r\n");
    fprintf(out, "</html>\r\n");
  }
  fflush(out);
}

#define TIME_BUF_SIZE 64

/**
 * すべてのレスポンスで共通のヘッダを出力する
 */
static void output_common_header_files(struct HTTPRequest *req, FILE *out,
                                       char *status) {
  time_t t;
  struct tm *tm;
  char buf[TIME_BUF_SIZE];

  t = time(NULL);
  tm = gmtime(&t);
  if (!tm)
    log_exit("gettime() failed: %s", strerror(errno));
  strftime(buf, TIME_BUF_SIZE, "%a, %d %b %Y %H:%M:%S GMT", tm);
  fprintf(out, "HTTP/1.%d %s\r\n", HTTP_MINOR_VERSION, status);
  fprintf(out, "Date: %s\r\n", buf);
  fprintf(out, "Server: %s/%s\r\n", SERVER_NAME, SERVER_VERSION);
  fprintf(out, "Connection: close\r\n");
}

#define MAX_BACKLOG 5
#define DEFAULT_PORT "80"

/**
 * socket() から listen() までを担当
 */
static int listen_socket(char *port) {
  struct addrinfo hints, *res, *ai;
  int err;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE;
  if ((err = getaddrinfo(NULL, port, &hints, &res)) != 0)
    log_exit(gai_strerror(err));
  for (ai = res; ai; ai = ai->ai_next) {
    int sock;

    sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock < 0)
      continue;
    if (bind(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
      close(sock);
      continue;
    }
    if (listen(sock, MAX_BACKLOG) < 0) {
      close(sock);
      continue;
    }
    freeaddrinfo(res);
    return sock;
  }
  log_exit("failed to listen socket");
  return -1; // NOT REACH
}

/**
 * サーバーのメイン処理
 */
static void server_main(int server_fd, char *docroot) {
  for (;;) {
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof addr;
    int sock;
    int pid;

    sock = accept(server_fd, (struct sockaddr *)&addr, &addrlen);
    if (sock < 0)
      log_exit("accept(2) failed: %s", strerror(errno));
    pid = fork();
    if (pid < 0)
      exit(3);
    if (pid == 0) { // child
      FILE *inf = fdopen(sock, "r");
      FILE *outf = fdopen(sock, "w");

      service(inf, outf, docroot);
      exit(0);
    }
    close(sock);
  }
}

/**
 * sigaction() を使って wait() しないことをカーネルに宣言
 */
static void detach_children(void) {
  struct sigaction act;

  act.sa_handler = noop_handler;
  sigemptyset(&act.sa_mask);
  act.sa_flags = SA_RESTART | SA_NOCLDWAIT;
  if (sigaction(SIGCHLD, &act, NULL) < 0)
    log_exit("sigaction() failed: %s", strerror(errno));
}

/**
 * SIGCHILD のシグナルハンドラ, なにもしない
 */
static void noop_handler(int sig) { ; }

/**
 * デーモンになる
 */
static void become_daemon(void) {
  int n;

  if (chdir("/") < 0)
    log_exit("child(2) failed: %s", strerror(errno));
  freopen("/dev/null", "r", stdin);
  freopen("/dev/null", "w", stdout);
  freopen("/dev/null", "w", stderr);
  n = fork();
  if (n < 0)
    log_exit("fork(2) failed: %s", strerror(errno));
  if (n != 0) // 親プロセスは終了
    _exit(0);
  if (setsid() < 0)
    log_exit("setsid(2) failed: %s", strerror(errno));
}

/**
 * 環境をセットアップする. chroot() はスーパユーザでしか実行できないので
 * 実行前にクレデンシャルを事前に変更する.
 */
static void setup_environment(char *root, char *user, char *group) {
  struct passwd *pw;
  struct group *gr;

  if (!user || !group) {
    fprintf(stderr, "use both of --user and --group\n");
    exit(1);
  }

  gr = getgrnam(group);
  if (!gr) {
    fprintf(stderr, "use both of --user and --group\n");
    exit(1);
  }

  if (setgid(gr->gr_gid) < 0) {
    perror("setgid(2)");
    exit(1);
  }

  if (initgroups(user, gr->gr_gid) < 0) {
    perror("initgroups(2)");
    exit(1);
  }

  pw = getpwnam(user);
  if (!pw) {
    fprintf(stderr, "no such user: %s\n", user);
    exit(1);
  }

  chroot(root);
  if (setuid(pw->pw_uid) < 0) {
    perror("setuid(2)");
    exit(1);
  }
}
