#ifndef _INCLUDE_BASE
#define _INCLUDE_BASE

#include "utils.h"

#define DEFAULT_SESSION_TIMEOUT 3600
#define DEFAULT_HTPASSWD "/etc/apache2/.htpasswd"
#define DEFAULT_LOCKFILE "/var/log/auth2cookie/auth2cookie.lock"
#define DEFAULT_SECRETS_DIR "/var/log/auth2cookie"
#define DEFAULT_URL_COOKIE "IL-URL"
#define DEFAULT_HTML_FOLDER "/var/www/html"
#define DEFAULT_ID_MAP_FILE "/usr/local/etc/oauth-id-map.txt"
#define DEFAULT_MY_CSS "/auth2cookie/ui.css"

#define SECONDS_PER_YEAR 31536000

#define MINIMUM_SESSION_TIMEOUT 60 /* seconds */

struct _config;
typedef struct _config _CONFIG;

#include "url.h"
#include "oauth.h"
#include "id-map.h"
#include "config.h"

#endif
