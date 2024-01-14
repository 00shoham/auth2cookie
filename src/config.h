#ifndef _INCLUDE_CONFIG
#define _INCLUDE_CONFIG

#define CONFIGDIR "/usr/local/etc/"
#define CONFIGFILE "auth2cookie.ini"

typedef struct _config
  {
  char* configFolder;

  int currentlyParsing;
  _TAG_VALUE* parserLocation;

  /* to avoid duplicate includes */
  _TAG_VALUE *includes;

  /* macro expansion */
  _TAG_VALUE *list;

  /* used in installers and diagnostics */
  int listIncludes;
  int includeCounter;

  char* authServiceUrl;
  char* httpRefererEnvVar;
  char* myCSS;
  char* remoteAddrEnvVar;
  char* urlEnvVar;
  char* userAgentEnvVar;
  char* userEnvVar;

  uint8_t key[AES_KEYLEN];
  char* htPasswdFile;

  _URL* urls;

  char* lockFile;

  char* secretsDir;

  char* sessionCookieName;
  char* urlCookie;
  char* htmlFolder;

  char* idMapFile;
  _OAUTH_PROVIDER* oauthProviders;

  /* lua_State* L; */
  } _CONFIG;

void SetDefaults( _CONFIG* config );
void ReadConfig( _CONFIG* config, char* filePath );
void PrintConfig( FILE* f, _CONFIG* config );
void FreeConfig( _CONFIG* config );
void ValidateConfig( _CONFIG* config );

#endif
