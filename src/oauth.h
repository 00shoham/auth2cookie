#ifndef _INCLUDE_OAUTH
#define _INCLUDE_OAUTH

#define DEFAULT_TOKEN_TIMEOUT 20 /* seconds */

typedef struct _oauthProvider
  {
  char* name;
  char* logoURL;
  char* authURL;
  char* tokenURL;
  char* lookupURL;
  char* clientID;
  char* clientSecret;
  char* scope;
  char* receiverURL;
  int timeout;
  struct _oauthProvider* next;
  } _OAUTH_PROVIDER;

_OAUTH_PROVIDER* NewOauthProvider( char* name, _OAUTH_PROVIDER* list );
void FreeOauthProviderList( _OAUTH_PROVIDER* p );
_OAUTH_PROVIDER* FindOAuthProvider( _OAUTH_PROVIDER* list, char* name );
void ValidateOAuthProvider( _OAUTH_PROVIDER* p );
void PrintOAuthProvider( FILE* f, _OAUTH_PROVIDER* p );

char* GenerateSecret( _CONFIG* conf, char* oauthProviderName, char* returnURL );
_OAUTH_PROVIDER* ValidateSecret( _CONFIG* conf, char* secretId, char** returnURL );
void ScrubOldSecrets( _CONFIG* conf );

int ParseOAuthToken( _OAUTH_PROVIDER* p,
                     char* data,
                     char** fullNamePtr,
                     char** givenNamePtr,
                     char** surNamePtr,
                     char** picturePtr,
                     char** emailPtr,
                     char** emailVerifiedPtr,
                     char** localePtr );

#endif
