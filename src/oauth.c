#include "base.h"

#define MAX_SECRET_FILE_AGE 60*10  /* seconds */

_OAUTH_PROVIDER* NewOauthProvider( char* name, _OAUTH_PROVIDER* list )
  {
  _OAUTH_PROVIDER* p = (_OAUTH_PROVIDER*)SafeCalloc( 1, sizeof(_OAUTH_PROVIDER), "New _OAUTH_PROVIDER" );
  p->name = strdup( name );
  p->next = list;
  p->timeout = DEFAULT_TOKEN_TIMEOUT;
  return p;
  }

void FreeOauthProviderList( _OAUTH_PROVIDER* list )
  {
  _OAUTH_PROVIDER* p = list;
  _OAUTH_PROVIDER* pnext = list->next;

  FreeIfAllocated( &(p->name) );
  FreeIfAllocated( &(p->logoURL) );
  FreeIfAllocated( &(p->authURL) );
  FreeIfAllocated( &(p->tokenURL) );
  FreeIfAllocated( &(p->lookupURL) );
  FreeIfAllocated( &(p->clientID) );
  FreeIfAllocated( &(p->clientSecret) );
  FreeIfAllocated( &(p->scope) );
  FreeIfAllocated( &(p->receiverURL) );

  free( p );

  if( pnext!=NULL )
    FreeOauthProviderList( pnext );
  }

_OAUTH_PROVIDER* FindOAuthProvider( _OAUTH_PROVIDER* list, char* name )
  {
  if( list==NULL )
    {
    Warning( "FindOAuthProvider() - NULL list" );
    return NULL;
    }

  if( EMPTY( name ) )
    {
    Warning( "FindOAuthProvider() - no provider specified" );
    return NULL;
    }

  for( _OAUTH_PROVIDER* p=list; p!=NULL; p=p->next )
    if( NOTEMPTY( p->name )
        && strcasecmp( p->name, name ) ==0 )
      return p;

  Warning( "FindOAuthProvider() - %s not found", name );

  return NULL;
  }

void ValidateOAuthProvider( _OAUTH_PROVIDER* p )
  {
  if( p==NULL )
    Error( "ValidateOAuthProvider(NULL)" );

  if( EMPTY( p->name ) )
    Error( "ValidateOAuthProvider(no name)" );

  if( EMPTY( p->authURL ) )
    Error( "ValidateOAuthProvider(%s) - no auth URL", p->name );

  if( EMPTY( p->tokenURL ) )
    Error( "ValidateOAuthProvider(%s) - no token URL", p->name );

  if( EMPTY( p->clientID ) )
    Error( "ValidateOAuthProvider(%s) - no client ID", p->name );

  if( EMPTY( p->clientSecret ) )
    Error( "ValidateOAuthProvider(%s) - no client secret", p->name );

  if( EMPTY( p->scope ) )
    Error( "ValidateOAuthProvider(%s) - no scope", p->name );

  if( EMPTY( p->receiverURL ) )
    Error( "ValidateOAuthProvider(%s) - receiver URL", p->name );

  if( p->timeout<5 )
    Error( "ValidateOAuthProvider(%s) - token timeout must be at least 5 seconds", p->name );
  }

void PrintOAuthProvider( FILE* f, _OAUTH_PROVIDER* p )
  {
  if( p==NULL )
    Error( "PrintOAuthProvider(NULL)" );

  if( EMPTY( p->name ) )
    Error( "PrintOAuthProvider(no name)" );

  fprintf( f, "\n" );
  fprintf( f, "# OAuth provider\n" );
  fprintf( f, "OAUTH_PROVIDER %s\n", p->name );

  if( NOTEMPTY( p->logoURL ) )
    fprintf( f, "OAUTH_LOGO_URL %s\n", p->logoURL );

  if( NOTEMPTY( p->authURL ) )
    fprintf( f, "OAUTH_AUTH_URL %s\n", p->authURL );

  if( NOTEMPTY( p->tokenURL ) )
    fprintf( f, "OAUTH_TOKEN_URL %s\n", p->tokenURL );

  if( NOTEMPTY( p->lookupURL ) )
    fprintf( f, "OAUTH_LOOKUP_URL %s\n", p->lookupURL );

  if( NOTEMPTY( p->clientID ) )
    fprintf( f, "OAUTH_CLIENT_ID %s\n", p->clientID );

  if( NOTEMPTY( p->clientSecret ) )
    fprintf( f, "OAUTH_CLIENT_SECRET %s\n", p->clientSecret );

  if( NOTEMPTY( p->scope ) )
    fprintf( f, "OAUTH_SCOPE %s\n", p->scope );

  if( NOTEMPTY( p->receiverURL ) )
    fprintf( f, "OAUTH_RECEIVER_URL %s\n", p->receiverURL );

  if( p->timeout != DEFAULT_TOKEN_TIMEOUT )
    fprintf( f, "OAUTH_TOKEN_TIMEOUT %d\n", p->timeout );
  }

char* GenerateSecret( _CONFIG* conf, char* oauthProviderName, char* returnURL )
  {
  if( conf==NULL || EMPTY( conf->secretsDir ) )
    Error( "GenerateSecret() - NULL config or no secrets directory" );

  if( EMPTY( oauthProviderName ) )
    Error( "GenerateSecret() - must specify which oauth provider this is for" );

  char secretId[20];
  GenerateIdentifier( secretId, 10 );

  char secretFilename[40];
  snprintf( secretFilename, sizeof(secretFilename)-1, "secret-%s.txt", secretId );

  char* secretPath = MakeFullPath( conf->secretsDir, secretFilename );
  if( EMPTY( secretPath ) )
    Error( "Failed to generate secret path" );

  FILE* secretFile = fopen( secretPath, "w" );
  if( secretFile==NULL )
    Error( "Failed to create secret file in folder %s", conf->secretsDir );

  time_t tNow = time(NULL);
  char timeStr[100];

  fprintf( secretFile, "secret=%s\nrequestTime=%08lx\nfriendlyTime=%s\nprovider=%s\nreturnURL=%s\n",
           secretId,
           (long)tNow,
           DateTimeStr( timeStr, sizeof(timeStr)-1, 1, tNow ),
           oauthProviderName,
           EMPTY( returnURL ) ? "NULL" : returnURL
           );
  fclose( secretFile );

  return strdup( secretId );
  }

_OAUTH_PROVIDER* ValidateSecret( _CONFIG* conf, char* secretId, char** returnURL )
  {
  if( conf==NULL || EMPTY( conf->secretsDir ) )
    Error( "ValidateSecret() - no config or no secrets dir" );

  if( StringIsAnIdentifier( secretId )!=0 )
    Error( "ValidateSecret() - provided secret is not an identifier" );

  char secretFilename[40];
  snprintf( secretFilename, sizeof(secretFilename)-1, "secret-%s.txt", secretId );

  char* secretPath = MakeFullPath( conf->secretsDir, secretFilename );
  if( EMPTY( secretPath ) )
    Error( "Failed to generate secret path" );

  FILE* secretFile = fopen( secretPath, "r" );
  if( secretFile==NULL )
    Error( "Invalid secret - perhaps expired?" );

  char* providerName = NULL;
  char line[BUFLEN];
  while( fgets( line, sizeof(line)-1, secretFile ) == line )
    {
    if( strncasecmp( line, "provider=", 9 )==0 )
      providerName = strdup( StripEOL( line + 9 ) );
    else if( strncasecmp( line, "returnURL=", 10 )==0 )
      {
      if( returnURL!=NULL )
        *returnURL = strdup( StripEOL( line+10 ) );
      }
    }
  fclose( secretFile );

  if( EMPTY( providerName ) )
    {
    Warning( "Valid secret file has no provider name!" );
    return NULL;
    }

  _OAUTH_PROVIDER* p = FindOAuthProvider( conf->oauthProviders, providerName );
  if( p==NULL )
    {
    Warning( "Valid secret file specifies unknown OAuth provider [%s]", providerName );
    free( providerName );
    return NULL;
    }

  return p;
  }

void ScrubOldSecrets( _CONFIG* conf )
  {
  if( conf==NULL || EMPTY( conf->secretsDir ) )
    Error( "ScrubOldSecrets with no config or empty secrets directory" );

  DIR* d = opendir( conf->secretsDir );
  if( d==NULL )
    {
    Warning( "Cannot scan %s for old secrets file - dir won't open", conf->secretsDir );
    return;
    }

  struct dirent * de = NULL;
  while( (de=readdir( d ))!=NULL )
    {
    char* name = de->d_name;
    if( StringStartsWith( name, "secret-", 1 ) != 0
        || StringEndsWith( name, ".txt", 1 ) != 0 )
      continue; /* not a secret file */

    long age = GetFileAge( conf->secretsDir, name );
    if( age <= MAX_SECRET_FILE_AGE )
      continue;

    int err = FileUnlink2( conf->secretsDir, name );
    if( err )
      Warning( "Failed to remove %s/%s", conf->secretsDir, name );
    }

  closedir( d );
  }

char* StrDupNoUnicodeValue( char* str )
  {
  if( str==NULL )
    return str;
  if( *str==0 )
    return strdup( "" );
  if( IsUnicodeMarkup( str )==0 )
    return UnescapeUnicodeMarkup( str );
  return strdup( str );
  }

int ParseAssertion( char* json,
                    char** fullNamePtr,
                    char** givenNamePtr,
                    char** surNamePtr,
                    char** picturePtr,
                    char** emailPtr,
                    char** emailVerifiedPtr,
                    char** localePtr )
  {
  if( EMPTY( json ) )
    {
    Warning( "ParseAssertion() - empty JSON" );
    return -1;
    }

  char* fullName = NULL;
  char* givenName = NULL;
  char* surName = NULL;
  char* picture = NULL;
  char* email = NULL;
  char* emailVerified = NULL;
  char* locale = NULL;

  _TAG_VALUE* assertionTV = ParseJSON( (char*)json );
  if( assertionTV==NULL )
    {
    Warning( "ParseAssertion() - failed to parse JSON [%s]", json );
    return -1;
    }

  for( _TAG_VALUE* t=assertionTV; t!=NULL; t=t->next )
    {
    if( NOTEMPTY( t->tag ) )
      {
      if( NOTEMPTY( t->value ) )
        {
        /* Warning( "Got tag [%s]:[%s]", t->tag, t->value ); */
        if( strcasecmp( t->tag, "email" )==0 )
          email = StrDupNoUnicodeValue( t->value );
        else if( strcasecmp( t->tag, "name" )==0 )
          fullName = StrDupNoUnicodeValue( t->value );
        else if( strcasecmp( t->tag, "given_name" )==0 )
          givenName = StrDupNoUnicodeValue( t->value );
        else if( strcasecmp( t->tag, "family_name" )==0 )
          surName = StrDupNoUnicodeValue( t->value );
        else if( strcasecmp( t->tag, "picture" )==0 )
          picture = StrDupNoUnicodeValue( t->value );
        else if( strcasecmp( t->tag, "email_verified" )==0 )
          emailVerified = StrDupNoUnicodeValue( t->value );
        else if( strcasecmp( t->tag, "locale" )==0 )
          locale = StrDupNoUnicodeValue( t->value );
        /*
        else
          Warning( "Unknown tag in OAuth [%s]", t->tag );
        */
        } /* non-empty scalar value */
      else if( t->subHeaders!=NULL )
        {
        if( strcasecmp( t->tag, "picture" )==0 )
          {
          _TAG_VALUE* data = FindTagValueNoCase( t->subHeaders, "data" );
          if( data!=NULL )
            {
            _TAG_VALUE* url = FindTagValueNoCase( data->subHeaders, "url" );
            if( url!=NULL )
              {
              picture = StrDupNoUnicodeValue( url->value );
              }
            }
          }
        } /* scalaar value NULL but subheaders present */
      } /* non empty tag */
    }

  FreeTagValue( assertionTV );

  if( fullName!=NULL && fullNamePtr!=NULL )
    *fullNamePtr = fullName;

  if( givenName!=NULL && givenNamePtr!=NULL )
    *givenNamePtr = givenName;

  if( surName!=NULL && surNamePtr!=NULL )
    *surNamePtr = surName;

  if( picture!=NULL && picturePtr!=NULL )
    *picturePtr = picture;

  if( email!=NULL && emailPtr!=NULL )
    *emailPtr = email;

  if( emailVerified!=NULL && emailVerifiedPtr!=NULL )
    *emailVerifiedPtr = emailVerified;

  if( locale!=NULL && localePtr!=NULL )
    *localePtr = locale;

  return 0;
  }

int OAuthLookupFromAccessToken( _OAUTH_PROVIDER* p,
                                char* accessToken,
                                char** fullNamePtr,
                                char** givenNamePtr,
                                char** surNamePtr,
                                char** picturePtr,
                                char** emailPtr,
                                char** emailVerifiedPtr,
                                char** localePtr )
  {
  _DATA httpResponse = { 0, NULL, NULL };
  char* httpErrmsg = NULL;

  char url[BUFLEN];
  snprintf( url, sizeof(url)-1, "%s%s", p->lookupURL, accessToken );

  /*
  Notice( "Going to fetch [%s]", url );
  */

  CURLcode httpError = WebTransaction( url,
                                       HTTP_GET,
                                       NULL,
                                       0,
                                       "application/x-www-form-urlencoded",
                                       &httpResponse,
                                       NULL,
                                       NULL,
                                       NULL,
                                       NULL,
                                       NULL,
                                       p->timeout,
                                       NULL,
                                       NULL,
                                       1,
                                       1,
                                       &httpErrmsg
                                       );
  if( httpError != CURLE_OK )
    {
    Warning( "Token service returned no id_token but did yield an access_token.  "
             "The lookup service failed with HTTP error %d (%s)",
             p->name, (int)httpError, NULLPROTECT(httpErrmsg) );
    return -10;
    }

  if( httpResponse.data==NULL )
    {
    Warning( "Token service returned no id_token but did yield an access_token.  "
             "The lookup service returned no HTTP data." );
    return -11;
    }

  Notice( "Got response [%s] from [%s]", httpResponse.data, url );

  int err = ParseAssertion( (char*)httpResponse.data,
                            fullNamePtr,
                            givenNamePtr,
                            surNamePtr,
                            picturePtr,
                            emailPtr,
                            emailVerifiedPtr,
                            localePtr );

  free( httpResponse.data );
  return err;
  }

int ParseOAuthToken( _OAUTH_PROVIDER* p,
                     char* data,
                     char** fullNamePtr,
                     char** givenNamePtr,
                     char** surNamePtr,
                     char** picturePtr,
                     char** emailPtr,
                     char** emailVerifiedPtr,
                     char** localePtr )
  {
  int err = 0;

  if( EMPTY( data ) )
    return -1;

  /*
  Notice( "Parsing id_token [%s]", data );
  */

  _TAG_VALUE* messageTV = ParseJSON( data );
  if( messageTV==NULL )
    {
    Warning( "Failed to read parse JSON from token service" );
    return -2;
    }

  _TAG_VALUE* idToken = FindTagValueNoCase( messageTV, "id_token" );
  _TAG_VALUE* accessToken = FindTagValueNoCase( messageTV, "access_token" );
  if( ( idToken==NULL ) )
    {
    Notice( "id_token not provided in OAuth assertion" );
    if( accessToken==NULL || EMPTY( accessToken->value ) || EMPTY( p->lookupURL ) )
      {
      Warning( "No id_token but either no access_token or no lookup URL. "
               "Aborting OAuth parse." );
      return -3;
      }

    Notice( "access_token was provided and lookupURL is specified .. try that" );
    err = OAuthLookupFromAccessToken( p,
                                      accessToken->value,
                                      fullNamePtr,
                                      givenNamePtr,
                                      surNamePtr,
                                      picturePtr,
                                      emailPtr,
                                      emailVerifiedPtr,
                                      localePtr );
    FreeTagValue( messageTV );
    return err;
    }

  /* We got id_token! */
  char* ptr = NULL;
  int n = 0;
  for( char* segment = strtok_r( idToken->value, ".", &ptr );
       segment != NULL;
       segment = strtok_r( NULL, ".", &ptr ), ++n )
    {
    if( n!=1 )
      continue;

    /* Notice( "Segment %d - base64 encoded - [%s]", n, segment ); */

    /* might be a weird base64 dialect using  -_ instead of +/ */
    RepairBase64( segment );

    int rawLen = 0;
    unsigned char* rawToken = DecodeFromBase64( segment, strlen( segment ), &rawLen );
    if( rawLen<=0 )
      {
      Warning( "Segment %d of id_token does not decode as base64", n );
      continue;
      }

    err = ParseAssertion( (char*)rawToken,
                          fullNamePtr,
                          givenNamePtr,
                          surNamePtr,
                          picturePtr,
                          emailPtr,
                          emailVerifiedPtr,
                          localePtr );
    break;
    }

  FreeTagValue( messageTV );

  return err;
  }
