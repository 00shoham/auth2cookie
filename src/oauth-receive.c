#include "base.h"

void PrintVariable( char* name, char* value )
  {
  if( value==NULL )
    printf( "      <p>%s NULL</p>\n", name );
  else
    printf( "      <p>%s = %s</p>\n", name, value );
  }

void BasicPage( _CONFIG* conf, _OAUTH_PROVIDER* p, char* block, char* returnURL )
  {
  if( conf==NULL )
    Error( "BasicPage() - no config" );
  if( p==NULL )
    Error( "BasicPage() - no OAuth Provider" );
  if( EMPTY( block ) )
    Error( "BasicPage() - no URL parameters from IdP" );

  char* fullName = NULL;
  char* givenName = NULL;
  char* surName = NULL;
  char* picture = NULL;
  char* email = NULL;
  char* emailVerified = NULL;
  char* locale = NULL;

  int err = ParseOAuthToken( p,
                             block,
                             &fullName,
                             &givenName,
                             &surName,
                             &picture,
                             &email,
                             &emailVerified,
                             &locale );

  if( EMPTY( email ) )
    Error( "OAuth assertion did not specify e-mail address" );
  else
    Notice( "OAuth assertion has e-mail [%s]", email );

  char* localId = MapIdFromFile( p->name, email, conf->idMapFile );
  Notice( "localID == %s", NULLPROTECT( localId ) );

  if( NOTEMPTY( returnURL ) )
    { 
    _URL* url = FindURLByLocation( conf->urls, returnURL );
    if( url==NULL )
      Error( "Not permissioned for return URL [%s]", returnURL );

    char* finalId = localId==NULL ? email : localId;

    int err = UserIsValidForURL( url, finalId );
    if( err )
      Error( "User %s not permissioned for this URL - %d", finalId, err );

    int errWrite = PrintSessionCookie( url->sessionCookieName,
                                       finalId,
                                       url->timeout,
                                       conf->remoteAddrEnvVar,
                                       conf->userAgentEnvVar,
                                       conf->key );

    Notice( "PrintSessionCookie as [%s] -> %d", NULLPROTECT( finalId ), errWrite );
    if( errWrite )
      Error( "Failed to generate session cookie - %d", errWrite );
    if( NOTEMPTY( returnURL ) )
      {
      Notice( "returnURL is %s - redirecting", returnURL );
      RedirectToUrl( returnURL, conf->myCSS );
      }
    return;
    }

  printf( "Content-Type: text/html\r\n\r\n" );
  inCGI = 1;
  printf( "<html>\n" );
  printf( "  <head>\n" );
  printf( "    <title>Token response</title>\n" );
  printf( "    <link rel=\"stylesheet\" href=\"/%s\"/>\n", conf->myCSS );
  printf( "  </head>\n" );
  printf( "  <body>\n" );
  printf( "    <h1>Token response</h1>\n" );
  printf( "    <pre>\n" );
  printf( "      %s\n", block );
  printf( "    </pre>\n" );

  if( err )
    Error( "      <p><b>Failed to parse JWT id_token - %d</b></p>\n", err );
  else
    {
    PrintVariable( "fullName", fullName );
    PrintVariable( "givenName", givenName );
    PrintVariable( "surName", surName );
    PrintVariable( "picture", picture );
    PrintVariable( "email", email );
    PrintVariable( "emailVerified", emailVerified );
    PrintVariable( "locale", locale );
    PrintVariable( "localId", localId );
    }

  printf( "  </body>\n" );
  printf( "</html>\n" );
  printf( "\n" );
  }

int main( int argc, char** argv )
  {
  inCGI = 2;

  logFileHandle = fopen( "/var/log/auth2cookie/oauth-receive.log", "a" );

  char* confPath = MakeFullPath( CONFIGDIR, CONFIGFILE );
  _CONFIG* conf = (_CONFIG*)calloc( 1, sizeof( _CONFIG ) );
  if( conf==NULL ) Error( "Cannot allocate CONFIG object" );

  SetDefaults( conf );
  ReadConfig( conf, confPath );
  ValidateConfig( conf );

  char* q = getenv( "QUERY_STRING" );
  if( EMPTY( q ) )
    Error( "No URL parameters provided.  Not really redirected from the IdP?" );

  /*
   * ?state=uG8XcSt8e6&code=4%2F0AfJohXlIYZT6EBBtuWCvqxM70KXOSoTq12ZCzgE5tDCfu10wM-MxHNk-7vJHlBzAdaiSCg&scope=email+profile+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.email+https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fuserinfo.profile+openid&authuser=0&prompt=consent
   */
  char* state = NULL;
  char* code = NULL;
  /* char* scope = NULL; */
  /* char* authuser = NULL; */
  /* char* prompt = NULL; */
  char* ptr = NULL;
  for( char* arg = strtok_r( q, "?&", &ptr ); arg!=NULL; arg = strtok_r( NULL, "?&", &ptr ) )
    {
    if( strncasecmp( arg, "state=", 6 )==0 )
      state = arg+6;
    else if( strncasecmp( arg, "code=", 5 )==0 )
      code = arg+5;
    else if( strncasecmp( arg, "scope=", 6 )==0 )
      {} /* scope = arg+6; */
    else if( strncasecmp( arg, "authuser=", 9 )==0 )
      {} /* authuser = arg+9; */
    else if( strncasecmp( arg, "prompt=", 7 )==0 )
      {} /* prompt = arg+7; */
    else
      Warning( "URL parameter [%s] unexpected", arg );
    }

  /* This is normal for some IdPs.
  if( EMPTY( state ) || EMPTY( code ) || EMPTY( scope ) || EMPTY( authuser ) || EMPTY( prompt ) )
    {
    Warning( "OAuth redirection - missing one of the fields state=%s/code=%s/scope=%s/authuser=%s/prompt=%s",
           NULLPROTECT( state ),
           NULLPROTECT( code ),
           NULLPROTECT( scope ),
           NULLPROTECT( authuser ),
           NULLPROTECT( prompt )
           );
    }
  */

  if( EMPTY( state ) || EMPTY( code ) )
    Warning( "Aborting - no state or no code" );

  char* returnURL = NULL;
  _OAUTH_PROVIDER* p = ValidateSecret( conf, state, &returnURL );
  if( p==NULL )
    Error( "OAuth redirection - problem with the secret (expired?)" );

  char* urlEncodeReceiver = URLEncode( p->receiverURL );

  char post[BUFLEN];
  snprintf( post, sizeof(post)-1,
            "code=%s"
            "&client_id=%s"
            "&client_secret=%s"
            "&redirect_uri=%s"
            "&grant_type=%s",
            code,
            p->clientID,
            p->clientSecret,
            urlEncodeReceiver,
            "authorization_code"
            );

  /*
  Notice( "POST data is [%s]", post );
  */

  _DATA token = { 0, NULL, NULL };
  char* postErrmsg = NULL;

  /* need to add HTTP header
     Authorization: Basic c3FIOG9vSGV4VHo4QzAyg5T1JvNnJoZ3ExaVNyQWw6WjRsanRKZG5lQk9qUE1BVQ */

  CURLcode postError = WebTransaction( p->tokenURL,
                         HTTP_POST,
                         post,
                         0,
                         "application/x-www-form-urlencoded",
                         &token,
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
                         &postErrmsg
                         );

  if( postError != CURLE_OK )
    Error( "Called %s token service, got HTTP error %d (%s)",
           p->name, (int)postError, NULLPROTECT(postErrmsg) );

  /*
  Notice( "Got good response from %s token service", p->name );
  Notice( NULLPROTECT( token.data ) );
  */

  if( EMPTY( token.data ) )
    BasicPage( conf, p, "no data back", returnURL );
  else
    BasicPage( conf, p, (char*)token.data, returnURL );

  FreeData( &token );

  ScrubOldSecrets( conf );

  return 0;
  }
