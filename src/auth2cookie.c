#include "base.h"

void BasicPage( _CONFIG* conf, char* title, char* msg  )
  {
  if( EMPTY( title ) || EMPTY( msg ) )
    Error( "BasicPage() requires a title and msg" );

  printf( "Content-Type: text/html\r\n\r\n" );
  printf( "<html>\n" );
  printf( "  <head>\n" );
  printf( "    <title>%s</title>\n", title );
  printf( "    <link rel='stylesheet' href='%s'/>\n", conf->myCSS );
  printf( "  </head>\n" );
  printf( "  <body>\n" );
  printf( "    <h1>%s</h1>\n", title );
  printf( "    <p>%s</p>\n", msg );
  printf( "  </body>\n" );
  printf( "</html>\n" );
  printf( "\n" );
  }

void LoginPage( _CONFIG* conf, char* user, char* errmsg, char* returnURL )
  {
  Notice( "LoginPage() - user=%s, errmsg=%s, returnURL=%s",
          NULLPROTECT( user ), NULLPROTECT( errmsg ), NULLPROTECT( returnURL ) );

  /* prompt user for login creds */
  printf( "Content-Type: text/html\r\n\r\n" );
  printf( "<html>\n" );
  printf( "  <head>\n" );
  printf( "    <title>Login</title>\n" );
  printf( "    <link rel='stylesheet' href='%s'/>\n", conf->myCSS );
  printf( "  </head>\n" );
  printf( "  <body>\n" );
  printf( "    <h1>Login</h1>\n" );
  if( NOTEMPTY( errmsg ) )
    printf( "    <p class='error'>%s</p>\n", errmsg );

  if( NOTEMPTY( conf->htPasswdFile ) )
    {
    printf( "    <form action='?LOGIN' method='post'>\n" );
    printf( "      <table>\n" );
    printf( "        <tr class='login-tr'>\n" );
    printf( "          <td class='login-td'><label for='id'>Login&nbsp;ID:</label></td>\n" );
    printf( "          <td class='login-td'><input autocapitalize='off' type='text' id='id' name='id' maxlength=50 value='%s' autofocus/></td>\n", NOTEMPTY(user)?user:"" );
    printf( "        </tr>\n" );
    printf( "        <tr class='login-tr'>\n" );
    printf( "          <td class='login-td'><label for='password'>Password:</label></td>\n" );
    printf( "          <td class='login-td'><input type='password' id='password' name='password' maxlength=50/></td>\n" );
    printf( "        </tr>\n" );
    printf( "        <tr class='login-tr'>\n" );
    printf( "        </tr>\n" );
    printf( "        <tr class='login-tr'>\n" );
    printf( "          <td class='login-td'>&nbsp;</td>\n" );
    printf( "          <td class='login-td'><input class='submit-button' type='submit' value='Login'/></td>\n" );
    printf( "        </tr>\n" );
    printf( "      </table>\n" );
    printf( "    </form>\n" );
    }

  if( conf->oauthProviders != NULL )
    {
    for( _OAUTH_PROVIDER* p = conf->oauthProviders; p!=NULL; p=p->next )
      {
      printf( "      <p><b>%s</b></p>\n", p->name );

      char* secret = GenerateSecret( conf, p->name, returnURL );
      char* urlEncodeScope = URLEncode( p->scope );
      char* urlEncodeReceiver = URLEncode( p->receiverURL );

      char requestUrl[BUFLEN];
      snprintf( requestUrl, sizeof(requestUrl)-1,
                "%s?response_type=code"
                "&client_id=%s"
                "&redirect_uri=%s"
                "&scope=%s"
                "&state=%s",
                p->authURL,
                p->clientID,
                urlEncodeReceiver,
                urlEncodeScope,
                secret );

      printf( "      <p><a href='%s'>", requestUrl );
      if( NOTEMPTY( p->logoURL ) )
        printf( "<img src='%s'/>", p->logoURL );
      else
        printf( "Login with %s", p->name );
      printf( "</a></p>\n" );

      free( secret );
      free( urlEncodeScope );
      free( urlEncodeReceiver );
      }
    }

  printf( "  </body>\n" );
  printf( "</html>\n" );
  printf( "\n" );
  }

_URL* ValidateReturnURL( _CONFIG* conf, char* url )
  {
  if( conf==NULL )
    {
    Warning( "ValidateReturnURL() - NULL conf" );
    return NULL;
    }

  if( conf->urls==NULL )
    {
    Warning( "ValidateReturnURL() - no configured URLs" );
    return NULL;
    }

  if( EMPTY( url ) )
    {
    Warning( "ValidateReturnURL() - no provided URL" );
    return NULL;
    }

  for( _URL* okURL = conf->urls; okURL!=NULL; okURL=okURL->next )
    {
    char* acceptable = okURL->location;
    if( EMPTY( acceptable ) )
      {
      Warning( "Empty URL in list of valid URLs from config file" );
      continue;
      }
    if( strchr( acceptable, '*' )!=NULL )
      {
      if( StringMatchesRegex( acceptable, url )==0 )
        {
        Notice( "URL [%s] is acceptable via wildcard match to [%s]", url, acceptable );
        return okURL; /* acceptable */
        }
      }
    else
      {
      if( strcasecmp( acceptable, url )==0 )
        {
        Notice( "URL [%s] is acceptable via exact match to [%s]", url, acceptable );
        return okURL; /* acceptable */
        }
      }
    }

  Warning( "url %s is not on acceptable list", url );
  return NULL; /* never reached */
  }

int ValidateLoginCreds( _CONFIG* conf, char** userPtr, char* returnURL, _URL* matchingURL )
  {
  if( conf==NULL || userPtr==NULL || returnURL==NULL || matchingURL==NULL )
    Error( "ValidateLoginCreds() expects a conf, userPtr, return URL and matching URL" );

  Notice( "ValidateLoginCreds() returnURL=%s", NULLPROTECT( returnURL ) );

  if( EMPTY( conf->htPasswdFile ) )
    Error( "You cannot sign in with an ID and password on this instance of auth2cookie" );

  char buf[BUFLEN];
  if( fgets( buf, sizeof(buf)-1, stdin )!=buf )
    LoginPage( conf, NULL, "Failed to parse form inputs", returnURL );
  if( strncasecmp( buf, "id=", 3 )!=0 )
    LoginPage( conf, NULL, "Expected ID input", returnURL );
  char* userEncoded = buf + 3;
  char* ptr = NULL;
  int gotId = 0;
  for( ptr=userEncoded; *ptr!=0; ++ptr )
    if( *ptr=='&' )
      {
      *(ptr++) = 0;
      gotId = 1;
      break;
      }

  if( gotId==0 )
    {
    LoginPage( conf, NULL, "Expected ID and password input", returnURL );
    exit(0);
    }

  if( EMPTY( userEncoded ) )
    {
    LoginPage( conf, NULL, "You must enter a user ID", returnURL );
    exit(0);
    }

  if( strncasecmp( ptr, "password=", 9 )!=0 )
    {
    LoginPage( conf, userEncoded, "You must submit a password", returnURL );
    exit(0);
    }

  char* passwordEncoded = ptr + 9;
  if( EMPTY( passwordEncoded ) )
    {
    LoginPage( conf, userEncoded, "You must enter a password", returnURL );
    exit(0);
    }

  char* user = URLDecode( userEncoded );
  char* password = URLDecode( passwordEncoded );

  if( IsValidPassword( user ) != 0
      || IsValidPassword( password ) !=0 )
    {
    LoginPage( conf, NULL, "User and password may only contain printable characters", returnURL );
    exit(0);
    }

  int err = UserIsValidForURL( matchingURL, user );
  if( err )
    {
    Warning( "User %s does not quality for location %s, without regard to password validity",
             user, matchingURL->location );
    return -100 + err;
    }

  err = HTPasswdCheckPassword( conf->lockFile, conf->htPasswdFile, user, password );

  Notice( "Password validation for user %s returned %d", user, err );

  if( err==0 )
    *userPtr = strdup( user );
  else
    *userPtr = NULL;

  free( user );
  free( password );

  return err;
  }

void SetReturnURL( _CONFIG* conf, char* url )
  {
  if( conf==NULL || EMPTY( conf->urlCookie ) || EMPTY( url ) )
    Error( "SetReturnURL() requires config with URL_COOKIE and a target url" );

  char* encodedUrl = NULL;
  int encodedUrlLen = 0;
  int err = EncryptAES256Base64Encode( (uint8_t*)url, strlen(url),
                                       conf->key, AES_KEYLEN,
                                       &encodedUrl, &encodedUrlLen );
  if( err==0 && encodedUrlLen>0 )
    {
    printf( "Set-Cookie: %s=%s; Max-Age=%ld\n", conf->urlCookie, encodedUrl, (long)SECONDS_PER_YEAR );
    free( encodedUrl );
    return;
    }

  Error( "SetReturnURL() - Failed to encode url - %d", err );
  }

char* ReadUrlFromEnvironment( _CONFIG* conf )
  {
  if( conf==NULL || EMPTY( conf->urlCookie ) )
    Error( "ReadUrlFromEnvironment() - no conf or urlCookie" );

  char* base64cipher = GetCookieFromEnvironment( conf->urlCookie );
  if( EMPTY( base64cipher ) )
    {
    Warning( "Cannot find cookie [%s]", conf->urlCookie );
    return NULL;
    }

  uint8_t* urlBuffer = NULL;
  size_t   urlLen = 0;
  int err = Base64DecodeDecryptAES256( base64cipher, strlen( base64cipher ),
                                       conf->key, AES_KEYLEN,
                                       &urlBuffer, &urlLen );
  if( err==0 && urlBuffer!=NULL && urlLen>0 )
    return (char*)urlBuffer;

  Warning( "ReadUrlFromEnvironment() - Failed to decode url from cookie [%s] - %d", base64cipher, err );
  return NULL;
  }

int main( int argc, char** argv )
  {
  inCGI = 2;

  logFileHandle = fopen( "/var/log/auth2cookie/auth2cookie.log", "a" );

  char* confPath = MakeFullPath( CONFIGDIR, CONFIGFILE );
  _CONFIG* conf = (_CONFIG*)calloc( 1, sizeof( _CONFIG ) );
  if( conf==NULL ) Error( "Cannot allocate CONFIG object" );

  SetDefaults( conf );
  ReadConfig( conf, confPath );
  ValidateConfig( conf );

  char* q = getenv( "QUERY_STRING" );
  if( EMPTY( q ) )
    Error( "You must specify a URL argument, such as URL=return-url" );

  /* DEBUG
  else
    Notice( "Got this query string: %s", q );
  */

  if( strncasecmp( q, "LOGOUT", 6 )==0
      || strncasecmp( q, "LOGOFF", 6 )==0 ) /* can't remember how to spell it */
    {
    char* remoteAddr = getenv( DEFAULT_REMOTE_ADDR );
    char* userAgent = getenv( DEFAULT_USER_AGENT_VAR );
    Notice( "Logout from %s @ %s", NULLPROTECT( userAgent ), NULLPROTECT( remoteAddr ) );

    char* sessionCookie = RefererCookieId( conf );
    Notice( "Session cookie name is %s", NULLPROTECT( sessionCookie ) );

    char* cookieValue = GetCookieFromEnvironment( sessionCookie );
    Notice( "Session cookie value is %s", NULLPROTECT( cookieValue ) );

    if( EMPTY( cookieValue ) )
      Notice( "Logout attempt from %s @ %s but not currently logged in",
              NULLPROTECT( userAgent ), NULLPROTECT( remoteAddr ) );
    else
      {
      char* user = NULL;
      /* get the actual cookie value */
      int err = GetIdentityFromCookie( cookieValue,
                                       &user,
                                       NULL, NULL,
                                       remoteAddr, userAgent,
                                       conf->key );
      if( err )
        Notice( "Failed to get identity from cookie offered by %s @ %s - %d",
              NULLPROTECT( userAgent ), NULLPROTECT( remoteAddr ), err );
      else
        Notice( "Logging out %s - %s @ %s",
              NULLPROTECT( user ), NULLPROTECT( userAgent ), NULLPROTECT( remoteAddr ), err );

      ClearSessionCookieSpecific( sessionCookie );
      }

    BasicPage( conf, "Logged out", "You have been signed out." );
    exit(0);
    }

  if( strncasecmp( q, "URL=", 4 )==0 )
    {
    char* encodedUrl = q+4;
    char* url = URLDecode( encodedUrl );
    _URL* configuredURL = ValidateReturnURL( conf, url );
    if( configuredURL==NULL )
      Error( "Invalid URL [%s] (a)", url );
    else
      Notice( "auth2cookie - return URL is valid" );
    SetReturnURL( conf, url );
    LoginPage( conf, NULL, NULL, url );
    free( url );
    exit(0);
    }

  if( strcasecmp( q, "LOGIN" )==0 )
    {
    /* DEBUG Notice( "LOGIN in arguments.." ); */

    char* url = ReadUrlFromEnvironment( conf );
    Notice( "ReadUrlFromEnvironment -> %s", NULLPROTECT( url ) );

    _URL* configuredURL = ValidateReturnURL( conf, url );
    if( configuredURL==NULL )
      Error( "Invalid URL [%s] (b)", url );

    char* user = NULL;
    int errLogin = ValidateLoginCreds( conf, &user, url, configuredURL );
    Notice( "ValidateLoginCreds -> %d", errLogin );

    if( errLogin==0 )
      {
      int errWrite = PrintSessionCookie( configuredURL->sessionCookieName,
                                         user,
                                         configuredURL->timeout,
                                         conf->remoteAddrEnvVar,
                                         conf->userAgentEnvVar,
                                         conf->key );
      Notice( "PrintSessionCookie -> %d", errWrite );
      if( errWrite )
        Error( "Failed to generate session cookie - %d", errWrite );
      if( NOTEMPTY( url ) )
        RedirectToUrl( url, conf->myCSS );
      exit( 0 );
      }
    else
      {
      char buf[BUFLEN];
      snprintf( buf, sizeof(buf)-1, "Bad user ID or password (%d)", errLogin );
      char* url = ReadUrlFromEnvironment( conf );
      LoginPage( conf, user, buf, url );
      exit( 0 );
      }
    }

  Error( "%s is not a defined action.", q );

  return 0;
  }
