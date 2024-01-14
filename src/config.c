#include "base.h"

char defaultKey[] =
  {
  0xdb, 0xd2, 0x5a, 0x74, 0xc7, 0x44, 0x3b, 0x43,
  0xd2, 0x24, 0xcb, 0xce, 0x63, 0x4a, 0xe5, 0x4d,
  0x5d, 0x64, 0xd6, 0xcc, 0xcb, 0x97, 0x75, 0x2b,
  0x95, 0xa8, 0x52, 0x85, 0xe6, 0xed, 0x32, 0xc1
  };

void UpdateGlobalParsingLocation( _CONFIG* config )
  {
  FreeIfAllocated( &parsingLocation );
  if( config!=NULL
      && config->parserLocation!=NULL
      && NOTEMPTY( config->parserLocation->tag ) )
    {
    char whereAmI[BUFLEN];
    snprintf( whereAmI, sizeof(whereAmI)-1, "%s::%d ",
              config->parserLocation->tag,
              config->parserLocation->iValue );
    parsingLocation = strdup( whereAmI );
    }
  }

void SetDefaults( _CONFIG* config )
  {
  memset( config, 0, sizeof(_CONFIG) );

  memcpy( config->key, defaultKey, AES_KEYLEN );

  config->authServiceUrl = strdup( DEFAULT_AUTH_URL );
  config->myCSS = strdup( DEFAULT_MY_CSS );
  config->remoteAddrEnvVar = strdup( DEFAULT_REMOTE_ADDR );
  config->sessionCookieName = strdup( DEFAULT_ID_OF_AUTH_COOKIE );
  config->urlCookie = strdup( DEFAULT_URL_COOKIE );
  config->userAgentEnvVar = strdup( DEFAULT_USER_AGENT_VAR );
  config->userEnvVar = strdup( DEFAULT_USER_ENV_VAR );

  config->httpRefererEnvVar = strdup( DEFAULT_HTTP_REFERER );

  config->htPasswdFile = strdup( DEFAULT_HTPASSWD );
  config->lockFile = strdup( DEFAULT_LOCKFILE );
  config->secretsDir = strdup( DEFAULT_SECRETS_DIR );
  config->htmlFolder = strdup( DEFAULT_HTML_FOLDER );
  config->idMapFile = strdup( DEFAULT_ID_MAP_FILE );

  /* config->L = LUAInit(); */
  }

void FreeConfig( _CONFIG* config )
  {
  if( config==NULL )
    return;

  FreeIfAllocated( &(config->configFolder) );

  if( config->urls )
    {
    FreeURLList( config->urls );
    config->urls = NULL;
    }

  if( config->list )
    {
    FreeTagValue( config->list );
    }

  if( config->includes )
    {
    FreeTagValue( config->includes );
    }

  FreeIfAllocated( &(config->authServiceUrl) );
  FreeIfAllocated( &(config->myCSS) );
  FreeIfAllocated( &(config->remoteAddrEnvVar) );
  FreeIfAllocated( &(config->sessionCookieName) );
  FreeIfAllocated( &(config->urlEnvVar) );
  FreeIfAllocated( &(config->userAgentEnvVar) );
  FreeIfAllocated( &(config->userEnvVar) );

  FreeIfAllocated( &(config->htmlFolder ) );
  FreeIfAllocated( &(config->htPasswdFile ) );
  FreeIfAllocated( &(config->httpRefererEnvVar) );
  FreeIfAllocated( &(config->idMapFile ) );
  FreeIfAllocated( &(config->lockFile ) );
  FreeIfAllocated( &(config->secretsDir ) );
  FreeIfAllocated( &(config->sessionCookieName ) );
  FreeIfAllocated( &(config->urlCookie ) );

  FreeOauthProviderList( config->oauthProviders );

  /* lua_close( config->L ); */

  free( config );
  }

void ProcessConfigLine( char* ptr, char* equalsChar, _CONFIG* config )
  {
  *equalsChar = 0;

  char* variable = TrimHead( ptr );
  TrimTail( variable );
  char* value = TrimHead( equalsChar+1 );
  TrimTail( value );

  /* indicates that we used strdup() to recompute the value ptr */
  int allocatedValue = 0;

  if( NOTEMPTY( variable ) && NOTEMPTY( value ) )
    {
    char valueBuf[BUFLEN];

    /* expand any macros in the value */
    if( strchr( value, '$' )!=NULL )
      {
      int loopMax = 10;
      while( loopMax>0 )
        {
        int n = ExpandMacros( value, valueBuf, sizeof( valueBuf ), config->list );
        if( n>0 )
          {
          if( allocatedValue )
            FREE( value );
          value = strdup( valueBuf );
          allocatedValue = 1;
          }
        else
          {
          break;
          }
        --loopMax;
        }
      }

    config->list = NewTagValue( variable, value, config->list, 1 );

    if( strcasecmp( variable, "MY_CSS" )==0 )
      {
      FreeIfAllocated( &( config->myCSS) );
      config->myCSS = strdup( value );
      }
    else if( strcasecmp( variable, "USER_ENV_VARIABLE" )==0 )
      {
      FreeIfAllocated( &(config->userEnvVar) );
      config->userEnvVar = strdup( value );
      }
    else if( strcasecmp( variable, "AUTHENTICATION_SERVICE_URL" )==0 )
      {
      FreeIfAllocated( &(config->authServiceUrl) );
      config->authServiceUrl = strdup( value );
      }
    else if( strcasecmp( variable, "URL_ENV_VARIABLE" )==0 )
      {
      FreeIfAllocated( &(config->urlEnvVar) );
      config->urlEnvVar = strdup( value );
      }
    else if( strcasecmp( variable, "REMOTE_ADDR_ENV_VARIABLE" )==0 )
      {
      FreeIfAllocated( &( config->remoteAddrEnvVar) );
      config->remoteAddrEnvVar = strdup( value );
      }
    else if( strcasecmp( variable, "USER_AGENT_ENV_VARIABLE" )==0 )
      {
      FreeIfAllocated( &( config->userAgentEnvVar) );
      config->userAgentEnvVar = strdup( value );
      }
    else if( strcasecmp( variable, "SESSION_COOKIE_ENCRYPTION_KEY" )==0 )
      {
      uint8_t binaryKey[100];
      memset( binaryKey, 0, sizeof(binaryKey)-1 );
      UnescapeString( value, binaryKey, sizeof(binaryKey) );
      memset( config->key, 0, AES_KEYLEN );
      memcpy( config->key, binaryKey, AES_KEYLEN );
      }
    else if( strcasecmp( variable, "URL" )==0 )
      {
      if( EMPTY( config->sessionCookieName ) )
        Error( "No default AUTH_COOKIE defined yet - cannot add a URL" );

      config->urls = NewURL( value, config->sessionCookieName, config->urls );
      /* Notice( "Added URL %s", value ); */
      }
    else if( strcasecmp( variable, "LOCATION" )==0 )
      {
      _URL* url = config->urls;
      if( url==NULL )
        Error( "%s must follow URL", variable );
      FreeIfAllocated( &( url->location) );
      url->location = strdup( value );
      /* Notice( "Set URL %s - LOCATION = %s", url->name, value ); */
      }
    else if( strcasecmp( variable, "USER" )==0 )
      {
      _URL* url = config->urls;
      if( url==NULL )
        Error( "%s must follow URL", variable );
      url->users = NewTagValue( "user", value, url->users, 1 );
      /* Notice( "Set URL %s - USER = %s", url->name, value ); */
      }
    else if( strcasecmp( variable, "TIMEOUT" )==0 )
      {
      _URL* url = config->urls;
      if( url==NULL )
        Error( "%s must follow URL", variable );
      int x = atoi( value );
      if( x < MINIMUM_SESSION_TIMEOUT )
        Error( "%s must be at least %d seconds", variable, MINIMUM_SESSION_TIMEOUT );
      url->timeout = x;
      /* Notice( "Set URL %s - TIMEOUT = %d", url->name, x ); */
      }
    else if( strcasecmp( variable, "HTPASSWD" )==0 )
      {
      if( strcasecmp( value, "NULL" )==0 )
        {
        config->htPasswdFile = NULL;
        }
      else
        {
        if( FileExists( value ) !=0 )
          Error( "%s file %s does not exist", variable, value );
        FreeIfAllocated( &( config->htPasswdFile) );
        config->htPasswdFile = strdup( value );
        }
      }
    else if( strcasecmp( variable, "REFERER_VAR" )==0 )
      {
      FreeIfAllocated( &( config->httpRefererEnvVar) );
      config->httpRefererEnvVar = strdup( value );
      }
    else if( strcasecmp( variable, "LOCK" )==0 )
      {
      FreeIfAllocated( &( config->lockFile) );
      config->lockFile = strdup( value );
      }
    else if( strcasecmp( variable, "SECRETS_DIR" )==0 )
      {
      FreeIfAllocated( &( config->secretsDir) );
      config->secretsDir = strdup( value );
      }
    else if( strcasecmp( variable, "SESSION_COOKIE_NAME" )==0 )
      {
      if( StringIsAnIdentifier( value ) !=0 )
        Error( "%s must be an identifier", variable );

      if( config->urls )
        {
        FreeIfAllocated( &(config->urls->sessionCookieName) );
        config->urls->sessionCookieName = strdup( value );
        }
      else
        {
        FreeIfAllocated( &( config->sessionCookieName) );
        config->sessionCookieName = strdup( value );
        }
      }
    else if( strcasecmp( variable, "URL_COOKIE" )==0 )
      {
      if( StringIsAnIdentifier( value ) !=0 )
        Error( "%s must be an identifier", variable );
      FreeIfAllocated( &( config->urlCookie) );
      config->urlCookie = strdup( value );
      }
    else if( strcasecmp( variable, "HTML_FOLDER" )==0 )
      {
      if( DirExists( value ) !=0 )
        Error( "%s must be a valid folder", variable );
      FreeIfAllocated( &( config->htmlFolder) );
      config->htmlFolder = strdup( value );
      }
    else if( strcasecmp( variable, "ID_MAP_FILE" )==0 )
      {
      if( FileExists( value ) !=0 )
        Error( "%s file %s does not exist", variable, value );
      FreeIfAllocated( &( config->idMapFile) );
      config->idMapFile = strdup( value );
      }
    else if( strcasecmp( variable, "OAUTH_PROVIDER" )==0 )
      {
      if( StringIsAnIdentifier( value ) !=0 )
        Error( "%s must be an identifier", variable );
      config->oauthProviders = NewOauthProvider( value, config->oauthProviders );
      }
    else if( strcasecmp( variable, "OAUTH_LOGO_URL" )==0 )
      {
      if( config->oauthProviders==NULL )
        Error( "%s must follow OAUTH_PROVIDER", variable );
      _OAUTH_PROVIDER* p = config->oauthProviders;
      FreeIfAllocated( &( p->logoURL ) );
      p->logoURL = strdup( value );
      }
    else if( strcasecmp( variable, "OAUTH_AUTH_URL" )==0 )
      {
      if( config->oauthProviders==NULL )
        Error( "%s must follow OAUTH_PROVIDER", variable );
      _OAUTH_PROVIDER* p = config->oauthProviders;
      FreeIfAllocated( &( p->authURL ) );
      p->authURL = strdup( value );
      }
    else if( strcasecmp( variable, "OAUTH_TOKEN_URL" )==0 )
      {
      if( config->oauthProviders==NULL )
        Error( "%s must follow OAUTH_PROVIDER", variable );
      _OAUTH_PROVIDER* p = config->oauthProviders;
      FreeIfAllocated( &( p->tokenURL ) );
      p->tokenURL = strdup( value );
      }
    else if( strcasecmp( variable, "OAUTH_LOOKUP_URL" )==0 )
      {
      if( config->oauthProviders==NULL )
        Error( "%s must follow OAUTH_PROVIDER", variable );
      _OAUTH_PROVIDER* p = config->oauthProviders;
      FreeIfAllocated( &( p->lookupURL ) );
      p->lookupURL = strdup( value );
      }
    else if( strcasecmp( variable, "OAUTH_TOKEN_TIMEOUT" )==0 )
      {
      if( config->oauthProviders==NULL )
        Error( "%s must follow OAUTH_PROVIDER", variable );
      int t = atoi( value );
      if( t<5 )
        Error( "%s must be at least 5 (seconds)", variable );

      _OAUTH_PROVIDER* p = config->oauthProviders;
      p->timeout = t;
      }
    else if( strcasecmp( variable, "OAUTH_CLIENT_ID" )==0 )
      {
      if( config->oauthProviders==NULL )
        Error( "%s must follow OAUTH_PROVIDER", variable );
      _OAUTH_PROVIDER* p = config->oauthProviders;
      FreeIfAllocated( &( p->clientID ) );
      p->clientID = strdup( value );
      }
    else if( strcasecmp( variable, "OAUTH_CLIENT_SECRET" )==0 )
      {
      if( config->oauthProviders==NULL )
        Error( "%s must follow OAUTH_PROVIDER", variable );
      _OAUTH_PROVIDER* p = config->oauthProviders;
      FreeIfAllocated( &( p->clientSecret ) );
      p->clientSecret = strdup( value );
      }
    else if( strcasecmp( variable, "OAUTH_SCOPE" )==0 )
      {
      if( config->oauthProviders==NULL )
        Error( "%s must follow OAUTH_PROVIDER", variable );
      _OAUTH_PROVIDER* p = config->oauthProviders;
      FreeIfAllocated( &( p->scope ) );
      p->scope = strdup( value );
      }
    else if( strcasecmp( variable, "OAUTH_RECEIVER_URL" )==0 )
      {
      if( config->oauthProviders==NULL )
        Error( "%s must follow OAUTH_PROVIDER", variable );
      _OAUTH_PROVIDER* p = config->oauthProviders;
      FreeIfAllocated( &( p->receiverURL ) );
      p->receiverURL = strdup( value );
      }
    }

  if( allocatedValue )
    FREE( value );
  }

void PrintConfig( FILE* f, _CONFIG* config )
  {
  if( f==NULL )
    {
    Error("Cannot print configuration to NULL file");
    }

  if( NOTEMPTY( config->myCSS )
      && strcmp( config->myCSS, DEFAULT_MY_CSS )!=0 )
    fprintf( f, "MY_CSS=%s\n", config->myCSS );

  if( NOTEMPTY( config->authServiceUrl )
      && strcmp( config->authServiceUrl, DEFAULT_AUTH_URL )!=0 )
    {
    fprintf( f, "AUTHENTICATION_SERVICE_URL=%s\n", config->authServiceUrl );
    }

  if( NOTEMPTY( config->userEnvVar )
      && strcmp( config->userEnvVar, DEFAULT_USER_ENV_VAR )!=0 )
    {
    fprintf( f, "USER_ENV_VARIABLE=%s\n", config->userEnvVar );
    }

  if( NOTEMPTY( config->urlEnvVar )
      && strcmp( config->urlEnvVar, DEFAULT_REQUEST_URI_ENV_VAR )!=0 )
    {
    fprintf( f, "URL_ENV_VARIABLE=%s\n", config->urlEnvVar );
    }

  if( NOTEMPTY( config->remoteAddrEnvVar )
      && strcmp( config->remoteAddrEnvVar, DEFAULT_REMOTE_ADDR )!=0 )
    {
    fprintf( f, "REMOTE_ADDR_ENV_VARIABLE=%s\n", config->remoteAddrEnvVar );
    }

  if( NOTEMPTY( config->userAgentEnvVar )
      && strcmp( config->userAgentEnvVar, DEFAULT_USER_AGENT_VAR )!=0 )
    {
    fprintf( f, "USER_AGENT_ENV_VARIABLE=%s\n", config->userAgentEnvVar );
    }

  if( memcmp( config->key, defaultKey, AES_KEYLEN )!=0 )
    {
    char key_ascii[100];
    fprintf( f, "SESSION_COOKIE_ENCRYPTION_KEY=%s\n", EscapeString( config->key, AES_KEYLEN, key_ascii, sizeof( key_ascii ) ) );
    }

  if( config->htPasswdFile ==NULL )
    fprintf( f, "HTPASSWD=NULL\n" );
  else
    {
    if( NOTEMPTY( config->htPasswdFile )
        && strcmp( config->htPasswdFile, DEFAULT_HTPASSWD )!=0 )
      fprintf( f, "HTPASSWD=%s\n", config->htPasswdFile );
    }

  if( NOTEMPTY( config->httpRefererEnvVar )
      && strcmp( config->httpRefererEnvVar, DEFAULT_HTTP_REFERER )!=0 )
    fprintf( f, "REFERER_VAR=%s\n", config->httpRefererEnvVar );

  if( NOTEMPTY( config->lockFile )
      && strcmp( config->lockFile, DEFAULT_LOCKFILE )!=0 )
    fprintf( f, "LOCK=%s\n", config->lockFile );

  if( NOTEMPTY( config->secretsDir )
      && strcmp( config->secretsDir, DEFAULT_SECRETS_DIR )!=0 )
    fprintf( f, "SECRETS_DIR=%s\n", config->secretsDir );

  if( NOTEMPTY( config->sessionCookieName )
      && strcmp( config->sessionCookieName, DEFAULT_ID_OF_AUTH_COOKIE )!=0 )
    fprintf( f, "SESSION_COOKIE_NAME=%s\n", config->sessionCookieName );

  if( NOTEMPTY( config->urlCookie )
      && strcmp( config->urlCookie, DEFAULT_URL_COOKIE )!=0 )
    fprintf( f, "URL_COOKIE=%s\n", config->urlCookie );

  if( NOTEMPTY( config->htmlFolder )
      && strcmp( config->htmlFolder, DEFAULT_HTML_FOLDER )!=0 )
    fprintf( f, "HTML_FOLDER=%s\n", config->htmlFolder );

  if( NOTEMPTY( config->idMapFile )
      && strcmp( config->idMapFile, DEFAULT_ID_MAP_FILE )!=0 )
    fprintf( f, "ID_MAP_FILE=%s\n", config->idMapFile );

  for( _URL* url = config->urls; url!=NULL; url=url->next )
    PrintURL( f, url );

  for( _OAUTH_PROVIDER* p=config->oauthProviders; p!=NULL; p=p->next )
    {
    PrintOAuthProvider( f, p );
    }
  }

void ReadConfig( _CONFIG* config, char* filePath )
  {
  char folder[BUFLEN];
  folder[0] = 0;
  (void)GetFolderFromPath( filePath, folder, sizeof( folder )-1 );

  // Notice( "Config is being read from folder [%s]", folder );

  if( EMPTY( folder ) )
    config->configFolder = NULL;
  else
    config->configFolder = strdup( folder );

  if( EMPTY( filePath ) )
    {
    Error( "Cannot read configuration file with empty/NULL name");
    }

  FILE* f = fopen( filePath, "r" );
  if( f==NULL )
    {
    Error( "Failed to open configuration file %s", filePath );
    }

  config->parserLocation = NewTagValue( filePath, "", config->parserLocation, 0 );
  config->parserLocation->iValue = 0;
  UpdateGlobalParsingLocation( config );
  ++ ( config->currentlyParsing );

  /* this is wrong if we have #include's
  SetDefaults( config );
  */

  char buf[BUFLEN];
  char* endOfBuf = buf + sizeof(buf)-1;
  while( fgets(buf, sizeof(buf)-1, f )==buf )
    {
    ++(config->parserLocation->iValue);
    UpdateGlobalParsingLocation( config );

    char* ptr = TrimHead( buf );
    TrimTail( ptr );

    while( *(ptr + strlen(ptr) - 1)=='\\' )
      {
      char* startingPoint = ptr + strlen(ptr) - 1;
      if( fgets(startingPoint, endOfBuf-startingPoint-1, f )!=startingPoint )
        {
        ++(config->parserLocation->iValue);
        UpdateGlobalParsingLocation( config );
        break;
        }
      ++config->parserLocation->iValue;
      UpdateGlobalParsingLocation( config );
      TrimTail( startingPoint );
      }

    if( *ptr==0 )
      {
      continue;
      }

    if( *ptr=='#' )
      {
      ++ptr;
      if( strncmp( ptr, "include", 7 )==0 )
        { /* #include */
        ptr += 7;
        while( *ptr!=0 && ( *ptr==' ' || *ptr=='\t' ) )
          {
          ++ptr;
          }
        if( *ptr!='"' )
          {
          Error("#include must be followed by a filename in \" marks.");
          }
        ++ptr;
        char* includeFileName = ptr;
        while( *ptr!=0 && *ptr!='"' )
          {
          ++ptr;
          }
        if( *ptr=='"' )
          {
          *ptr = 0;
          }
        else
          {
          Error("#include must be followed by a filename in \" marks.");
          }

        int redundantInclude = 0;
        for( _TAG_VALUE* i=config->includes; i!=NULL; i=i->next )
          {
          if( NOTEMPTY( i->tag ) && strcmp( i->tag, includeFileName )==0 )
            {
            redundantInclude = 1;
            break;
            }
          }

        if( redundantInclude==0 )
          {
          config->includes = NewTagValue( includeFileName, "included", config->includes, 1 );

          if( config->listIncludes )
            {
            if( config->includeCounter )
              {
              fputs( " ", stdout );
              }
            fputs( includeFileName, stdout );
            ++config->includeCounter;
            }

          char* confPath = SanitizeFilename( CONFIGDIR, NULL, includeFileName, 0 );
          if( FileExists( confPath )==0 )
            {
            ReadConfig( config, confPath );
            }
          else
            {
            confPath = SanitizeFilename( folder, NULL, includeFileName, 0 );
            if( FileExists( confPath )==0 )
              {
              ReadConfig( config, confPath );
              }
            else
              {
              Warning( "Cannot open #include \"%s\" -- skipping.",
                       confPath );
              }
            FreeIfAllocated( &confPath );
            }
          FreeIfAllocated( &confPath );
          }
        }
      else if( strncmp( ptr, "print", 5 )==0 )
        { /* #print */
        ptr += 5;
        while( *ptr!=0 && ( *ptr==' ' || *ptr=='\t' ) )
          {
          ++ptr;
          }
        if( *ptr!='"' )
          {
          Error("#include must be followed by a filename in \" marks.");
          }
        ++ptr;
        char* printFileName = ptr;
        while( *ptr!=0 && *ptr!='"' )
          {
          ++ptr;
          }
        if( *ptr=='"' )
          {
          *ptr = 0;
          }
        else
          {
          Error("#print must be followed by a filename in \" marks.");
          }

        FILE* printFile = fopen( printFileName, "w" );
        if( printFile==NULL )
          {
          Error( "Could not open/create %s to print configuration.",
                 printFileName );
          }
        PrintConfig( printFile, config );
        fclose( printFile );
        Notice( "Printed configuration to %s.", printFileName );
        }
      else if( strncmp( ptr, "exit", 4 )==0 )
        { /* #exit */
        ptr += 4;
        ValidateConfig( config );
        Notice( "Exit program due to command in config file." );
        exit(0);
        }

      /* not #include or #include completely read by now */
      continue;
      }

    /* printf("Processing [%s]\n", ptr ); */
    char* equalsChar = NULL;
    for( char* eolc = ptr; *eolc!=0; ++eolc )
      {
      if( equalsChar==NULL && *eolc == '=' )
        {
        equalsChar = eolc;
        }

      if( *eolc == '\r' || *eolc == '\n' )
        {
        *eolc = 0;
        break;
        }
      }

    if( *ptr!=0 && equalsChar!=NULL && equalsChar>ptr )
      {
      ProcessConfigLine( ptr, equalsChar, config );
      }
    }

  /* unroll the stack of config filenames after ReadConfig ended */
  _TAG_VALUE* tmp = config->parserLocation->next;
  if( config->parserLocation->tag!=NULL ) { FREE( config->parserLocation->tag ); }
  if( config->parserLocation->value!=NULL ) { FREE( config->parserLocation->value ); }
  FREE( config->parserLocation );
  config->parserLocation = tmp;
  UpdateGlobalParsingLocation( config );
  -- ( config->currentlyParsing );

  fclose( f );

  /*
  This is wrong if we have #include's !
  FreeTagValue( config->list );
  config->list = NULL;
  */
  }

void ValidateConfig( _CONFIG* config )
  {
  if( config==NULL )
    Error( "Cannot validate a NULL configuration" );

  if( config->urls==NULL )
    Error( "At least one URL must be specified" );

  if( EMPTY( config->myCSS ) )
    Error( "MY_CSS must be set (or left as default) in config" );

  if( EMPTY( config->remoteAddrEnvVar ) )
    Error( "REMOTE_ADDR_VAR must be set (or left as default) in config" );

  if( EMPTY( config->userAgentEnvVar ) )
    Error( "USER_AGENT_VAR must be set (or left as default) in config" );

  for( _URL* url=config->urls; url!=NULL; url=url->next )
    ValidateURL( url );

  if( config->htPasswdFile==NULL )
    { /* special case - okay */
    }
  else
    {
    if( EMPTY( config->htPasswdFile ) )
      Error( "HTPASSWD must be specified" );
    }

  if( NOTEMPTY( config->htPasswdFile ) )
    {
    if( FileExists( config->htPasswdFile )!=0 )
      Error( "HTPASSWD must point to an accessible file" );

    FILE* f = fopen( config->htPasswdFile, "r" );
    if( f==NULL )
      Error( "HTPASSWD cannot be opened" );
    else
    fclose( f );
    }

  if( EMPTY( config->lockFile ) )
    Error( "LOCK must be specified" );

  if( EMPTY( config->htmlFolder ) )
    Error( "HTML_FOLDER must be specified" );

  if( EMPTY( config->idMapFile ) )
    Warning( "No ID_MAP_FILE specified - will take OAuth IDs literally" );
  else
    {
    if( FileExists( config->idMapFile )!=0 )
      Error( "No ID_MAP_FILE [%s] cannot be opened", config->idMapFile );
    }

  if( DirExists( config->htmlFolder )!=0 )
    Error( "Folder %s cannot be opened", config->htmlFolder );

  if( EMPTY( config->secretsDir ) )
    Error( "SECRETS_DIR must be specified" );

  if( DirExists( config->secretsDir )!=0 )
    Error( "Folder %s cannot be opened", config->secretsDir );

  for( _OAUTH_PROVIDER* p=config->oauthProviders; p!=NULL; p=p->next )
    {
    ValidateOAuthProvider( p );
    }
  }

