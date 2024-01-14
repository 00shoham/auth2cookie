#include "base.h"

char* MyCookieId( _CONFIG* conf )
  {
  char* location = MyRelativeRequestURL( conf->urlEnvVar );
  if( EMPTY( location ) )
    {
    Warning( "MyCookieId() - Cannot discern my own URL - default cookie" );
    return conf->sessionCookieName;
    }

  _URL* url = FindURLByLocation( conf->urls, location );
  if( url==NULL )
    {
    Warning( "MyCookieId() - No matching URL for [%s] - default cookie", location );
    return conf->sessionCookieName;
    }

  return url->sessionCookieName;
  }

char* RefererCookieId( _CONFIG* conf )
  {
  char* location = getenv( conf->httpRefererEnvVar );
  if( EMPTY( location ) )
    {
    Warning( "RefererCookieId() - Cannot discern referer URL - default cookie" );
    return conf->sessionCookieName;
    }

  _URL* url = FindURLByLocation( conf->urls, location );
  if( url==NULL )
    {
    Warning( "RefererCookieId() - No matching URL for [%s] - default cookie", location );
    return conf->sessionCookieName;
    }

  return url->sessionCookieName;
  }

_URL* NewURL( char* name, char* sessionCookieName, _URL* list )
  {
  if( EMPTY( name ) )
    Error( "Cannot allocate a URL with no name" );

  _URL* u = (_URL*)SafeCalloc( 1, sizeof(_URL), "URL" );
  u->name = strdup( name );
  u->timeout = DEFAULT_SESSION_TIMEOUT;
  if( EMPTY( sessionCookieName ) )
    u->sessionCookieName = strdup( DEFAULT_ID_OF_AUTH_COOKIE );
  else
    u->sessionCookieName = strdup( sessionCookieName );
  u->next = list;
  return u;
  }

void FreeURLList( _URL* url )
  {
  if( url->next )
    {
    FreeURLList( url->next );
    url->next = NULL;
    }

  FreeIfAllocated( &(url->name) );
  FreeIfAllocated( &(url->location) );
  FreeIfAllocated( &(url->sessionCookieName) );
  FreeTagValue( url->users );
  free( url );
  }

_URL* FindURLByName( _URL* list, char* name )
  {
  if( EMPTY( name ) )
    return NULL;
  if( list==NULL )
    return NULL;

  for( _URL* u=list; u!=NULL; u=u->next )
    if( NOTEMPTY( u->name )
        && strcasecmp( u->name, name )==0 )
      return u;

  return NULL;
  }

_URL* FindURLByLocation( _URL* list, char* location )
  {
  if( EMPTY( location ) )
    return NULL;
  if( list==NULL )
    return NULL;

  for( _URL* u=list; u!=NULL; u=u->next )
    {
    /* Notice( "Does location [%s] match pattern [%s]?", location, NULLPROTECT( u->location ) ); */
    if( NOTEMPTY( u->location )
        && CompareTwoUrls( u->location, location )==0 ) /* pattern, example */
      return u;
    }

  return NULL;
  }

void ValidateURL( _URL* url )
  {
  if( url==NULL )
    Error( "Cannot validate a NULL url" );

  if( EMPTY( url->name ) )
    Error( "Invalid URL - no name" );

  if( EMPTY( url->location ) )
    Error( "URL %s has no location", url->name );

  if( EMPTY( url->sessionCookieName ) )
    Error( "URL %s has no authentication cookie name", url->name );

  if( url->users==NULL )
    Error( "URL %s has no users", url->name );

  for( _TAG_VALUE* u=url->users; u!=NULL; u=u->next )
    if( EMPTY( u->value ) )
      Error( "URL %s has a NULL user", url->name );

  if( url->timeout < MINIMUM_SESSION_TIMEOUT )
    Error( "URL %s session timeout shorter than %d second minimum",
           url->name, MINIMUM_SESSION_TIMEOUT );
  }

void PrintURL( FILE* f, _URL* url )
  {
  if( f==NULL )
    return;
  if( url==NULL )
    return;
  if( EMPTY( url->name ) || EMPTY( url->location ) )
    return;

  fprintf( f, "\n" );
  fprintf( f, "URL=%s\n", url->name );
  fprintf( f, "LOCATION=%s\n", url->location );
  if( url->timeout != DEFAULT_SESSION_TIMEOUT )
    fprintf( f, "TIMEOUT=%d\n", url->timeout );
  if( NOTEMPTY( url->sessionCookieName ) && strcasecmp( url->sessionCookieName, DEFAULT_ID_OF_AUTH_COOKIE )!=0 )
    fprintf( f, "SESSION_COOKIE_NAME=%s\n", url->sessionCookieName );
  for( _TAG_VALUE* u=url->users; u!=NULL; u=u->next )
    if( EMPTY( u->value ) )
      Warning( "URL %s has a NULL user", url->name );
    else
      fprintf( f, "USER=%s\n", u->value );
  }

int UserIsValidForURL( _URL* url, char* user )
  {
  if( url==NULL )
    return -1;
  if( EMPTY( user ) )
    return -2;

  for( _TAG_VALUE* u=url->users; u!=NULL; u=u->next )
    {
    char* uid = u->value;
    if( EMPTY( uid ) )
      continue;
    if( strchr( uid, '*' )!=NULL
        && StringMatchesRegex( uid, user )==0 )
      return 0;
    if( strcasecmp( uid, user )==0 )
      return 0;
    }

  return -3;
  }
