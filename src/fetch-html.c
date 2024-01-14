#include "base.h"

int main( int argc, char** argv )
  {
  logFileHandle = fopen( "/var/log/auth2cookie/fetch-html.log", "a" );
  inCGI = 2;

  char* confPath = MakeFullPath( CONFIGDIR, CONFIGFILE );
  _CONFIG* conf = (_CONFIG*)calloc( 1, sizeof( _CONFIG ) );
  if( conf==NULL ) Error( "Cannot allocate CONFIG object" );

  SetDefaults( conf );
  ReadConfig( conf, confPath );
  ValidateConfig( conf );
  free( confPath );

  char* q = getenv( "QUERY_STRING" );
  if( EMPTY( q ) )
    Error( "You must specify a filename argument, such as index.html" );

  Notice( "Got query string %s", q );

  char* user = ExtractUserIDOrDieEx( cm_ui,
                                     conf->userEnvVar,
                                     conf->remoteAddrEnvVar,
                                     conf->userAgentEnvVar,
                                     MyCookieId( conf ),
                                     conf->urlEnvVar,
                                     conf->authServiceUrl,
                                     conf->key,
                                     conf->myCSS );

  if( EMPTY( user ) )
    Error( "Authentication failure" );

  Notice( "Authenticated user is %s", user );
  free( user );

  char* s = strdup( q );
  (void)TrimCharsFromTail( s, "/&=?" );

  if( strcmp( s, q )!=0 )
    Notice( "Stripped end chars from [%s] to fetch [%s]", q, s );

  char* path = MakeFullPath( conf->htmlFolder, s );
  if( FileExists( path ) != 0 )
    Error( "Cannot open %s", q );

  free( s );

  Notice( "We will try to fetch %s", path );

  printf( "Content-Type: text/html\r\n\r\n" );

  FILE* f = fopen( path, "r" );
  free( path );
  if( f==NULL )
    Error( "Failed to open %s in HTML_FOLDER", q );

  FileCopyHandles( f, stdout );

  Notice( "Sent document over", path );

  fclose( f );
  FreeConfig( conf );

  return 0;
  }
