#include "base.h"

void BasicPage( _CONFIG* conf )
  {
  char* user = ExtractUserIDOrDieEx( cm_ui,
                                     conf->userEnvVar,
                                     conf->remoteAddrEnvVar,
                                     conf->userAgentEnvVar,
                                     MyCookieId( conf ),
                                     conf->urlEnvVar,
                                     conf->authServiceUrl,
                                     conf->key,
                                     conf->myCSS );

  Notice( "ExtractUserIDOrDieEx() returned %s", NULLPROTECT( user ) );

  printf( "Content-Type: text/html\r\n\r\n" );
  printf( "<html>\n" );
  printf( "  <head>\n" );
  printf( "    <title>Test-CGI</title>\n" );
  printf( "    <link rel=\"stylesheet\" href=\"%s\"/>\n", conf->myCSS );
  printf( "  </head>\n" );
  printf( "  <body>\n" );
  printf( "    <h1>Test-CGI</h1>\n" );
  printf( "    <p>Your user ID is '%s'</p>\n", user );
  printf( "    <a href=\"/cgi-bin/auth2cookie?LOGOUT\">Logout</a></p>\n" );
  printf( "  </body>\n" );
  printf( "</html>\n" );
  printf( "\n" );
  }

int main( int argc, char** argv )
  {
  inCGI = 2;
  logFileHandle = fopen( "/var/log/auth2cookie/test-cgi.log", "a" );

  char* confPath = MakeFullPath( CONFIGDIR, CONFIGFILE );
  _CONFIG* conf = (_CONFIG*)calloc( 1, sizeof( _CONFIG ) );
  if( conf==NULL ) Error( "Cannot allocate CONFIG object" );

  SetDefaults( conf );
  ReadConfig( conf, confPath );
  ValidateConfig( conf );

  Notice( "Config read from %s", confPath );

  BasicPage( conf );

  return 0;
  }
