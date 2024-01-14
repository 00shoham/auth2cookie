#include "base.h"

int main( int argc, char** argv )
  {
  inCGI = 2;

  logFileHandle = fopen( "/var/log/auth2cookie/oauth-request.log", "a" );

  char* confPath = MakeFullPath( CONFIGDIR, CONFIGFILE );
  _CONFIG* conf = (_CONFIG*)calloc( 1, sizeof( _CONFIG ) );
  if( conf==NULL ) Error( "Cannot allocate CONFIG object" );

  SetDefaults( conf );
  ReadConfig( conf, confPath );
  ValidateConfig( conf );

  printf( "Content-Type: text/html\r\n\r\n" );
  printf( "<html>\n" );
  printf( "  <head>\n" );
  printf( "    <title>OAuth Selector</title>\n" );
  printf( "    <link rel=\"stylesheet\" href=\"/%s\"/>\n", conf->myCSS );
  printf( "  </head>\n" );
  printf( "  <body>\n" );
  printf( "    <h1>OAuth Selector</h1>\n" );

  if( conf->oauthProviders == NULL )
    printf( "      <p><b>No OAuth providers defined in the configuration file!</b></p>\n" );
  else
    {
    for( _OAUTH_PROVIDER* p = conf->oauthProviders; p!=NULL; p=p->next )
      {
      printf( "      <p><b>%s</b></p>\n", p->name );

      char* secret = GenerateSecret( conf, p->name, NULL );
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

  return 0;
  }
