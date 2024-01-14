#include "base.h"

char* NormalizeEmail( char* raw )
  {
  if( EMPTY( raw ) )
    return raw;
  char* at = strchr( raw, '@' );
  if( at==NULL )
    {
    Warning( "Cannot normalize e-mail address [%s] - no @ sign", raw );
    return raw;
    }

  char newMail[BUFLEN];
  char* src = NULL;
  char* dst = NULL;
  char* end = newMail + sizeof(newMail)-5;

  for( src=raw, dst=newMail; src<at && dst<end; ++src )
    {
    if( *src=='.' || *src=='_' )
      continue;
    *(dst++) = *src;
    }

  *dst = 0;
  strncpy( dst, at, end-dst );

  for( src=newMail; *src!=0; ++src )
    if( isupper( *src ) )
      *src = tolower( *src );

  return strdup( newMail );
  }

char* MapIdFromFile( char* providerId, char* providerEmail, char* fileName )
  {
  if( EMPTY( providerId ) )
    {
    Warning( "MapIdFromFile() - What provider did this ID come from? No mapping permitted." );
    return NULL;
    }

  if( EMPTY( providerEmail ) )
    {
    Warning( "MapIdFromFile() - You have to map an actual e-mail, not a blank." );
    return NULL;
    }

  if( EMPTY( fileName ) )
    {
    Warning( "MapIdFromFile() - No map file provided." );
    return NULL;
    }

  FILE* f = fopen( fileName, "r" );
  if( f==NULL )
    {
    Warning( "MapIdFromFile() - Cannot open ID map file [%s]", fileName );
    return NULL;
    }

  char line[BUFLEN];
  while( fgets( line, sizeof(line)-1, f )==line )
    {
    TrimTail( line );
    if( *line==0 )
      continue;
    if( *line=='#' )  /* comment */
      continue;

    char* p = NULL;
    char* e = NULL;
    char* i = NULL;
    char* ptr = NULL;
    for( char* segment = strtok_r( line, " \r\n\t", &ptr );
         segment!=NULL;
         segment = strtok_r( NULL, " \r\n\t", &ptr ) )
      {
      char* q = strchr( segment, '=' );
      if( q==NULL )
        continue;
      *q = 0;
      char* varName = TrimHead( segment );
      if( NOTEMPTY( varName ) )
        TrimTail( varName );
      char* varValue = TrimHead( q+1 );
      if( NOTEMPTY( varValue ) )
        TrimTail( varValue );

      if( EMPTY( varName ) || EMPTY( varValue ) )
        continue;

      if( strcasecmp( varName, "provider" )==0 )
        p = varValue;
      else if( strcasecmp( varName, "email" )==0 )
        e = varValue;
      else if( strcasecmp( varName, "id" )==0 )
        i = varValue;
      }

    if( EMPTY( p ) || EMPTY( e ) || EMPTY( i ) )
      continue;

    if( ( strcmp( p, "*" )==0 || strcasecmp( p, providerId )==0 ) )
      {
      char* ne = NormalizeEmail( e );
      char* np = NormalizeEmail( providerEmail );
      if( strcasecmp( ne, np )==0 )
        {
        free( ne );
        free( np );
        fclose( f );
        return strdup( i );
        }

      free( np );
      free( ne );
      }
    }

  fclose( f );

  return NULL;
  }
