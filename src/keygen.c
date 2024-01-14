#include "base.h"

int main()
  {
  uint8_t key[AES_KEYLEN];

  srand(time(NULL));
  for( int i=0; i<32; ++i )
    key[i] = rand() % 256;

  printf( "char defaultKEK[] =\n" );
  printf( "  {" );
  for( int i=0; i<32; ++i )
    {
    if( i%8==0 )
      printf( "\n  " );
    printf( "0x%02x", key[i] );
    if( i+1<32 )
      printf( ", " );
    }
  printf( "\n  };\n" );

  char key_ascii[100];
  EscapeString( key, AES_KEYLEN, key_ascii, sizeof( key_ascii ) );
  printf( "/* as an escaped-string:\n" );
  printf( "   \"%s\"\n", key_ascii );
  printf( " */\n" );

  return 0;
  }
