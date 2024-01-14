#ifndef _IDMAP_INCLUDE
#define _IDMAP_INCLUDE

typedef struct _idMap
  {
  char* providerId;
  char* providerEmail;
  char* localId;
  } _IDMAP;

char* NormalizeEmail( char* raw );
char* MapIdFromFile( char* providerId, char* providerEmail, char* fileName );

#endif
