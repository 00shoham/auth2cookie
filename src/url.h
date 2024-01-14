#ifndef _URL_INCLUDE
#define _URL_INCLUDE

typedef struct _url
  {
  char* name;
  char* location;
  char* sessionCookieName;
  int timeout;
  _TAG_VALUE* users;
  struct _url* next;
  } _URL;

char* MyCookieId( _CONFIG* conf );
char* RefererCookieId( _CONFIG* conf );

_URL* NewURL( char* name, char* sessionCookieName, _URL* list );
void FreeURLList( _URL* l );
_URL* FindURLByName( _URL* list, char* name );
_URL* FindURLByLocation( _URL* list, char* location );
void ValidateURL( _URL* url );
void PrintURL( FILE* f, _URL* url );
int UserIsValidForURL( _URL* url, char* user );

#endif
