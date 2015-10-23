#ifndef __MyXcodeProj__Util__
#define __MyXcodeProj__Util__

#include <stdlib.h>

struct Bar {
  int var;
  char var_2;
  short var_3;
};


void doSomething();
char* anotherMethod();

// Source methods.
char* source();
void source(char*);
void source(char);
void source(Bar);

// Propagator methods.
void propagator(const char* source, char* destination);
char* propagator2(const char* source);

// Filter methods
void filter(const char* taintedVar);

// Sink methods.
void sink(char*);
void sink(char);
void sink(Bar);
void sink1(char*);
void sink2(char*);
#endif 
