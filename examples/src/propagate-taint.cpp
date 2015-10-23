//
//  ### TaintChecker ###
//
//  Example that shows how the tainting propagation works.
//  In this case, objA variable taints objB one.
//

#include <stdio.h>
#include "Util.h"

void propagateTaint() {
  char* objA = source();
  char* objB = (char*)malloc(sizeof(char));;
  propagator(objA,objB);
  filter(objA);
  sink(objB);
}


void propagateTaint_2(bool shouldPropagate) {
  char* objA = source();
  char* objB = NULL;
  if (objA != NULL && shouldPropagate){
    objB = propagator2(objA);
  }
  else {
    filter(objA);
  }
  if (shouldPropagate)
    sink(objB);
  sink(objA);
}