//
//  ### TaintChecker ###
//
//  Filter methods clean the taint mark to the variables passed on as arguments.
//
//  In this example, the variable 'objA' goes through a source - propagator -
//  filter - sink flow, and it gets cleaned because of the filter stage.
//  Whereas, objB skips the filter stage, so the analyzer generates a warning.
//

#include <stdio.h>
#include "Util.h"

int filterTaint() {
  char* objA = source();
  char objB;
  propagator(objA, &objB);
  filter(objA);
  sink(objA);
  sink(objB);
  free(objA);
  return 0;
}
