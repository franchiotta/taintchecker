//
//  ### TaintChecker ###
//
//  Example that shows the analyzer also works when macros are used, since
//  it takes a translation unit as an input (source code after all #include and
//  #define statement have been processed).
//
//  Note: sink(..) as well as sink1(..) is marked as a destination method in
//  the configuration file. So tainted data provided to them should end up in an
//  alert to the user. Whereas, sink2 is not marked in the configuration file,
//  so there will be no alert for it instead.
//
//

#include <stdlib.h>
#include "Util.h"

#define parametrizedSink(num,param)  sink##num(param)
#define normalSink(param)            sink(param)

int method(bool executeSink, int sinkPreffix){
  doSomething();
  char *c = source();
  doSomething();
  if (executeSink){
    if (sinkPreffix <= 0){
      normalSink(c);
    }
    if (sinkPreffix == 1){
      parametrizedSink(1, c);
    }
    if (sinkPreffix == 2){
      parametrizedSink(2, c);
    }
  }
  free(c);
  return 0;
}