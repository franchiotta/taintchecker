//
//  ### TaintChecker ###
//
//  The source methods don't just taint the argument provided if said in the
//  configuration file. But also if invoked over a struct/class object will
//  try to mark as tainted member or global variables used inside the call.
//
//  compoundSource is configured as it doesn't take any arguments to taint. But
//  the checker realizes we are doing an assignment over a member variable.
//

#include "Util.h"

struct Foo {
private:
  char* data;
  
public:
  Foo (){};
  void compoundSource(char* data){
    this->data = data;
  }
  char* getData(){
    return data;
  }
};

void compoundExample(char* data){
  Foo foo = Foo();
  foo.compoundSource(data);
  sink(foo.getData());
}
