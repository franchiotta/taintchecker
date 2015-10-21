What is this project about?
---------------------------

CustomTaintChecker is a clang static checker that carries out tainting analysis. This repository contains the necessary source code to build a dynamic library which can be loaded into scan-build for this purpose. Originally, it was developed as an extension of GenericTaintChecker, which is distributed with clang static analyzer.

scan-build, which is installed along with LLVM/clang infraestructure, is a command line utility that enables a user to run the static analyzer over their codebase as part of performing a regular build (from the command line).

Here is the general format for invoking scan-build:

$ scan-build [scan-build options] <command> [command options]

There is a specific option that can be used to load a checker compiled as a dynamic library. You can use --load-plugin as follows:

$ scan-build **--load-plugin** */path/to/checker* <command> [command options]

For further information about scan-build, please go to http://clang-analyzer.llvm.org/scan-build.html

Taint Checking
--------------

The concept behind taint checking is that any variable that can be modified by an outside user poses a potential security risk. If that variable is used in an expression that sets a second variable, that second variable is now also suspicious. The taint checking tool proceeds variable by variable until it has a complete list of all variables which are potentially influenced by outside input. If any of these variables is used to execute dangerous commands, the taint checker warns that the program is using a potentially dangerous tainted variable.

In order to run this analysis, we should consider the following concepts:
- Source, a method that is source of (o generate) tainting.
- Propagator, a method that propagates the tainting from one variable to another.
- Sink, a method that is dangerous, and tainted data should be avoided when passig parameters.
- Filter, a method that cleans a tainted data (this variable is not considered tainted anymore).


Our checker has a list of pre-defined sources and sink, which are used by default. But it also allows the user to define custom sources, propagators, destination and filter methods. This specification is written in a XML file, and passed on the checker when executing scan-build.


Installation
------------

In order to build the checker as a library, we will need to follow these steps.

1. Install **libxml2** library if not already installed.
2. git clone *https://github.com/franchiotta/taintchecker.git*
3. create a build directory, and go there.
4. run cmake */directory/to/taintchecker/repository* -DLLVM_PATH=*/path/to/llvm/build*. You need to provide the **LLVM_PATH** argument, which is the path to the build LLVM directory.
5. make

And that's it. The dynamic library will be placed in lib folder.

Additional note: as libxml2 is a prerequisite, cmake will not build the library unless it detectes a libxml2 installation. In order to check that, cmake will use the xml2-config command utility installed along with the library. So make sure to have it included in the path environment variable.
You will need to have installed the libxml2 library (shared) as well as the development headers (if you use a package manager, they usually come in different packages, e.g. libxml2 and libxml2-dev packages).


Usage
-----

The library has to be provided to scan-build, so does the XML configuration file.

$ scan-build **--load-plugin** */path/to/checker* **-enable-checker** *alpha.security.taint.CustomTaintPropagation* **-analyzer-config alpha.security.taint.CustomTaintPropagation:ConfigurationFile**=*/path/to/conf/file* <command> [command options]

We also should enable the checker we want to run (using *-enable-checker*), otherwise scan-build will just run some pre-defined checkers.

We may want to add an additional option to dump some debug information, just for debugging purposes.

**alpha.security.taint.CustomTaintPropagation:DebugFile**=*/path/to/debug/file*

Putting everything together:

$ scan-build --load-plugin */path/to/checker* -enable-checker alpha.security.taint.CustomTaintPropagation -analyzer-config alpha.security.taint.CustomTaintPropagation:ConfigurationFile=*/path/to/debug/file* -analyzer-config alpha.security.taint.CustomTaintPropagation:DebugFile=*/path/to/conf/file* <command> [command options]

How to configure the checker
----------------------------

The root label of the xml configuration file is <TaintChecker>, then inside it we can provide four more:

- TaintSources
  Include a list of TaintSource elements, which are source methods.

```xml
  <TaintChecker>
    <TaintSources>
  	  <TaintSource>
  	    <method>foo</method>
  	    <params>
  	      <value>0</value>
  	    </params>
  	  </TaintSource>
  	  ...
    </TaintSources>
  </TaintChecker>
```
  Define method 'foo' as a source, and it will taint whatever is passed as a fist argument.

- PropagationsRules
  Include a list of PropagationsRules elements, which are rules for propagation.

```xml
  <TaintChecker>
    <PropagationRules>
      <PropagationRule>
        <method>bar</method>
        <sources>
          <value>0</value>
        </sources>
        <destinations>
          <value>1</value>
        </destinations>
      </PropagationRule>
      ...
    </PropagationRules>
  </TaintChecker>
```
  Define 'bar' as a propagator, and if any of the arguments listed in sources are tainted, mark all argument of destinations as such.

- TaintDestinations
  Include a list of TaintDestination elements, which are sink methods.

```xml
  <TaintChecker>
    <TaintDestinations>
      <TaintDestination>
        <method>baz</method>
        <params>
          <value>1</value>
          <value>2</value>
        </params>
      </TaintDestination>
      ...
    </TaintDestinations>
  </TaintChecker>
```
  Define 'baz' as a sink, which if tainted data is provided at the second or third argument, the checker will generate an alert.

- TaintFilters
  Include a list of TaintFilter elements, which are filter methods.

```xml
  <TaintChecker>
    <TaintFilters>
      <TaintFilter>
        <method>qux</method>
        <params>
          <value>0</value>
        </params>
      </TaintFilter>
      ...
    </TaintFilters>
  </TaintChecker>
```
  Define 'qux' as a filter, any tainted data passed on at the first argument will be cleaned.