//===-- llvm/Instruction.h - Instruction class definition -------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
///
/// \file
/// Implementation of TaintParser class.
///
//===----------------------------------------------------------------------===//

#include "includes/TaintParser.h"
using namespace llvm;

namespace taintutil {

// ----------------------------- //
//     Parser implementation     //
// ----------------------------- //

TaintParser::TaintParser(std::string XMLfilename, std::string XSDfilename) {
  this->XMLfilename = XMLfilename;
  this->XSDfilename = XSDfilename;
  this->sourceMap =
      SmallVector<std::pair<std::string, SmallVector<int, SIZE_ARGS>>,
                  SIZE_METHODS>();
  this->propagationRuleMap = PROPAGATION_MAP();
  this->destinationMap = DESTINATION_MAP();
  this->filterMap = FILTER_MAP();
}
TaintParser::~TaintParser() {}

short TaintParser::process() {
  xmlDocPtr doc;

  // Load XML document
  doc = xmlParseFile(this->XMLfilename.data());
  if (doc == NULL) {
    return Errors::GeneralError;
  }

  if (!validateXMLAgaintSchema(doc))
    return Errors::ValidationError;

  // Init libxml
  xmlInitParser();
  LIBXML_TEST_VERSION

  // Do the main job
  if (!executeXpathExpression(doc,
                              BAD_CAST "/TaintChecker/TaintSources/TaintSource",
                              &TaintParser::parseSources))
    return Errors::GeneralError;

  if (!executeXpathExpression(doc, BAD_CAST
                              "/TaintChecker/PropagationRules/PropagationRule",
                              &TaintParser::parsePropagationRules))
    return Errors::GeneralError;

  if (!executeXpathExpression(
          doc, BAD_CAST "/TaintChecker/TaintDestinations/TaintDestination",
          &TaintParser::parseDestinations))
    return Errors::GeneralError;

  if (!executeXpathExpression(doc,
                              BAD_CAST "/TaintChecker/TaintFilters/TaintFilter",
                              &TaintParser::parseFilters))
    return Errors::GeneralError;

  // Cleanup
  xmlCleanupParser();
  xmlFreeDoc(doc);
  return 0;
}

bool TaintParser::executeXpathExpression(xmlDocPtr doc,
                                         const xmlChar *xpathExpr,
                                         ResultManager ResultManagerFunction) {
  xmlXPathContextPtr xpathCtx;
  xmlXPathObjectPtr xpathObj;

  assert(doc);
  assert(xpathExpr);

  // Create xpath evaluation context.
  xpathCtx = xmlXPathNewContext(doc);
  if (xpathCtx == NULL) {
    // debug("Error: unable to create new XPath context\n");
    xmlFreeDoc(doc);
    return false;
  }

  // Evaluate xpath expression.
  xpathObj = xmlXPathEvalExpression(xpathExpr, xpathCtx);
  if (xpathObj == NULL) {
    // debug("Error: unable to evaluate xpath expression << xpathExpr \n");
    xmlXPathFreeContext(xpathCtx);
    xmlFreeDoc(doc);
    return false;
  }

  (this->*ResultManagerFunction)(xpathObj->nodesetval);

  /* Cleanup */
  xmlXPathFreeObject(xpathObj);
  xmlXPathFreeContext(xpathCtx);
  return true;
}

void TaintParser::parseSources(xmlNodeSetPtr nodes) {
  xmlNodePtr cur;
  int size;

  size = (nodes) ? nodes->nodeNr : 0;
  for (int i = 0; i < size; ++i) {
    assert(nodes->nodeTab[i]);

    if (nodes->nodeTab[i]->type == XML_ELEMENT_NODE) {
      cur = nodes->nodeTab[i];
      std::string generateMethod;
      SmallVector<int, SIZE_ARGS> generateArgs;

      xmlNodePtr node = cur->children;
      while (node != cur->last) {
        if (xmlStrEqual(node->name, xmlCharStrdup("method"))) {
          generateMethod =
              std::string(reinterpret_cast<char *>(node->children->content));
        }
        if (xmlStrEqual(node->name, xmlCharStrdup("params"))) {
          generateArgs = SmallVector<int, SIZE_ARGS>();
          xmlNodePtr paramsNodes = node->children;
          while (paramsNodes != node->last) {
            if (xmlStrEqual(paramsNodes->name, xmlCharStrdup("value"))) {
              generateArgs.push_back(std::stoi(
                  reinterpret_cast<char *>(paramsNodes->children->content)));
            }
            paramsNodes = paramsNodes->next;
          }
        }
        node = node->next;
      }
      sourceMap.push_back(std::pair<std::string, SmallVector<int, SIZE_ARGS>>(
          generateMethod, generateArgs));
    } else {
      cur = nodes->nodeTab[i];
    }
  }
}

void TaintParser::parsePropagationRules(xmlNodeSetPtr nodes) {
  xmlNodePtr cur;
  int size;

  size = (nodes) ? nodes->nodeNr : 0;
  for (int i = 0; i < size; ++i) {
    assert(nodes->nodeTab[i]);

    if (nodes->nodeTab[i]->type == XML_ELEMENT_NODE) {
      cur = nodes->nodeTab[i];
      std::string propagateMethod;
      PropagationRule pr = PropagationRule();

      xmlNodePtr node = cur->children;
      while (node != cur->last) {
        if (xmlStrEqual(node->name, xmlCharStrdup("method"))) {
          propagateMethod =
              std::string(reinterpret_cast<char *>(node->children->content));
        }
        if (xmlStrEqual(node->name, xmlCharStrdup("sources"))) {
          xmlNodePtr paramsNodes = node->children;
          while (paramsNodes != node->last) {
            if (xmlStrEqual(paramsNodes->name, xmlCharStrdup("value"))) {
              pr.addSrcArg(std::stoi(
                  reinterpret_cast<char *>(paramsNodes->children->content)));
            }
            paramsNodes = paramsNodes->next;
          }
        }
        if (xmlStrEqual(node->name, xmlCharStrdup("destinations"))) {
          xmlNodePtr paramsNodes = node->children;
          while (paramsNodes != node->last) {
            if (xmlStrEqual(paramsNodes->name, xmlCharStrdup("value"))) {
              pr.addDstArg(std::stoi(
                  reinterpret_cast<char *>(paramsNodes->children->content)));
            }
            paramsNodes = paramsNodes->next;
          }
        }
        node = node->next;
      }
      propagationRuleMap.push_back(
          std::pair<std::string, PropagationRule>(propagateMethod, pr));
    } else {
      cur = nodes->nodeTab[i];
    }
  }
}

void TaintParser::parseDestinations(xmlNodeSetPtr nodes) {
  xmlNodePtr cur;
  int size;

  size = (nodes) ? nodes->nodeNr : 0;
  for (int i = 0; i < size; ++i) {
    assert(nodes->nodeTab[i]);

    if (nodes->nodeTab[i]->type == XML_ELEMENT_NODE) {
      cur = nodes->nodeTab[i];
      std::string destinationMethod;
      SmallVector<int, SIZE_ARGS> destinationArgs;

      xmlNodePtr node = cur->children;
      while (node != cur->last) {
        if (xmlStrEqual(node->name, xmlCharStrdup("method"))) {
          destinationMethod =
              std::string(reinterpret_cast<char *>(node->children->content));
        }
        if (xmlStrEqual(node->name, xmlCharStrdup("params"))) {
          destinationArgs = SmallVector<int, SIZE_ARGS>();
          xmlNodePtr paramsNodes = node->children;
          while (paramsNodes != node->last) {
            if (xmlStrEqual(paramsNodes->name, xmlCharStrdup("value"))) {
              destinationArgs.push_back(std::stoi(
                  reinterpret_cast<char *>(paramsNodes->children->content)));
            }
            paramsNodes = paramsNodes->next;
          }
        }
        node = node->next;
      }
      destinationMap.push_back(
          std::pair<std::string, SmallVector<int, SIZE_ARGS>>(destinationMethod,
                                                              destinationArgs));
    } else {
      cur = nodes->nodeTab[i];
    }
  }
}

void TaintParser::parseFilters(xmlNodeSetPtr nodes) {
  xmlNodePtr cur;
  int size;

  size = (nodes) ? nodes->nodeNr : 0;
  for (int i = 0; i < size; ++i) {
    assert(nodes->nodeTab[i]);

    if (nodes->nodeTab[i]->type == XML_ELEMENT_NODE) {
      cur = nodes->nodeTab[i];
      std::string filterMethod;
      SmallVector<int, SIZE_ARGS> filterArgs;

      xmlNodePtr node = cur->children;
      while (node != cur->last) {
        if (xmlStrEqual(node->name, xmlCharStrdup("method"))) {
          filterMethod =
              std::string(reinterpret_cast<char *>(node->children->content));
        }
        if (xmlStrEqual(node->name, xmlCharStrdup("params"))) {
          xmlNodePtr paramsNodes = node->children;
          while (paramsNodes != node->last) {
            if (xmlStrEqual(paramsNodes->name, xmlCharStrdup("value"))) {
              filterArgs.push_back(std::stoi(
                  reinterpret_cast<char *>(paramsNodes->children->content)));
            }
            paramsNodes = paramsNodes->next;
          }
        }
        node = node->next;
      }
      filterMap.push_back(std::pair<std::string, SmallVector<int, SIZE_ARGS>>(
          filterMethod, filterArgs));
    } else {
      cur = nodes->nodeTab[i];
    }
  }
}

bool TaintParser::validateXMLAgaintSchema(xmlDocPtr doc) {
  xmlSchemaParserCtxtPtr ctxt;
  xmlSchemaPtr schema;
  xmlSchemaValidCtxtPtr validCtxt;

  assert(doc);

  ctxt = xmlSchemaNewParserCtxt(this->XSDfilename.data());

  if (ctxt != NULL) {
    schema = xmlSchemaParse(ctxt);
    xmlSchemaFreeParserCtxt(ctxt);

    validCtxt = xmlSchemaNewValidCtxt(schema);
    int ret = xmlSchemaValidateDoc(validCtxt, doc);

    if (ret == 0) {
      return true;
    } else {
      return false;
    }
  }
  return false;
}

SOURCE_MAP TaintParser::getSourceMap() { return sourceMap; }

TaintParser::PROPAGATION_MAP TaintParser::getPropagationRuleMap() {
  return propagationRuleMap;
}

DESTINATION_MAP TaintParser::getDestinationMap() { return destinationMap; }

FILTER_MAP TaintParser::getFilterMap() { return filterMap; }

std::string TaintParser::toString() {
  std::string str = "Paser {\n";
  str = str + "Sources :\n";
  for (SOURCE_MAP::const_iterator I = sourceMap.begin(), E = sourceMap.end();
       I != E; ++I) {
    std::pair<StringRef, SmallVector<int, SIZE_ARGS>> pair = *I;
    str = str + " - Name: " + pair.first.data() + "\n";
    for (SmallVector<int, SIZE_ARGS>::const_iterator J = pair.second.begin(),
                                                     Y = pair.second.end();
         J != Y; ++J) {
      int arg = *J;
      str = str + "   >> Arg " + std::to_string(arg) + "\n";
    }
  }

  str = str + "Propagation: \n";
  for (PROPAGATION_MAP::const_iterator I = propagationRuleMap.begin(),
                                       E = propagationRuleMap.end();
       I != E; ++I) {
    std::pair<std::string, PropagationRule> pair = *I;
    str = str + " - Name: " + pair.first.data() + "\n";
    str = str + "   - Sources\n";
    for (ArgVector::const_iterator J = pair.second.SrcArgs.begin(),
                                   Y = pair.second.SrcArgs.end();
         J != Y; ++J) {
      int arg = *J;
      str = str + "     >> Arg " + std::to_string(arg) + "\n";
    }
    str = str + "   - Destinations\n";
    for (ArgVector::const_iterator J = pair.second.DstArgs.begin(),
                                   Y = pair.second.DstArgs.end();
         J != Y; ++J) {
      int arg = *J;
      str = str + "     >> Arg " + std::to_string(arg) + "\n";
    }
  }

  str = str + "Destinations: \n";
  for (DESTINATION_MAP::const_iterator I = destinationMap.begin(),
                                       E = destinationMap.end();
       I != E; ++I) {
    std::pair<StringRef, SmallVector<int, SIZE_ARGS>> pair = *I;
    str = str + " - Name: " + pair.first.data() + "\n";
    for (SmallVector<int, SIZE_ARGS>::const_iterator J = pair.second.begin(),
                                                     Y = pair.second.end();
         J != Y; ++J) {
      int arg = *J;
      str = str + "   >> Arg " + std::to_string(arg) + "\n";
    }
  }

  str = str + "Filters:\n";
  for (FILTER_MAP::const_iterator I = filterMap.begin(), E = filterMap.end();
       I != E; ++I) {
    std::pair<StringRef, SmallVector<int, SIZE_ARGS>> pair = *I;
    str = str + " - Name: " + pair.first.data() + "\n";
    for (SmallVector<int, SIZE_ARGS>::const_iterator J = pair.second.begin(),
                                                     Y = pair.second.end();
         J != Y; ++J) {
      int arg = *J;
      str = str + "   >> Arg " + std::to_string(arg) + "\n";
    }
  }
  str = str + "}\n";
  return str;
}
}
