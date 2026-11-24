// Linux stand-ins for ZSign/Utils.mm (Objective-C++, iOS-only): log sink and documents dir.
#include <stdio.h>
extern "C" const char *getDocumentsDirectory() { return "/tmp"; }
extern "C" void writeToNSLog(const char *msg) { (void)msg; }
