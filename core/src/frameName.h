/*
 * Copyright The async-profiler authors
 * Copyright 2026 movblock
 * SPDX-License-Identifier: Apache-2.0
 * Modified for Windows x86-64.
 */

#ifndef _FRAMENAME_H
#define _FRAMENAME_H

#include <jvmti.h>
#include <locale.h>
#include <map>
#include <vector>
#include <string>
#include "arguments.h"
#include "matcher.h"
#include "mutex.h"
#include "vmEntry.h"

#ifdef __APPLE__
#  include <xlocale.h>
#endif


typedef std::map<jmethodID, std::string> JMethodCache;
typedef std::map<int, std::string> ThreadMap;
typedef std::map<unsigned int, const char*> ClassMap;

class CallTrace;

class FrameName {
  private:
    static JMethodCache _cache;

    JNIEnv* _jni;
    ClassMap _class_names;
    std::vector<Matcher> _include;
    std::vector<Matcher> _exclude;
    std::string _str;
    int _style;
    unsigned char _cache_epoch;
    unsigned char _cache_max_age;
    Mutex& _thread_names_lock;
    ThreadMap& _thread_names;
#ifdef _WIN32
    std::string _saved_numeric_locale;
    int _saved_thread_locale_mode;
#else
    locale_t _saved_locale;
#endif

    const char* decodeNativeSymbol(const char* name);
    const char* typeSuffix(FrameTypeId type);
    void javaMethodName(jmethodID method);
    void javaClassName(const char* symbol, size_t length, int style);
    bool include(const char* frame_name);
    bool exclude(const char* frame_name);

  public:
    FrameName(Arguments& args, int style, int epoch, Mutex& thread_names_lock, ThreadMap& thread_names);
    ~FrameName();
#ifdef _WIN32
    static void forgetMethod(jmethodID method) { _cache.erase(method); }
#endif

    const char* name(ASGCT_CallFrame& frame, bool for_matching = false);
    FrameTypeId type(ASGCT_CallFrame& frame);

    bool excludeTrace(CallTrace* trace);
};

#endif // _FRAMENAME_H
