/*
 * windivert_static.h - Shim for compiling WinDivert as a static object
 *
 * The official WinDivert SDK ships DLL source (C) plus a header that uses
 * Microsoft SAL annotations (__in, __out, ...) and a WINDIVERTEXPORT macro
 * that defaults to __declspec(dllimport).  That layout is awkward to drop
 * straight into a clang/MSYS2 static build, so this shim:
 *
 *   1. defines every SAL annotation the header uses to nothing
 *   2. forces WINDIVERTEXPORT to nothing (no dllexport/dllimport)
 *   3. includes the real windivert.h
 *
 * Then windivert.c / windivert_shared.c / windivert_helper.c can be
 * compiled as plain translation-unit code and linked into the exe.
 */
#ifndef WINDIVERT_STATIC_H
#define WINDIVERT_STATIC_H

/* SAL annotations: harmless no-ops for static builds */
#ifndef __in
#define __in
#endif
#ifndef __in_opt
#define __in_opt
#endif
#ifndef __out
#define __out
#endif
#ifndef __out_opt
#define __out_opt
#endif
#ifndef __inout
#define __inout
#endif
#ifndef __inout_opt
#define __inout_opt
#endif
#ifndef __deref_out
#define __deref_out
#endif
#ifndef __deref_out_opt
#define __deref_out_opt
#endif
#ifndef __in_ecount
#define __in_ecount(x)
#endif
#ifndef __out_ecount
#define __out_ecount(x)
#endif
#ifndef __in_bcount
#define __in_bcount(x)
#endif
#ifndef __out_bcount
#define __out_bcount(x)
#endif

/* Compile WinDivert as static code, not a DLL */
#ifdef WINDIVERTEXPORT
#undef WINDIVERTEXPORT
#endif
#define WINDIVERTEXPORT

/* WinDivert assumes winsock2.h was included before windows.h.
 * windivert.h pulls in windows.h, so satisfy that ordering here. */
#include <winsock2.h>
#include <ws2tcpip.h>

/* Pull in the real WinDivert 2.2 API header (the one in the SDK).
 * The -I path for C:\WinDivert-2.2.2\include is set in the Makefile. */
#include "windivert.h"

#endif /* WINDIVERT_STATIC_H */
