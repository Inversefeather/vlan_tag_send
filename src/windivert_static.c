/*
 * windivert_static.c - Statically compile WinDivert into the exe
 *
 * This file exists only to compile the official WinDivert 2.2 user-mode
 * source as part of the static build.  It pulls in windivert.c, which in
 * turn #includes windivert_shared.c and windivert_helper.c, so the whole
 * library ends up in one translation unit.
 *
 * The WinDivertDllEntry (DllMain) is harmless in a static build: it is
 * simply never called, since there is no DLL loader.  We leave it in.
 */
#include "windivert_static.h"

/* Prevent the DLL entry point from being named DllMain-like; we don't
 * need it and it can cause linker noise on some setups.  Renaming via
 * preprocessor is the least invasive way. */
#define WinDivertDllEntry  WinDivertDllEntry_Unused

#include "../../WinDivert-2.2.2/dll/windivert.c"
