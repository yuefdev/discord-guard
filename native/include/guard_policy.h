#pragma once
#include <stddef.h>

/* Shared with native user-mode tests. Windows paths are case-insensitive. */
static __inline wchar_t DgFold(wchar_t ch) {
    return ch >= L'A' && ch <= L'Z' ? (wchar_t)(ch + (L'a' - L'A')) : ch;
}

static __inline int DgPathWithin(const wchar_t* name, size_t nameChars,
                        const wchar_t* root, size_t rootChars) {
    size_t i;
    if (!name || !root || !rootChars || nameChars < rootChars) return 0;
    for (i = 0; i < rootChars; ++i) {
        if (DgFold(name[i]) != DgFold(root[i])) return 0;
    }
    return nameChars == rootChars || name[rootChars] == L'\\';
}

static __inline int DgFileAllowed(int connected, int trustedProcess, int kernelRequest) {
    return kernelRequest || (connected && trustedProcess);
}

static __inline unsigned long DgRestrictedAccess(unsigned long requested, unsigned long dangerous,
                                         int sourceTrusted, int destinationTrusted,
                                         int duplicate, int kernelHandle) {
    if (kernelHandle || (sourceTrusted && (!duplicate || destinationTrusted))) return requested;
    return requested & ~dangerous;
}
