#include <cassert>
#include <cwchar>
#include <iostream>
#include "guard_protocol.h"
#include "guard_policy.h"

int main() {
    static_assert(sizeof(DG_STATUS) == 32, "Driver/broker status ABI mismatch");
    static_assert(sizeof(DG_REQUEST) == 3088, "Driver request ABI mismatch");
    static_assert(sizeof(DG_PIPE_REPLY) == 40, "Python/native pipe ABI mismatch");
    const wchar_t* root = L"\\Device\\HarddiskVolume3\\Users\\Guard\\AppData\\Roaming\\discord";
    auto within = [&](const wchar_t* name) {
        return DgPathWithin(name, wcslen(name), root, wcslen(root));
    };
    assert(within(root));
    assert(within(L"\\DEVICE\\HarddiskVolume3\\Users\\Guard\\AppData\\Roaming\\DISCORD\\Local State"));
    assert(!within(L"\\Device\\HarddiskVolume3\\Users\\Guard\\AppData\\Roaming\\discord-other\\Local State"));
    assert(!within(L"\\Device\\HarddiskVolume3\\Users\\Other\\AppData\\Roaming\\discord"));
    assert(!DgPathWithin(L"x", 1, root, wcslen(root)));
    assert(!DgPathWithin(root, wcslen(root), root, 0));
    assert(DgFileAllowed(1, 1, 0));
    assert(!DgFileAllowed(1, 0, 0));
    assert(!DgFileAllowed(0, 1, 0)); // Broker loss locks new user-mode file access.
    assert(DgFileAllowed(0, 0, 1));  // Kernel/paging I/O is not advertised as blocked.
    const unsigned long requested = 0xFFFF, dangerous = 0xF00;
    assert(DgRestrictedAccess(requested, dangerous, 0, 0, 0, 0) == (requested & ~dangerous));
    assert(DgRestrictedAccess(requested, dangerous, 1, 0, 0, 0) == requested);
    assert(DgRestrictedAccess(requested, dangerous, 1, 0, 1, 0) == (requested & ~dangerous));
    assert(DgRestrictedAccess(requested, dangerous, 1, 1, 1, 0) == requested);
    assert(DgRestrictedAccess(requested, dangerous, 0, 0, 0, 1) == requested);
    std::cout << "Native policy checks passed (ABI, scope, broker loss, duplicate-handle target).\n";
}
