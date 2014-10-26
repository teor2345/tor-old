/** This file is generated based on the build architecture list,
 * then copied over tor/orconfig.h before building. */

/** Xcode expects architecture-specific code to be conditionalised,
 * rather than being in different files. It doesn't have per-architecture
 * file -> target memberships, so we fake it here. */

#ifdef __x86_64__
#include "contrib/osxbuild/orconfig-x86_64.h"
#endif // __x86_64__

#ifdef __i386__
#include "contrib/osxbuild/orconfig-i386.h"
#endif // __i386__
