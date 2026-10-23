/* Resolve the fixed system symbol; never call it or create fixture processes. */
#include <dlfcn.h>
#include <stdio.h>

int main(void) {
    void *library = dlopen("/usr/lib/libproc.dylib", RTLD_LAZY | RTLD_LOCAL);
    if (library == NULL) {
        puts("library_unavailable");
        return 0;
    }
    dlerror();
    void *symbol = dlsym(library, "proc_signal_with_audittoken");
    const char *error = dlerror();
    puts(error == NULL && symbol != NULL ? "present" : "absent");
    if (dlclose(library) != 0) {
        fputs("could not close Darwin inspection library\n", stderr);
        return 1;
    }
    return 0;
}
