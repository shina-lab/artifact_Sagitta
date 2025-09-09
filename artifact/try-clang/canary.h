#ifndef __canary_h__
#define __canary_h__

#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

/* libcをインクルードすると
crypto/getenv.c:94:12: error: call to undeclared function 'secure_getenv'; ISO C99 and later do not support implicit function declarations [-Wimplicit-function-declaration]
    return secure_getenv(name);
           ^
1 error generated.
*/

#ifdef __cplusplus
extern "C"
{
#endif
    // void __magma_log(const char *bug_id, bool bug_triggered, const char *func, char* file, unsigned long int line);
    void __polytracker_save() __attribute__((weak)) {}
#ifdef __cplusplus
}
#endif

// static inline void __magma_log(const char *bug_id, bool bug_triggered, const char *func, char* file, unsigned long int line) {
//     if (bug_triggered) {
//         // fprintf(stderr, "[!] Aborted by %s", bug_id);
//         // abort();
//     }
// }

// #define __trace_canary dprintf(100, "- { log_type: Kind, kind: Canary, func: \"%s\", file: \"%s\", line: %lu }\n", __func__, __FILE__, __LINE__);
// #define MAGMA_LOG(bug_id, expr) __magma_log(bug_id, (bool) expr,  __func__, __FILE__, __LINE__)
#define MAGMA_LOG(bug_id, expr)                                                 \
    {                                                                           \
        volatile bool result = (expr);                                          \
        if (result)                                                             \
        {                                                                       \
            fprintf(stderr, "[!] Canary triggered by %s: %s\n", bug_id, #expr); \
            __polytracker_save();                                               \
            char *term_id = getenv("MAGMA_TERM_ID");                            \
            if (term_id && strcmp(term_id, bug_id) == 0)                        \
            {                                                                   \
                fprintf(stderr, "[!] Aborted by canary %s\n", bug_id);          \
                raise(SIGTRAP);                                                 \
            }                                                                   \
        }                                                                       \
        else                                                                    \
        {                                                                       \
            fprintf(stderr, "[*] Canary %s not triggered\n", bug_id);           \
        }                                                                       \
    }
#define MAGMA_LOG_V(b, c) (MAGMA_LOG((b), (int)(c)))
#define MAGMA_AND(a, b) ((bool)(a) && (bool)(b))
#define MAGMA_OR(a, b) ((bool)(a) || (bool)(b))

#endif