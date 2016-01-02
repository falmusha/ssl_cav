#ifndef CAV_COMMON_H
#define CAV_COMMON_H

#define DEBUG 1

#define DEBUG_PRINT(fmt, ...) \
        do { if (DEBUG) fprintf(stderr, "%s:%d:%s(): " fmt, __FILE__, \
                                __LINE__, __func__, __VA_ARGS__); } while (0)
#endif /* CAV_COMMMON_H */
