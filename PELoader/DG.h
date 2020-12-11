#pragma once
#ifdef _DEBUG
#define ANSI_COLOR_RED "\x1b[31m"
#define ANSI_COLOR_GREEN "\x1b[32;1m"
#define ANSI_COLOR_RESET "\x1b[0m"
#define DEBUGD_PREFIX "[DEBUG] "
#define DEBUGI_PREFIX ANSI_COLOR_GREEN "[INFO] "
#define ERROR_PREFIX ANSI_COLOR_RED "[ERROR] "
#define DBGMSG(msg,...) fprintf(stderr, DEBUG_PREFIX "[%s %s %d] : " msg "\n", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOGD(msg,...) fprintf(stderr, DEBUGD_PREFIX msg "\n", ##__VA_ARGS__)
#define LOGI(msg,...) fprintf(stderr, DEBUGI_PREFIX msg "\n" ANSI_COLOR_RESET, ##__VA_ARGS__)
#define LOGE(msg,...) fprintf(stderr, ERROR_PREFIX msg "\n" ANSI_COLOR_RESET, ##__VA_ARGS__)
#else
#define DEGMSG(...)
#define LOGD(...)
#define LOGI(...)
#define LOGE(...)
#endif