#ifndef __AC_DEVICESERVICE_H__
#define __AC_DEVICESERVICE_H__
#include <stdio.h>
#include <stdlib.h>

#define MAX_OTAFILENUM 5

#define VERBOSE (1L)

typedef struct
{
    char chName[64];
    char chDownloadUrl[512];
    int IntFileType;
    int IntChecksum;
}AC_OtaFileInfo;

typedef struct
{
    char chTargetVersion[32];
    char chUpgradeLog[128];
    int IntOtaMode;
    int IntStatus;
    AC_OtaFileInfo struFileInfo[MAX_OTAFILENUM];
    int IntFileNum; 
}AC_OtaInfo;

#ifdef __cplusplus
extern "C" {
#endif
int AC_Init(char *domain, char *subdomain, char *devid, char *version);
int AC_UploadFile(const char *bucketName, char *remotefilename, char *localfilepath);
int AC_DownloadFile(const char *bucketName, char *remotefilename, char *localfilename);
int AC_OtaUpdate(int otaMode, char *DonwloadOtaFilePath, AC_OtaFileInfo *DonwloadOtaFileInfo, int *FileNum, char *OtaDescription);
#ifdef __cplusplus
}
#endif
#endif