/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2015, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/
/* <DESC>
 * simple HTTP POST using the easy interface
 * </DESC>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <curl/cJSON.h>
#include <curl/base64.h>
#include <fcntl.h>
#include <time.h>
#include <mbedtls/rsa.h>
#include <openssl/sha.h>
#include <mbedtls/config.h>
#include <HTTPClient.h>
#define MAJOR_DOMAIN "hongyan"//

#define SUB_DOMAIN  "https" //

#define DEVICE_ID "6666666666666666" //

#define DEFAULT_IOT_PRIVATE_KEY {\
0xE5,0x49,0x6A,0xCC,\
0x9D,0xE8,0x68,0x76,\
0xCE,0x5D,0xF4,0xB9,\
0xD5,0xE5,0x30,0x44,\
0xB6,0x39,0x9B,0x6C,\
0xB2,0x38,0xC8,0xCC,\
0x59,0x1B,0xD0,0x3C,\
0x9B,0x03,0x00,0x6B,\
0xFD,0xDE,0xB1,0x99,\
0x72,0x35,0xE7,0x9E,\
0xD8,0xD0,0x64,0x73,\
0xF5,0xE0,0x44,0xB9,\
0xE7,0x35,0xEB,0x65,\
0xCE,0xE9,0xF1,0x54,\
0xEB,0x14,0x84,0x9A,\
0x6F,0x5F,0x24,0x43,\
0x34,0xCC,0x61,0xE7,\
0x65,0xE7,0x6C,0x1A,\
0x8F,0x41,0x18,0x03,\
0x3D,0xF9,0xBC,0x91,\
0x02,0x62,0x87,0xFF,\
0x10,0xD7,0x50,0xE9,\
0xF3,0x52,0xCE,0xDB,\
0x58,0xF2,0xBE,0x49,\
0xE4,0x9B,0x1A,0x58,\
0x90,0x53,0x8F,0x7C,\
0xF6,0xDD,0x3B,0x12,\
0x78,0x9C,0x59,0xDA\
}

#define DEFAULT_IOT_PUBliC_KEY {\
0xE5,0x49,0x6A,0xCC,\
0x9D,0xE8,0x68,0x76,\
0xCE,0x5D,0xF4,0xB9,\
0xD5,0xE5,0x30,0x44,\
0xB6,0x39,0x9B,0x6C,\
0xB2,0x38,0xC8,0xCC,\
0x59,0x1B,0xD0,0x3C,\
0x9B,0x03,0x00,0x6B,\
0x01,0x00,0x01,0x00\
}
typedef enum
{
        AuthSchemaHttp = 0,
        AuthSchemaHttps,
}AC_HttpAuthSchema;


typedef enum
{
	    INVLIADBODYFORMAT = 1000,
        UPDATESTATUS_NOTVERSION = 1100,
        UPDATESTATUS_NOTFILIEINFOR,
}AC_RETSTATUS;

#define DEVICE_VERSION "0-0-1" // local device version

#define ACCSEE_KEY_LENGTH 16

#define KEY_LEN 256

#define HTTPS_PORT 9101

#define HTTP_PORT 5000 

#define FirmwarePath "/tmp/AbcloudFirmware" 

#define DNS "dev.ablecloud.cn" 

#define VERBOSE (0L)

char g_chDomain[32];
char g_chSubDomain[32];
char g_chModuleVersion[17];
char g_chDeviceId[17];
char g_chaccessKey[18] = {0};
char g_chPrivateKey[112] = DEFAULT_IOT_PRIVATE_KEY;
char g_chPublicKey[36] = DEFAULT_IOT_PUBliC_KEY;
AC_RETSTATUS  g_int32ErrorCode = 0;
int  g_int32fd = 0;

unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);

typedef struct
{
    char chAccessToken[64];
    char chAccessTokenExpire[21];
    char chrefreshToken[33];
    char chrefreshTokenExpire[21];
}AC_TokenInfo;

AC_TokenInfo g_struAcTokenInfo;

typedef struct
{
    char chUploadToken[512];
    char chStoreType[21];
}AC_UploadInfo;

AC_UploadInfo g_struAcUploadInfo;

typedef struct
{
    char chDownloadUrl[512];
    char chStoreType[21];
}AC_Downloadnfo;

AC_Downloadnfo g_struAcDownloadInfo;

typedef struct
{
    char chTargetVersion[32];
    char chName[64];
    char chDownloadUrl[512];
    char chUpgradeLog[128];
    int IntType;
    int IntChecksum;
    int IntOtaMode;
    int IntStatus;
}AC_OtaFileInfo;

AC_OtaFileInfo g_struAcOtaFileInfo;
typedef size_t (*pFunWriteCallback)(char *ptr, size_t size, size_t nmemb, void *userdata);

extern int mbedtls_rsa_self_test( int verbose );
/*************************************************
* Function: AC_Rand
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void AC_Rand(unsigned char *pu8Rand)
{
    unsigned int u32Rand;
    unsigned int u32Index;  
    srand((int)time(0));
    for (u32Index = 0; u32Index < (ACCSEE_KEY_LENGTH); u32Index++)
    {
        switch(rand()%3)
        {
            case 0:pu8Rand[u32Index]='A'+rand()%26;break;
            case 1:pu8Rand[u32Index]='a'+rand()%26;break;
            case 2:pu8Rand[u32Index]='0'+rand()%10;break;
        }       
    }
}

static int myrand( void *rng_state, unsigned char *output, size_t len )
{
#if !defined(__OpenBSD__)
    size_t i;
 //srand((int)time(0));
    if( rng_state != NULL )
        rng_state  = NULL;

    for( i = 0; i < len; ++i )
        output[i] = rand();
#else
    if( rng_state != NULL )
        rng_state = NULL;

    arc4random_buf( output, len );
#endif /* !OpenBSD */

    return( 0 );
}

/*************************************************
* Function: AC_InitRsaContextWithPrivateKey
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void AC_InitRsaContextWithPrivateKey(mbedtls_rsa_context *pstrRsa, const unsigned char *pu8PrivateKey)
{
    unsigned char u8Index;
    unsigned short u16StartPos;
    unsigned char u8BufLen[6] = {KEY_LEN >> 3,KEY_LEN >> 4,KEY_LEN >> 4,KEY_LEN >> 4,KEY_LEN >> 4,KEY_LEN >> 4};
    mbedtls_mpi *pstruMpi[6];
    
    mbedtls_rsa_init(pstrRsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1 );

    pstrRsa->len = KEY_LEN >> 3;

    pstruMpi[0] = &pstrRsa->N;
    pstruMpi[1] = &pstrRsa->P;
    pstruMpi[2] = &pstrRsa->Q;
    pstruMpi[3] = &pstrRsa->DP;
    pstruMpi[4] = &pstrRsa->DQ;    
    pstruMpi[5] = &pstrRsa->QP;  

    u16StartPos = 0;
    for (u8Index = 0; u8Index < 6; u8Index++)
    {
        mbedtls_mpi_read_binary(pstruMpi[u8Index], pu8PrivateKey + u16StartPos, u8BufLen[u8Index]);
        u16StartPos += (unsigned short)u8BufLen[u8Index];
    }
    
}
/*************************************************
* Function: AC_InitRsaContextWithPrivateKey
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void AC_InitRsaContextWithPulicKey(mbedtls_rsa_context *pstrRsa, const unsigned char *pu8Pubkey)
{

    
    mbedtls_rsa_init(pstrRsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1 );

    pstrRsa->len = KEY_LEN >> 3;

    mbedtls_mpi_read_binary(&pstrRsa->N, pu8Pubkey, pstrRsa->len);
    mbedtls_mpi_read_binary(&pstrRsa->E, pu8Pubkey + pstrRsa->len, 3);
}
/*************************************************
* Function: AC_RsaPssSign
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_RsaPssSign(unsigned short u16Len, unsigned char *sha1sum, unsigned char * rsa_ciphertext)
{
    mbedtls_rsa_context rsa;
    int ret = 0;
    
    AC_InitRsaContextWithPrivateKey(&rsa,g_chPrivateKey);
    #if 0
    if(mbedtls_rsa_check_privkey(&rsa) != 0)
    {
        printf("check key failed\n" );
        return ;
    }
    #endif
    ret = mbedtls_rsa_pkcs1_sign( &rsa, myrand, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA1, u16Len,
                        sha1sum, rsa_ciphertext);
    // mbedtls_rsa_private(&rsa, NULL,NULL,rsa_ciphertext, rsa_ciphertext);
    return ret;
}

/*************************************************
* Function: AC_RsaPssSign
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_RsaPssVerify(unsigned short u16Len, unsigned char *sha1sum, unsigned char * rsa_ciphertext)
{
    mbedtls_rsa_context rsa;
    int ret = 0;
    
    AC_InitRsaContextWithPulicKey(&rsa,g_chPublicKey);
   
    
    ret = mbedtls_rsa_pkcs1_verify( &rsa, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA1, u16Len,
                        sha1sum, rsa_ciphertext);
    return ret;
}
/*************************************************
* Function: AC_ReadTokenInfo
* Description: 
* Author: zhangwen 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_ReadTokenInfo()
{
    int line_count = 0;
    int file_size = 0;
    char *buffer;
    size_t result = 0;
    cJSON *root = NULL;
    cJSON *format;
    int ret = 0;

    do
    {
        g_int32fd = open("/tmp/AC_TonkenInfo", O_RDWR| O_CREAT, S_IRWXU);
        if(g_int32fd < 0)
        {
            fprintf(stderr, "open /tmp/AC_TonkenInfo failed\r\n");
            ret = -1;
            break;
        }
  
        file_size =lseek(g_int32fd,0,SEEK_END); 
        if(file_size<1)
        {
            fprintf(stderr, "lseek failed\r\n");
            ret = -2;
            break;  
        }

        lseek(g_int32fd,0,SEEK_SET);

         /* ·ÖÅäÄÚ´æ´æ´¢Õû¸öÎÄ¼þ */   
        buffer = (char*) malloc (sizeof(char)*file_size);  
        if (buffer == NULL)  
        {  
            fprintf(stderr,"Memory error");
            ret = -3;
            break;  
        }
    
        /* read token info */  
        result = read(g_int32fd, buffer, file_size);
        lseek(g_int32fd,0,SEEK_SET);  
        if (result != file_size)  
        {  
            fprintf(stderr,"Reading error");  
            ret = -4;
            break; 
        }  
    
        root = cJSON_Parse(buffer);
  
        if((NULL==cJSON_GetObjectItem(root,"accessToken"))||(NULL==cJSON_GetObjectItem(root,"refreshToken")))
        {
            fprintf(stderr, "read accessToken refreshToken failed\r\n");
            ret = -5;
            break; 
        }
        strcpy(g_struAcTokenInfo.chAccessToken,cJSON_GetObjectItem(root,"accessToken")->valuestring);
        strcpy(g_struAcTokenInfo.chAccessTokenExpire,cJSON_GetObjectItem(root,"accessTokenExpire")->valuestring);
        strcpy(g_struAcTokenInfo.chrefreshToken,cJSON_GetObjectItem(root,"refreshToken")->valuestring);
        strcpy(g_struAcTokenInfo.chrefreshTokenExpire,cJSON_GetObjectItem(root,"refreshTokenExpire")->valuestring);
    }while(0);

    if(NULL!=root)
    {
        cJSON_Delete(root);
    }

    if(0!=buffer)
    {
        free(buffer);
    }
    return ret;
}

/*************************************************
* Function: AC_WriteTokenInfo
* Description: 
* Author: zhangwen 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_WriteTokenInfo()
{
    cJSON *root = NULL;
    char *out = NULL;
    int ret = 0;

    do
    {  
        lseek(g_int32fd,0,SEEK_SET);

        root=cJSON_CreateObject();  
        cJSON_AddStringToObject(root,"accessToken",g_struAcTokenInfo.chAccessToken);
        cJSON_AddStringToObject(root,"accessTokenExpire",g_struAcTokenInfo.chAccessTokenExpire);
        cJSON_AddStringToObject(root,"refreshToken",g_struAcTokenInfo.chrefreshToken);
        cJSON_AddStringToObject(root,"refreshTokenExpire",g_struAcTokenInfo.chrefreshTokenExpire);

        out=cJSON_Print(root);  
        //printf("AC_WriteTokenInfo\r\n:%s\n",out); 
        ret = write(g_int32fd,out,strlen(out));
        if(ret!=strlen(out))
        {
        	printf("Write file fail\r\n:%s\n",out); 
        	break;
        }
        free(out);
    }while(0);

    if(NULL!=root)
    {
        cJSON_Delete(root);
    }
    return ret;
}
/*************************************************
* Function: ZC_HexToString
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void AC_HexToString(unsigned char *StringBuf,unsigned char* HexBuf,unsigned char len)
{
    unsigned char i;
    unsigned char *xad;

    // Display the extended address.
    xad = HexBuf;

    for (i = 0; i < len*2; xad++)
    {
        unsigned char ch;
        ch = (*xad >> 4) & 0x0F;
        StringBuf[i++] = ch + (( ch < 10 ) ? '0' : 'W');
        ch = *xad & 0x0F;
        StringBuf[i++] = ch + (( ch < 10 ) ? '0' : 'W');
    }
    StringBuf[len*2] = 0;
}

/*************************************************
* Function: GetTokenCallback
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
static size_t HttpHeaderCallback(void *buffer, size_t size, size_t nmemb, void *stream)
{
    if(HTTPStrInsensitiveCompare(buffer,"X-Zc-Ack",nmemb) == TRUE)
    {
         printf("X-Zc-Ack\r\n");
         g_int32ErrorCode = CURLE_OK;
    }
    else if(HTTPStrInsensitiveCompare(buffer,"X-Zc-Err",nmemb) == TRUE)
    {
         printf("X-Zc-Error\r\n");
         g_int32ErrorCode = -1;
    }
    return nmemb; 
}

/*************************************************
* Function: AC_AddHttpHeader
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_SendHttpRequest2(const char *body,const char *interface,char *token,pFunWriteCallback funWriteCallback)
{
    CURL *curl;
    CURLcode res;
    char tempspace[256] = {0};
    char sha1input[256] = {0};
    char sha1output[20] = {0};
    char chaccessKey[17] = {0};
    int timeout = 3600;
    int i = 0;
    time_t timestamp = time(NULL);
        /* In windows, this will init the winsock stuff */
    curl_global_init(CURL_GLOBAL_ALL);

    /* get a curl handle */
    curl = curl_easy_init();
    if(curl) {
     struct curl_slist *chunk = NULL;
    /* First set the URL that is about to receive our POST. This URL can
       just as well be a https:// URL if that is what should receive the
       data. */
    curl_msnprintf(tempspace,256,"http://%s:%d/%s",DNS,HTTP_PORT,interface);
    curl_easy_setopt(curl, CURLOPT_URL,tempspace);
    /* Now specify the POST data */
    
    if(NULL!=body)
    {
    	curl_easy_setopt(curl, CURLOPT_POSTFIELDS,body);
    }

    /* Remove a header curl would otherwise add by itself */
    chunk = curl_slist_append(chunk, "Content-Type:application/x-zc-object");

    curl_msnprintf(tempspace,256,"x-zc-major-domain:%s",g_chDomain);
   /* Remove a header curl would otherwise add by itself */
    chunk = curl_slist_append(chunk, (const char *)tempspace);

    curl_msnprintf(tempspace,256,"x-zc-sub-domain:%s",g_chSubDomain);

   /* Remove a header curl would otherwise add by itself */
    chunk = curl_slist_append(chunk, (const char *)tempspace);
   
    curl_msnprintf(tempspace,256,"X-Zc-Dev-Id:%s",g_chDeviceId);
   /* Remove a header curl would otherwise add by itself */
    chunk = curl_slist_append(chunk, (const char *)tempspace);
  
    /* Sec */
    chunk = curl_slist_append(chunk, "X-Zc-Content-Sec:noencrypt");

    /*Timestamp*/  
    curl_msnprintf(tempspace,256,"X-Zc-Timestamp:%ld",timestamp);
    chunk = curl_slist_append(chunk, (const char *)tempspace);

    /*Timeout*/
    curl_msnprintf(tempspace,256,"X-Zc-Timeout:%d",timeout);
    chunk = curl_slist_append(chunk, (const char *)tempspace);
    
    /*random key*/
    AC_Rand(chaccessKey);
   
    curl_msnprintf(tempspace,256,"X-Zc-Nonce:%s",chaccessKey);
    chunk = curl_slist_append(chunk, (const char *)tempspace);
    
    /*sha1*/
    curl_msnprintf(sha1input,256,"%d%ld%s%s",timeout,timestamp,chaccessKey,token);
   

    SHA1(sha1input,strlen(sha1input),sha1output);

    AC_HexToString(sha1input,sha1output,20);

    
    curl_msnprintf(tempspace,256,"X-Zc-Dev-Signature:%s",sha1input);

    chunk = curl_slist_append(chunk, (const char *)tempspace);

   /* set our custom set of headers */
    res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
   
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);     
    /* Perform the request, res will get the return code */
    if(funWriteCallback!=NULL)
    {
    	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, funWriteCallback);

    }

    for(i=0; i<3; i++)
    {
        res = curl_easy_perform(curl);
        /* Check for errors */
        if(res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                  curl_easy_strerror(res));
            sleep(1);
        }  
        else
        {
            res = g_int32ErrorCode;
            break;
        }
    }

    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  
  return res;  
}

/*************************************************
* Function: AC_AddHttpHeader
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_SendHttpRequest(AC_HttpAuthSchema scheme ,const char *body,const char *interface,char *token,pFunWriteCallback funWriteCallback)
{
    CURL *curl;
    CURLcode res;
    char tempspace[256] = {0};
    char sha1input[256] = {0};
    char sha1output[20] = {0};
    char chaccessKey[17] = {0};
    int timeout = 3600;
    int i=0;
    time_t timestamp = time(NULL);
        /* In windows, this will init the winsock stuff */
    curl_global_init(CURL_GLOBAL_ALL);

    /* get a curl handle */
    curl = curl_easy_init();
    if(curl) {
     struct curl_slist *chunk = NULL;
    /* First set the URL that is about to receive our POST. This URL can
       just as well be a https:// URL if that is what should receive the
       data. */
    if(AuthSchemaHttps== scheme)
    {
        curl_msnprintf(tempspace,256,"https://%s:%d/%s",DNS,HTTPS_PORT,interface);    	
    }
    else
    {
    	 curl_msnprintf(tempspace,256,"http://%s:%d/%s",DNS,HTTP_PORT,interface);   
    }
    curl_easy_setopt(curl, CURLOPT_URL,tempspace);
    /* Now specify the POST data */
    if(NULL!=body)
    {
    	curl_easy_setopt(curl, CURLOPT_POSTFIELDS,body);
    }

    /* Remove a header curl would otherwise add by itself */
    chunk = curl_slist_append(chunk, "Content-Type:application/x-zc-object");

    curl_msnprintf(tempspace,256,"x-zc-major-domain:%s",g_chDomain);
   /* Remove a header curl would otherwise add by itself */
    chunk = curl_slist_append(chunk, (const char *)tempspace);

    curl_msnprintf(tempspace,256,"x-zc-sub-domain:%s",g_chSubDomain);

   /* Remove a header curl would otherwise add by itself */
    chunk = curl_slist_append(chunk, (const char *)tempspace);
   
    curl_msnprintf(tempspace,256,"X-Zc-Dev-Id:%s",g_chDeviceId);
   /* Remove a header curl would otherwise add by itself */
    chunk = curl_slist_append(chunk, (const char *)tempspace);
  
    /* Sec */
    chunk = curl_slist_append(chunk, "X-Zc-Content-Sec:noencrypt");

    /*Timestamp*/  
    curl_msnprintf(tempspace,256,"X-Zc-Timestamp:%ld",timestamp);
    chunk = curl_slist_append(chunk, (const char *)tempspace);

    /*Timeout*/
    curl_msnprintf(tempspace,256,"X-Zc-Timeout:%d",timeout);
    chunk = curl_slist_append(chunk, (const char *)tempspace);
    
    /*random key*/
    AC_Rand(chaccessKey);
   
    curl_msnprintf(tempspace,256,"X-Zc-Nonce:%s",chaccessKey);
    chunk = curl_slist_append(chunk, (const char *)tempspace);
    
    /*sha1*/
    curl_msnprintf(sha1input,256,"%d%ld%s%s",timeout,timestamp,chaccessKey,token);
   
    //printf("sha1 input:");         
    //printf("%s\r\n", sha1input);
    SHA1(sha1input,strlen(sha1input),sha1output);
    //printf("sha1 output:"); 
    AC_HexToString(sha1input,sha1output,20);
   // printf("%s\r\n", sha1input);
    res = AC_RsaPssSign(20,sha1input,tempspace);
    if(res!=0)
    {
        printf("rsa pss fail= %d\n",res);
    }
    //printf("rsa pss = %s\r\n", tempspace);
    curl_msnprintf(tempspace,256,"X-Zc-Dev-Signature:%s",sha1input);

    chunk = curl_slist_append(chunk, (const char *)tempspace);

   /* set our custom set of headers */
    res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
   
    curl_easy_setopt(curl, CURLOPT_VERBOSE, VERBOSE);     
    /* Perform the request, res will get the return code */
    if(NULL!=funWriteCallback)
    {
    	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, funWriteCallback);
    }

     /*
     * If you want to connect to a site who isn't using a certificate that is
     * signed by one of the certs in the CA bundle you have, you can skip the
     * verification of the server's certificate. This makes the connection
     * A LOT LESS SECURE.
     *
     * If you have a CA cert for the server stored someplace else than in the
     * default bundle, then the CURLOPT_CAPATH option might come handy for
     * you.
     */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      /*
     * If the site you're connecting to uses a different host name that what
     * they have mentioned in their server certificate's commonName (or
     * subjectAltName) fields, libcurl will refuse to connect. You can skip
     * this check, but this will make the connection less secure.
     */ 
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    
    for(i=0; i<3; i++)
    {
        res = curl_easy_perform(curl);
        /* Check for errors */
        if(res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                  curl_easy_strerror(res));
            sleep(1);
        }  
        else
        {
            res = g_int32ErrorCode;
            break;
        }
    }
    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  
  return res;  
}
/*************************************************
* Function: AC_WriteFileCallback
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
static size_t AC_WriteFileCallback(void *ptr, size_t size, size_t nmemb, void *stream)
{
  cJSON *root = cJSON_Parse(ptr);
  size_t ret = 0;

  if(NULL!=root)
  {
  	cJSON *format = cJSON_GetObjectItem(root,"errorCode");
    
    if(NULL!=format)
    {
        g_int32ErrorCode = format->valueint;
        ret = 0;
    }
    else
    {   
            g_int32ErrorCode = CURLE_OK;
            ret = nmemb;
    }
     cJSON_Delete(root);
     return ret;
  }

  size_t written = fwrite(ptr, size, nmemb, (FILE *)stream);
  return written;
}

/*************************************************
* Function: AC_GetFile
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_GetFile(char *url,char *filename,pFunWriteCallback funWriteCallback)
{
  CURL *curl_handle;
  FILE *pagefile;
  int i=0;
  CURLcode res;
  
  curl_global_init(CURL_GLOBAL_ALL);

  /* init the curl session */
  curl_handle = curl_easy_init();
if(curl_handle)
{
  /* set URL to get here */
  curl_easy_setopt(curl_handle, CURLOPT_URL, url);

  /* Switch on full protocol/debug output while testing */
  curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);

  /* disable progress meter, set to 0L to enable and disable debug output */
  curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);

  /* send all data to this function  */
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, funWriteCallback);

  /* open the file */
  pagefile = fopen(filename, "wb");
  if (pagefile) {

    /* write the page body to this file handle */
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, pagefile);

    /* get it! */
   // for(i=0; i<3; i++)
    {
        res = curl_easy_perform(curl_handle);
        /* Check for errors */
        if(res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                  curl_easy_strerror(res));
            sleep(10);
        }  
        else
        {
           // break;
        }
    }

    /* close the header file */
    fclose(pagefile);
  }

  /* cleanup curl stuff */
  curl_easy_cleanup(curl_handle);
}
  curl_global_cleanup();
  return res;
}

/*************************************************
* Function: UpdateTokenCallback
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
static size_t UpdateTokenCallback(void *buffer, size_t size, size_t nmemb, void *stream)
{
    // printf("%s\r\n",buffer);
    cJSON *root = cJSON_Parse(buffer);
    size_t ret = 0;
    if(NULL == root)
    {
        printf("json parse error\r\n");
        g_int32ErrorCode = INVLIADBODYFORMAT;
        return nmemb;
    }


    cJSON *format = cJSON_GetObjectItem(root,"errorCode");
    
    if(NULL!=format)
    {
        g_int32ErrorCode = format->valueint;
        ret = nmemb;
    }
    else
    {   
            strcpy(g_struAcTokenInfo.chAccessToken,cJSON_GetObjectItem(root,"accessToken")->valuestring);
            strcpy(g_struAcTokenInfo.chAccessTokenExpire,cJSON_GetObjectItem(root,"accessTokenExpire")->valuestring);           
            AC_WriteTokenInfo();
            g_int32ErrorCode = 0;
            ret = nmemb;
    }
 
    printf("%s\r\n",(char*)buffer);
    cJSON_Delete(root);
    return ret; 
}

/*************************************************
* Function: AC_UpdateToken
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_UpdateToken()
{
    char body[256] = {0};
    curl_msnprintf(body,256,"{\"physicalDeviceId\":\"%s\"}",g_chDeviceId);
    return AC_SendHttpRequest(AuthSchemaHttps,(const char *)body,"zc-warehouse/v1/updateAccessToken",g_struAcTokenInfo.chrefreshToken,(pFunWriteCallback)UpdateTokenCallback); 
}

/*************************************************
* Function: GetTokenCallback
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
static size_t GetTokenCallback(void *buffer, size_t size, size_t nmemb, void *stream)
{
    // printf("%s\r\n",buffer);
    cJSON *root = cJSON_Parse(buffer);
    size_t ret = 0;
    if(NULL == root)
    {
        printf("json parse error\r\n");
        g_int32ErrorCode = INVLIADBODYFORMAT;
        return nmemb;
    }

    cJSON *format = cJSON_GetObjectItem(root,"errorCode");
   
    
    if(NULL!=format)
    {
        g_int32ErrorCode = format->valueint;
        ret = nmemb;
    }
    else
    {   

            strcpy(g_struAcTokenInfo.chAccessToken,cJSON_GetObjectItem(root,"accessToken")->valuestring);
            strcpy(g_struAcTokenInfo.chAccessTokenExpire,cJSON_GetObjectItem(root,"accessTokenExpire")->valuestring);
            strcpy(g_struAcTokenInfo.chrefreshToken,cJSON_GetObjectItem(root,"refreshToken")->valuestring);
            strcpy(g_struAcTokenInfo.chrefreshTokenExpire,cJSON_GetObjectItem(root,"refreshTokenExpire")->valuestring);
            AC_WriteTokenInfo(); 
            g_int32ErrorCode = 0;         
            ret = nmemb;
    }
    cJSON_Delete(root);

    return ret; 
}

/*************************************************
* Function: AC_GetToken
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_GetToken2()
{
    CURL *curl;
    CURLcode res;
    char body[256] = {0};
    char tempspace[256] = {0};
    char sha1input[256] = {0};
    char sha1output[33] = {0};
    time_t timestamp = time(NULL);
    char chaccessKey[17] = {0};
    unsigned char rsa_ciphertext[256];
    int timeout = 3600;
    int i = 0;
    /* In windows, this will init the winsock stuff */
    curl_global_init(CURL_GLOBAL_ALL);

    /* get a curl handle */
    curl = curl_easy_init();
    if(curl) {
  	 struct curl_slist *chunk = NULL;
    /* First set the URL that is about to receive our POST. This URL can
       just as well be a https:// URL if that is what should receive the
       data. */
    //curl_easy_setopt(curl, CURLOPT_URL, "https://%s:9101/zc-warehouse/v1/activateDevice",DNS);

    /* Remove a header curl would otherwise add by itself */
    chunk = curl_slist_append(chunk, "Content-Type:application/x-zc-object");

    curl_msnprintf(tempspace,256,"x-zc-major-domain:%s",g_chDomain);
   /* Remove a header curl would otherwise add by itself */
    chunk = curl_slist_append(chunk, (const char *)tempspace);

    curl_msnprintf(tempspace,256,"x-zc-sub-domain:%s",g_chSubDomain);

   /* Remove a header curl would otherwise add by itself */
    chunk = curl_slist_append(chunk, (const char *)tempspace);
   
    curl_msnprintf(tempspace,256,"X-Zc-Dev-Id:%s",g_chDeviceId);
   /* Remove a header curl would otherwise add by itself */
    chunk = curl_slist_append(chunk, (const char *)tempspace);

   /* set our custom set of headers */
    res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
   
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);     
    /* Perform the request, res will get the return code */
    
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HttpHeaderCallback);   
    
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, GetTokenCallback);
      
    /* Now specify the POST data */
    AC_Rand(chaccessKey);

    /*sha1*/
    curl_msnprintf(sha1input,256,"%d%ld%s%s",timeout,timestamp,chaccessKey,g_chDeviceId);

     printf("sha1:%s\n", sha1input);
     SHA1(sha1input,strlen(sha1input),sha1output);
    res = AC_RsaPssSign(20,sha1output,rsa_ciphertext);
    if(res!=0)
    {
        printf("rsa pss sign fail= %d\n",res);
        return res;
    }
    res = AC_RsaPssVerify(20,sha1output,rsa_ciphertext);
        if(res!=0)
    {
        printf("rsa pss vefify fail= %d\n",res);
        return res;
    }
    AC_HexToString(sha1input,rsa_ciphertext,KEY_LEN >> 3);
   
    printf("rsa sign:%s\r\n", sha1input);
    
    curl_msnprintf(body,256,"{\"physicalDeviceId\":\"%s\",\"timestamp\":\"%ld\",\"timeout\":\"%ld\",\"nonce\":\"%s\", \"signature\":\"%s\"}",g_chDeviceId,timestamp,timeout,chaccessKey,sha1input);
 
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS,(const char *)body);
     /*
     * If you want to connect to a site who isn't using a certificate that is
     * signed by one of the certs in the CA bundle you have, you can skip the
     * verification of the server's certificate. This makes the connection
     * A LOT LESS SECURE.
     *
     * If you have a CA cert for the server stored someplace else than in the
     * default bundle, then the CURLOPT_CAPATH option might come handy for
     * you.
     */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      /*
     * If the site you're connecting to uses a different host name that what
     * they have mentioned in their server certificate's commonName (or
     * subjectAltName) fields, libcurl will refuse to connect. You can skip
     * this check, but this will make the connection less secure.
     */ 
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
    for(i = 0;i < 3;i++)
    {
        res = curl_easy_perform(curl);
        /* Check for errors */
        if(res != CURLE_OK)
        {
            fprintf(stderr, "curl_easy_perform() failed: %s\n",
                  curl_easy_strerror(res));
            sleep(1);
        }  
        else
        {
            res = g_int32ErrorCode;
            break;
        }
    }
    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  curl_global_cleanup();
  
  return res; 
}

/*************************************************
* Function: AC_GetToken
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_GetToken()
{
    CURLcode res;
    char body[256] = {0};
    char tempspace[256] = {0};
    char sha1input[256] = {0};
    char sha1output[33] = {0};
    time_t timestamp = time(NULL);
    char chaccessKey[17] = {0};
    unsigned char rsa_ciphertext[256];
    int timeout = 3600;
    int i = 0;
   
      
    /* Now specify the POST data */
    AC_Rand(chaccessKey);

    /*sha1*/
    curl_msnprintf(sha1input,256,"%d%ld%s%s",timeout,timestamp,chaccessKey,g_chDeviceId);

     printf("sha1:%s\n", sha1input);
     SHA1(sha1input,strlen(sha1input),sha1output);
    res = AC_RsaPssSign(20,sha1output,rsa_ciphertext);
    if(res!=0)
    {
        printf("rsa pss sign fail= %d\n",res);
        return res;
    }
    res = AC_RsaPssVerify(20,sha1output,rsa_ciphertext);
        if(res!=0)
    {
        printf("rsa pss vefify fail= %d\n",res);
        return res;
    }
    AC_HexToString(sha1input,rsa_ciphertext,KEY_LEN >> 3);
   
    printf("rsa sign:%s\r\n", sha1input);
    
    curl_msnprintf(body,256,"{\"physicalDeviceId\":\"%s\",\"timestamp\":\"%ld\",\"timeout\":\"%ld\",\"nonce\":\"%s\", \"signature\":\"%s\"}",g_chDeviceId,timestamp,timeout,chaccessKey,sha1input);
 
    return AC_SendHttpRequest(AuthSchemaHttps,(const char *)body,"zc-warehouse/v1/activateDevice",g_struAcTokenInfo.chAccessToken,(pFunWriteCallback)GetTokenCallback); 
 
}
/*************************************************
* Function: UpdateTokenCallback
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
static size_t AC_GetUploadFileInfoCallback(void *buffer, size_t size, size_t nmemb, void *stream)
{
    // printf("%s\r\n",buffer);
\
    cJSON *root = cJSON_Parse(buffer);
    size_t ret = 0;

    cJSON *format = cJSON_GetObjectItem(root,"errorCode");

    if(NULL!=format)
    {
        g_int32ErrorCode = format->valueint;
        ret = 0;
    }
    else
    {   

            strcpy(g_struAcUploadInfo.chUploadToken,cJSON_GetObjectItem(root,"uptoken")->valuestring);
            strcpy(g_struAcUploadInfo.chStoreType,cJSON_GetObjectItem(root,"storeType")->valuestring);  
            g_int32ErrorCode = 0;
            ret =  nmemb; 
    }
    printf("%s\r\n",(char*)buffer);
    cJSON_Delete(root);
    
    return ret; 
\
}

/*************************************************
* Function: AC_GetUploadFileInfo
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_GetUploadFileInfo(char *filename)
{
    cJSON *root = NULL;
    cJSON *fmt = NULL;
    char *out = NULL;
    char tempspace[256] = {0};
    int ret = 0;
    root=cJSON_CreateObject();
    curl_msnprintf(tempspace,256,"%s_%s",g_chDomain,g_chSubDomain); 
    cJSON_AddStringToObject(root,"bucket",tempspace);
    cJSON_AddStringToObject(root,"name",filename);
    cJSON_AddStringToObject(root,"storeType","aws");
    cJSON_AddStringToObject(root,"scheme","https");
    cJSON_AddItemToObject(root, "acl", fmt=cJSON_CreateObject());
    cJSON_AddTrueToObject (fmt,"isPublicReadAllow");
    cJSON_AddTrueToObject (fmt,"isPublicWriteAllow");
    //cJSON_AddStringToObject(root,"metaData",g_struAcTokenInfo.chrefreshTokenExpire);
   // cJSON_AddStringToObject(root,"acl",g_struAcTokenInfo.chrefreshTokenExpire);
    
    out=cJSON_Print(root); 
     
    cJSON_Delete(root); 
    printf("%s\n",out); 
    ret = AC_SendHttpRequest(AuthSchemaHttp,(const char *)out,"zc-blobstore/v1/uploadFileInfo",g_struAcTokenInfo.chAccessToken,(pFunWriteCallback)AC_GetUploadFileInfoCallback); 
    free(out);  /* Print to text, Delete the cJSON, print it, release the string. */
    return ret;
}
/*************************************************
* Function: UpdateTokenCallback
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
static size_t AC_GetDownloadFileInfoCallback(void *buffer, size_t size, size_t nmemb, void *stream)
{
    // printf("%s\r\n",buffer);
    cJSON *root = cJSON_Parse(buffer);
    size_t ret = 0;

    cJSON *format = cJSON_GetObjectItem(root,"errorCode");

    if(NULL!=format)
    {
        g_int32ErrorCode = format->valueint;
        ret = 0;
    }
    else
    {   

            strcpy(g_struAcDownloadInfo.chDownloadUrl,cJSON_GetObjectItem(root,"downloadUrl")->valuestring);
            strcpy(g_struAcDownloadInfo.chStoreType,cJSON_GetObjectItem(root,"storeType")->valuestring);    
             g_int32ErrorCode = 0;
             ret = nmemb;
    }
    printf("%s\r\n",(char*)buffer);
    cJSON_Delete(root);
    return ret; 
}

/*************************************************
* Function: AC_GetUploadFileInfo
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_GetDownloadFileInfo(char *filename)
{
    cJSON *root = NULL;
    char *out = NULL;
    char tempspace[256] = {0};
    int ret = 0;
    
    root=cJSON_CreateObject(); 
    curl_msnprintf(tempspace,256,"%s_%s",g_chDomain,g_chSubDomain); 
    cJSON_AddStringToObject(root,"bucket",tempspace);
    cJSON_AddStringToObject(root,"name",filename);
    cJSON_AddStringToObject(root,"storeType","aws");
    cJSON_AddStringToObject(root,"expireTime","3600");
    cJSON_AddStringToObject(root,"scheme","http");
    //cJSON_AddStringToObject(root,"metaData",g_struAcTokenInfo.chrefreshTokenExpire);
   // cJSON_AddStringToObject(root,"acl",g_struAcTokenInfo.chrefreshTokenExpire);
    
    out=cJSON_Print(root); 
     
    cJSON_Delete(root); 
    printf("%s\n",out); 
    ret = AC_SendHttpRequest(AuthSchemaHttp,(const char *)out,"zc-blobstore/v1/getDownloadUrl",g_struAcTokenInfo.chAccessToken,(pFunWriteCallback)AC_GetDownloadFileInfoCallback); 
    free(out);  /* Print to text, Delete the cJSON, print it, release the string. */
    return ret;
}

/*************************************************
* Function: UpdateTokenCallback
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
static size_t AC_CheckOtaFileInfoCallback(void *buffer, size_t size, size_t nmemb, void *stream)
{
  
    cJSON *root = cJSON_Parse(buffer);
    size_t ret = 0;
    cJSON *format;
    cJSON *OtaFileMeta;

    if(NULL == root)
    {
        g_int32ErrorCode = 0;
        printf("json parse error\r\n");
        return nmemb;
    }
    
    format = cJSON_GetObjectItem(root,"errorCode");


    if(NULL!=format)
    {
        g_int32ErrorCode = format->valueint;
        ret = nmemb;
    }
    else
    {   
        if(0 == cJSON_GetObjectItem(root,"update")->valueint)
        {
            g_int32ErrorCode = UPDATESTATUS_NOTVERSION;
            printf("check not ota version\r\n");  
            return nmemb;
        }
        OtaFileMeta = cJSON_GetObjectItem(root,"files");
        if(NULL == OtaFileMeta)
        {
        	g_int32ErrorCode = UPDATESTATUS_NOTFILIEINFOR;
            printf("Ota File Info error\r\n");
            return nmemb;
        }
        
            g_struAcOtaFileInfo.IntStatus = cJSON_GetObjectItem(root,"status")->valueint;
            strcpy(g_struAcOtaFileInfo.chTargetVersion, cJSON_GetObjectItem(root,"targetVersion")->valuestring);                 
            g_struAcOtaFileInfo.IntOtaMode = cJSON_GetObjectItem(root,"otaMode")->valueint;
            strcpy(g_struAcOtaFileInfo.chUpgradeLog,cJSON_GetObjectItem(root,"upgradeLog")->valuestring);
             
            strcpy(g_struAcOtaFileInfo.chName,cJSON_GetObjectItem(OtaFileMeta->child,"name")->valuestring);
            strcpy(g_struAcOtaFileInfo.chDownloadUrl,cJSON_GetObjectItem(OtaFileMeta->child,"downloadUrl")->valuestring);
            g_struAcOtaFileInfo.IntType = cJSON_GetObjectItem(OtaFileMeta->child,"type")->valueint;  
            g_struAcOtaFileInfo.IntChecksum = cJSON_GetObjectItem(OtaFileMeta->child,"checksum")->valueint;  
            g_int32ErrorCode = 0;

            ret = nmemb;
    }
    printf("%s\r\n",(char*)buffer);
    cJSON_Delete(root);
   
    return ret; 
 
}

/*************************************************
* Function: AC_CheckOtaFileInfo
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_CheckOtaFileInfo()
{
    cJSON *root = NULL;
    char *out = NULL;
    int ret = 0;
    
    root=cJSON_CreateObject(); 
    cJSON_AddStringToObject(root,"version",g_chModuleVersion);
    cJSON_AddStringToObject(root,"physicalDeviceId",g_chDeviceId);
    /*system update*/
    cJSON_AddNumberToObject(root,"otaType",2);
    //cJSON_AddStringToObject(root,"metaData",g_struAcTokenInfo.chrefreshTokenExpire);
   // cJSON_AddStringToObject(root,"acl",g_struAcTokenInfo.chrefreshTokenExpire);
    
    out=cJSON_Print(root); 
     
    cJSON_Delete(root); 
    printf("%s\n",out); 
    ret = AC_SendHttpRequest(AuthSchemaHttps,(const char *)out,"zc-ota/v1/checkUpdate",g_struAcTokenInfo.chAccessToken,(pFunWriteCallback)AC_CheckOtaFileInfoCallback); 
    free(out);  /* Print to text, Delete the cJSON, print it, release the string. */
    return ret;
}

/*************************************************
* Function: AC_CheckOtaFileInfo
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_OtaUpdateFileEnd()
{
    cJSON *root = NULL;
    char *out = NULL;
    int ret = 0;
    
    root=cJSON_CreateObject(); 
    cJSON_AddStringToObject(root,"currentVersion",g_chModuleVersion);
    cJSON_AddStringToObject(root,"physicalDeviceId",g_chDeviceId);
    /*system update*/
    cJSON_AddNumberToObject(root,"otaType",g_struAcOtaFileInfo.IntType);
    //cJSON_AddStringToObject(root,"metaData",g_struAcTokenInfo.chrefreshTokenExpire);
   // cJSON_AddStringToObject(root,"acl",g_struAcTokenInfo.chrefreshTokenExpire);
    
    out=cJSON_Print(root); 
     
    cJSON_Delete(root); 
    printf("%s\n",out); 
    ret = AC_SendHttpRequest(AuthSchemaHttps,(const char *)out,"zc-ota/v1/otaMediaDone",g_struAcTokenInfo.chAccessToken,NULL); 
    free(out);  /* Print to text, Delete the cJSON, print it, release the string. */
   
    close(g_int32fd);
    //ret = system("/etc/init.d/ablecloud restart");
    return ret;
}



/*************************************************
* Function: AC_CheckOtaFileInfo
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_OtaUpdate(char *DonwloadOtaFilePath,char *DonwloadOtaFileName)
{
    int ret = 0;
    char DownloadfileName[64] = {0};
    ret = AC_CheckOtaFileInfo();
    if(ret != 0)
    {
        return ret;
    }
    curl_msnprintf(DownloadfileName,"%s\\%s",DonwloadOtaFilePath,g_struAcOtaFileInfo.chName);
    ret = AC_GetFile(g_struAcOtaFileInfo.chDownloadUrl,FirmwarePath,(pFunWriteCallback)AC_WriteFileCallback);

    if(ret != 0)
    {
        return ret;
    }
    strcpy(DonwloadOtaFileName,g_struAcOtaFileInfo.chName);
    ret = AC_OtaUpdateFileEnd();

    return ret;
}

/*************************************************
* Function: read_callback
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
static size_t AC_ReadFileCallback(void *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t retcode;
  curl_off_t nread;

  /* in real-world cases, this would probably get this data differently
     as this fread() stuff is exactly what the library already would do
     by default internally */
  retcode = fread(ptr, size, nmemb, stream);

  nread = (curl_off_t)retcode;

  fprintf(stderr, "*** We read %" CURL_FORMAT_CURL_OFF_T
          " bytes from file\n", nread);

  return retcode;
}

/*************************************************
* Function: AC_Init
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_PutFile(char *file,char *url)
{
  CURL *curl;
  CURLcode res;
  FILE * hd_src ;
  struct stat file_info;
  int i  = 0;
  /* get the file size of the local file */
  stat(file, &file_info);

  /* get a FILE * of the same file, could also be made with
     fdopen() from the previous descriptor, but hey this is just
     an example! */
  hd_src = fopen(file, "rb");

  /* In windows, this will init the winsock stuff */
  curl_global_init(CURL_GLOBAL_ALL);

  /* get a curl handle */
  curl = curl_easy_init();
  if(curl) {
    /* we want to use our own read function */
    curl_easy_setopt(curl, CURLOPT_READFUNCTION, AC_ReadFileCallback);

    /* enable uploading */
    curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);

    /* HTTP PUT please */
    curl_easy_setopt(curl, CURLOPT_PUT, 1L);

    /* specify target URL, and note that this URL should include a file
       name, not only a directory */
    printf("AC_PutFile:url %s\n",url );
    curl_easy_setopt(curl, CURLOPT_URL, url);

    /* now specify which file to upload */
    curl_easy_setopt(curl, CURLOPT_READDATA, hd_src);

    /* provide the size of the upload, we specicially typecast the value
       to curl_off_t since we must be sure to use the correct data size */
    curl_easy_setopt(curl, CURLOPT_INFILESIZE_LARGE,
                     (curl_off_t)file_info.st_size);
     /*
     * If you want to connect to a site who isn't using a certificate that is
     * signed by one of the certs in the CA bundle you have, you can skip the
     * verification of the server's certificate. This makes the connection
     * A LOT LESS SECURE.
     *
     * If you have a CA cert for the server stored someplace else than in the
     * default bundle, then the CURLOPT_CAPATH option might come handy for
     * you.
     */
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
      /*
     * If the site you're connecting to uses a different host name that what
     * they have mentioned in their server certificate's commonName (or
     * subjectAltName) fields, libcurl will refuse to connect. You can skip
     * this check, but this will make the connection less secure.
     */ 
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);  
    /* Now run off and do what you've been told! */
    for(i = 0; i<3; i++)
    {
    res = curl_easy_perform(curl);
    /* Check for errors */
    if(res != CURLE_OK)
    {
      fprintf(stderr, "curl_easy_perform() failed: %s\n",
              curl_easy_strerror(res));
    }
    else
    {
    	break;
    }
    }
    /* always cleanup */
    curl_easy_cleanup(curl);
  }
  fclose(hd_src); /* close the local file */

  curl_global_cleanup();
  return 0;
}
/*************************************************
* Function: AC_Init
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_UploadFile(char *remotefilename,char *localfilename)
{
    int ret = 0;
    ret = AC_GetUploadFileInfo(remotefilename);
    if(ret != 0)
    {
        return ret;
    }
    ret = AC_PutFile(localfilename,g_struAcUploadInfo.chUploadToken);
    return ret;
}

/*************************************************
* Function: AC_DownloadFile
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_DownloadFile(char *remotefilename,char *localfilename)
{
    int ret = 0;
    ret = AC_GetDownloadFileInfo(remotefilename);
    if(ret != 0)
    {
        return ret;
    }
    ret = AC_GetFile(g_struAcDownloadInfo.chDownloadUrl,localfilename,(pFunWriteCallback)AC_WriteFileCallback);
    return ret;
}

/*************************************************
* Function: AC_Init
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_Init(char *domain, char *subdomain, char *devid, char *version)
{
    CURL *curl;
    CURLcode res;
    char *tempspace = (char *)malloc(256);
    int ret = 0;

    memset(g_chDomain,0,32);
    memset(g_chSubDomain,0,32);
    memset(g_chModuleVersion,0,17);
    memset(g_chDeviceId,0,17);

    strcpy(g_chDomain,domain);
    strcpy(g_chSubDomain,subdomain);
    memcpy(g_chDeviceId,devid,16);
    strcpy(g_chModuleVersion,version);
    ret = AC_ReadTokenInfo();

    if(0 != ret)
    {
        ret = AC_GetToken();
    }
    else
    {
        ret=AC_UpdateToken();
        if(0 != ret)
        {
            ret=AC_GetToken();
        }
    }
   return ret; 
}

#if 0
/*************************************************
* Function: AC_RsaPssSign
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_RsaTest( int verbose )
{
       int ret = 0;
    size_t len;
    mbedtls_rsa_context rsa;
    unsigned char rsa_plaintext[PT_LEN];
    unsigned char rsa_decrypted[PT_LEN*3];
    unsigned char rsa_ciphertext[KEY_LEN];
    unsigned char sha1sum[20];
    memcpy( rsa_plaintext, RSA_PT, PT_LEN );
   SHA1( rsa_plaintext, PT_LEN, sha1sum );
   ret = AC_RsaPssSign(20,sha1sum,rsa_ciphertext);

     AC_HexToString(rsa_decrypted,rsa_ciphertext,20);
    printf("%s\r\n", rsa_decrypted);
   if(ret==0)
   {   printf("rsa_ciphertext=%s\n", rsa_decrypted);}
else
{
    printf("ret fail=%d\n", ret);
}

}

int mbedtls_rsa_self_test2( int verbose )
{
    int ret = 0;

    size_t len;
    mbedtls_rsa_context rsa;
    mbedtls_rsa_context rsa1;
    unsigned char rsa_plaintext[32];
    unsigned char rsa_decrypted[PT_LEN];
    unsigned char rsa_ciphertext[KEY_LEN]={0};
    unsigned char buf[1024];
    unsigned char sha1sum[20];
    unsigned char rawsig[] = { 0x4c, 0x87, 0xb4, 0x28, 0x92, 0xa9,
        0xc1, 0x18, 0xcc, 0x3d, 0xbf, 0x7d,
        0x26, 0xdc, 0x86, 0x2f, 0xdc, 0x3f,
        0xf6, 0x3c, 0x35, 0xd3, 0x13, 0xad,
        0xb5, 0x6b, 0x4c, 0x2c, 0xdb, 0x3f,
        0x15, 0xbc };
#if 0
    mbedtls_rsa_init( &rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA1  );

    rsa.len = KEY_LEN;
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa.N , 16, RSA_N  ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa.E , 16, RSA_E  ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa.D , 16, RSA_D  ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa.P , 16, RSA_P  ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa.Q , 16, RSA_Q  ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa.DP, 16, RSA_DP ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa.DQ, 16, RSA_DQ ) );
    MBEDTLS_MPI_CHK( mbedtls_mpi_read_string( &rsa.QP, 16, RSA_QP ) );
#endif 
    AC_InitRsaContextWithPulicKey(&rsa1,g_chPublicKey);
    AC_InitRsaContextWithPrivateKey(&rsa,g_chPrivateKey);
    mbedtls_rsa_private(&rsa, NULL,NULL,rawsig, buf);

     {
    int i =0 ;
    printf("rsa_private::");
 for(i =0 ;i<32;i++)
 {
     printf("0x%x ", buf[i]);
 }
printf("\n");
}


   //memcpy( rsa_plaintext, RSA_PT, PT_LEN );
#if 0
    memcpy( rsa_plaintext, RSA_PT, PT_LEN );
    
    ret = mbedtls_rsa_pkcs1_encrypt( &rsa, myrand, NULL, MBEDTLS_RSA_PUBLIC, PT_LEN,
                           rsa_plaintext, rsa_ciphertext );
    if( ret != 0 )
    {
        if( verbose != 0 )
             printf( "failed, ret = %d\n",ret );

        return( 1 );
    }

    if( verbose != 0 )
        printf( "passed\n  PKCS#1 decryption : " );

    ret = mbedtls_rsa_pkcs1_decrypt( &rsa, myrand, NULL, MBEDTLS_RSA_PRIVATE, &len,
                           rsa_ciphertext, rsa_decrypted,
                           sizeof(rsa_decrypted) );
    if( ret != 0 )
    {
        if( verbose != 0 )
            printf( "failed, ret = %d\n",ret );

        return( 1 );
    }

    if( memcmp( rsa_decrypted, rsa_plaintext, len ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }

    if( verbose != 0 )
        printf( "passed\n" );
 #endif   
    memset( rsa_plaintext, 0, 32 );
#if 0
   if( verbose != 0 )
        printf( "  RSA key validation: " );

    if( mbedtls_rsa_check_pubkey(  &rsa ) != 0 ||
        mbedtls_rsa_check_privkey( &rsa ) != 0 )
    {
        if( verbose != 0 )
            printf( "failed\n" );

        return( 1 );
    }
    #endif
    if( verbose != 0 )
        printf( "PKCS#1 data sign  : " );

    SHA1( rsa_plaintext, 32, sha1sum );
 {
    int i =0 ;
    printf("sha1::");
 for(i =0 ;i<20;i++)
 {
     printf("0x%x ", sha1sum[i]);
 }
  printf("\n");
 }
 //AC_InitRsaContextWithPrivateKey(&rsa,g_chPrivateKey);
    ret = mbedtls_rsa_pkcs1_sign( &rsa, myrand, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA1, 20,
                        sha1sum, rsa_ciphertext ) ;
    #if 1
        mbedtls_rsa_private(&rsa, NULL,NULL,rsa_ciphertext, rsa_ciphertext);

     {
    int i =0 ;
    printf("rsa_private2::");
 for(i =0 ;i<32;i++)
 {
     printf("0x%x ", buf[i]);
 }
printf("\n");
}
#endif
    if(  ret!= 0 )
    {
        if( verbose != 0 )
            printf( "failed ret =%04x\n",ret );

        return( 1 );
    }

 {
    int i =0 ;
    printf("mbedtls_rsa_pkcs1_sign::");
 for(i =0 ;i<32;i++)
 {
     printf("0x%02x ", rsa_ciphertext[i]);
 }
  printf("\n");
 }
    if( verbose != 0 )
        printf( "passed\n  PKCS#1 sig. verify: " );
ret = mbedtls_rsa_pkcs1_verify( &rsa1, NULL, NULL, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA1, 0,
                          sha1sum, rsa_ciphertext );
    if( ret!= 0 )
    {
        if( verbose != 0 )
            printf( "failed ret =%d\n",ret );
        return( 1 );
    }

    if( verbose != 0 )
        printf( "passed\n" );


    if( verbose != 0 )
        printf( "\n" );

cleanup:
    mbedtls_rsa_free( &rsa );
/* MBEDTLS_PKCS1_V15 */
    return( ret );
}
#endif
/*************************************************
* Function: main
* Description: 
* Author: cxy 
* Returns: 
* Parameter: 
* History:
*************************************************/
void main()
{
       
    int ret =0;
     char filename[64] = {0};
    ret = AC_Init(MAJOR_DOMAIN,SUB_DOMAIN,DEVICE_ID,DEVICE_VERSION); 

    if(0 != ret)
    {
        printf("AC_Init errror=%d\n",ret);
    }
    else
    {
        //AC_UploadFile("test2","cJSON.c");
        //AC_DownloadFile("test","localtest.c");
        AC_OtaUpdate("//tmp",filename);
        printf("ota filename =%s\n",filename);
    }
 
   //mbedtls_rsa_self_test2(1);
    //AC_RsaTest(1);
   
}


