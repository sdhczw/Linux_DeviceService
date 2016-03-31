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
#include <cJSON/cJSON.h>
#include <curl/base64.h>
#include <fcntl.h>
#include <time.h>
#include <mbedtls/rsa.h>
#include <openssl/sha.h>
#include <mbedtls/config.h>
#include <base.h>
#include <io.h>
#include <AC_DeviceService.h>
#include <AC_CFG.h>

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
   UPDATESTATUS_FILIENUMERROR,
   ACCESSTOKENEXPIRE = 3515,
   REFRESHTOKENEXPIRE = 3516
}AC_RETSTATUS;

#define ACCSEE_KEY_LENGTH 16

#define KEY_LEN (256)

#define HTTPS_PORT (9005)

#define HTTP_PORT (5000) 

char g_chDomain[32];
char g_chSubDomain[32];
char g_chModuleVersion[17];
char g_chDeviceId[17];
char g_chPrivateKey[112] = DEFAULT_IOT_PRIVATE_KEY;
char g_chPublicKey[36] = DEFAULT_IOT_PUBliC_KEY;
AC_RETSTATUS  g_int32ErrorCode = 0;
int  g_int32fd = 0;

//unsigned char *SHA1(const unsigned char *d, size_t n, unsigned char *md);

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

AC_OtaInfo g_struAcOtaFileInfo;
typedef size_t (*pFunWriteCallback)(char *ptr, size_t size, size_t nmemb, void *userdata);
static size_t AC_GetTokenCallback(void *buffer, size_t size, size_t nmemb, void *stream);

/*************************************************
* Function: AC_Rand
* Description: 
* Author: zw 
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

/*************************************************
* Function: AC_RSARand
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
static int AC_RSARand( void *rng_state, unsigned char *output, size_t len )
{
#if !defined(__OpenBSD__)
    size_t i;
    
    srand((int)time(0));
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
* Author: zw 
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
* Function: AC_InitRsaContextWithPulicKey
* Description: 
* Author: zw 
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
* Author: zw 
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
    ret = mbedtls_rsa_check_privkey(&rsa);
    if(ret != 0)
    {
        printf("check key failed\n" );
        return ret;
    }
    #endif
    ret = mbedtls_rsa_pkcs1_sign( &rsa, AC_RSARand, NULL, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA1, u16Len,
        sha1sum, rsa_ciphertext);
    // mbedtls_rsa_private(&rsa, NULL,NULL,rsa_ciphertext, rsa_ciphertext);
    return ret;
}

/*************************************************
* Function: AC_RsaPssVerify
* Description: 
* Author: zw 
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
        if(NULL==root)
        {
            printf("Create Object fail\r\n"); 
            ret = -1;
            break;
        }  
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
            ret = -1;
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
* Function: AC_HexToString
* Description: 
* Author: zw 
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
* Function: AC_HttpHeaderCallback
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
static size_t AC_HttpHeaderCallback(void *buffer, size_t size, size_t nmemb, void *stream)
{
    if(NULL==buffer)
    {
       g_int32ErrorCode = -1;
       return nmemb;  
    }

    if(strstr(buffer,"X-Zc-Ack") != NULL)
    {
        printf("X-Zc-Ack\r\n");
        g_int32ErrorCode = CURLE_OK;
    }
    else if(strstr(buffer,"X-Zc-Err") != NULL)
    {
        printf("X-Zc-Error\r\n");
        g_int32ErrorCode = -1;
    } 
    return nmemb; 
}

/*************************************************
* Function: AC_GetToken
* Description: 
* Author: zw 
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

    printf("AC_GetToken!!!\r\n");
    /* Now specify the POST data */
    AC_Rand(chaccessKey);

    /*sha1*/
    curl_msnprintf(sha1input,256,"%d%ld%s%s",timeout,timestamp,chaccessKey,g_chDeviceId);

    //printf("sha1:%s\n", sha1input);
    SHA1(sha1input,strlen(sha1input),sha1output);
    //printf("sha1output:%s\r\n", sha1output);
    res = AC_RsaPssSign(20,sha1output,rsa_ciphertext);
    if(res!=0)
    {
        printf("rsa pss sign fail= %d\n",res);
        return res;
    }
    #if 0
    res = AC_RsaPssVerify(20,sha1output,rsa_ciphertext);
    if(res!=0)
    {
        printf("rsa pss vefify fail= %d\n",res);
        return res;
    }
    #endif
    AC_HexToString(sha1input,rsa_ciphertext,KEY_LEN >> 3);

    //printf("rsa sign:%s\r\n", sha1input);
    
    curl_msnprintf(body,256,"{\"physicalDeviceId\":\"%s\",\"timestamp\":\"%ld\",\"timeout\":\"%ld\",\"nonce\":\"%s\", \"signature\":\"%s\"}",g_chDeviceId,timestamp,timeout,chaccessKey,sha1input);

    return AC_SendHttpRequest(AuthSchemaHttps,(const char *)body,"zc-warehouse/v1/activateDevice",g_struAcTokenInfo.chAccessToken,(pFunWriteCallback)AC_GetTokenCallback); 

}

/*************************************************
* Function: AC_SendHttpRequest
* Description: 
* Author: zw 
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
	int i= 0;
	long httpCode;
	time_t timestamp = time(NULL);
        /* In windows, this will init the winsock stuff */
	curl_global_init(CURL_GLOBAL_ALL);

    /* get a curl handle */
	curl = curl_easy_init();
	if(curl)
	{
	    struct curl_slist *chunk = NULL;
        /* First set the URL that is about to receive our POST. This URL can
         just as well be a https:// URL if that is what should receive the
       data. */
        if(AuthSchemaHttps== scheme)
        {
       	    curl_msnprintf(tempspace,256,"https://%s:%d/%s",CLOUD_ADDR,HTTPS_PORT,interface);    	
        }
        else
        {
       	    curl_msnprintf(tempspace,256,"http://%s:%d/%s",CLOUD_ADDR,HTTP_PORT,interface);   
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

        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, AC_HttpHeaderCallback);

        if(NULL!=funWriteCallback)
        {
       	    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, funWriteCallback);
        }
#if 0
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
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 2L);
      /*
     * If the site you're connecting to uses a different host name that what
     * they have mentioned in their server certificate's commonName (or
     * subjectAltName) fields, libcurl will refuse to connect. You can skip
     * this check, but this will make the connection less secure.
     */ 
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
#endif

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
     		    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
     		    if (httpCode / 100 != 2) 
     		    {
     			    res= httpCode;
     		    }
     		    else
     		    {
     			    res = g_int32ErrorCode;
     		    }
                printf("AC_SendHttpRequest Ret = %d!!!\r\n",res);
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
* Author: zw 
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
			ret = nmemb;
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
    printf("fwrite\n");
	return written;
}

/*************************************************
* Function: AC_GetFile
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_GetFile(char *url,char *filename,pFunWriteCallback funWriteCallback)
{
	CURL *curl_handle;
	FILE *pagefile;
	long httpCode;
	int i = 0;
	CURLcode res;
	
	curl_global_init(CURL_GLOBAL_ALL);

  /* init the curl session */
	curl_handle = curl_easy_init();
	if(curl_handle)
	{
  /* set URL to get here */
		curl_easy_setopt(curl_handle, CURLOPT_URL, url);

  /* Switch on full protocol/debug output while testing */
		curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, VERBOSE);

  /* disable progress meter, set to 0L to enable and disable debug output */
		curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);

  /* send all data to this function  */
		curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, funWriteCallback);

  /* open the file */
		pagefile = fopen(filename, "wb");
		
        if (pagefile) 
        {
    /* write the page body to this file handle */
			curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, pagefile);

    /* get it! */
			for(i=0; i<3; i++)
			{
				res = curl_easy_perform(curl_handle);
        /* Check for errors */
				if(res != CURLE_OK)
				{
					fprintf(stderr, "curl_easy_perform() failed: %s\n",
						curl_easy_strerror(res));
					sleep(1);
				}  
				else
				{
					curl_easy_getinfo(curl_handle, CURLINFO_RESPONSE_CODE, &httpCode);
					if (httpCode / 100 != 2) 
					{
						res= httpCode;
					}
					else
					{
						res = CURLE_OK;
					}
					break;
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
* Function: AC_UpdateTokenCallback
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
static size_t AC_UpdateTokenCallback(void *buffer, size_t size, size_t nmemb, void *stream)
{
    // printf("%s\r\n",buffer);
	cJSON *root = NULL;
    size_t ret = 0;

    if(NULL == buffer)
    {
        printf("no body\r\n");
        g_int32ErrorCode = INVLIADBODYFORMAT;
        return nmemb;
    }

    root = cJSON_Parse(buffer);
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
	}
	else
	{   
		strcpy(g_struAcTokenInfo.chAccessToken,cJSON_GetObjectItem(root,"accessToken")->valuestring);
		strcpy(g_struAcTokenInfo.chAccessTokenExpire,cJSON_GetObjectItem(root,"accessTokenExpire")->valuestring);           
		g_int32ErrorCode = 0;
        AC_WriteTokenInfo();

	}

	//printf("%s\r\n",(char*)buffer);
	cJSON_Delete(root);
	return nmemb; 
}

/*************************************************
* Function: AC_UpdateToken
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_UpdateToken()
{
    char body[256] = {0};
    printf("AC_UpdateToken\r\n");
    curl_msnprintf(body,256,"{\"physicalDeviceId\":\"%s\"}",g_chDeviceId);
    return AC_SendHttpRequest(AuthSchemaHttps,(const char *)body,"zc-warehouse/v1/updateAccessToken",g_struAcTokenInfo.chrefreshToken,(pFunWriteCallback)AC_UpdateTokenCallback); 
}

/*************************************************
* Function: AC_GetTokenCallback
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
static size_t AC_GetTokenCallback(void *buffer, size_t size, size_t nmemb, void *stream)
{
    // printf("%s\r\n",buffer);
    cJSON *root = NULL;

    if(NULL == buffer)
    {
        printf("no body\r\n");
        g_int32ErrorCode = INVLIADBODYFORMAT;
        return nmemb;
    }

    root = cJSON_Parse(buffer);

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
    }
    else
    {   

        strcpy(g_struAcTokenInfo.chAccessToken,cJSON_GetObjectItem(root,"accessToken")->valuestring);
        strcpy(g_struAcTokenInfo.chAccessTokenExpire,cJSON_GetObjectItem(root,"accessTokenExpire")->valuestring);
        strcpy(g_struAcTokenInfo.chrefreshToken,cJSON_GetObjectItem(root,"refreshToken")->valuestring);
        strcpy(g_struAcTokenInfo.chrefreshTokenExpire,cJSON_GetObjectItem(root,"refreshTokenExpire")->valuestring);
        AC_WriteTokenInfo(); 
        g_int32ErrorCode = 0; 
        printf("AC_GetToken OK\r\n");        
    }
    cJSON_Delete(root);

    return nmemb; 
}

/*************************************************
* Function: AC_TimeExpire
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_TimeExpire(char *TokenExpire)
{
	time_t t;
	time_t timestamp =time(NULL); 
	struct tm tm;
	int ret = 0;
	timestamp = mktime(gmtime(&timestamp));
	sscanf(TokenExpire, "%d-%d-%d %d:%d:%d",
		&tm.tm_year, &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
	printf("Token Time Expire: year[%d], month[%d], day[%d], hour[%d], min[%d], second[%d]\r\n",
		tm.tm_year, tm.tm_mon, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
	tm.tm_year = tm.tm_year - 1900;
	tm.tm_mon = tm.tm_mon -1;
	t = mktime(&tm);
	//printf("second1970:[%d]\n", (int)t);
	//printf("local timestamp:[%d]\n", (int)timestamp);
	if(timestamp > t)
	{
		ret = -1;
	}
	else
	{
		ret = 0;
	}
	return ret;
}

/*************************************************
* Function: AC_TokenExpireProcess
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_TokenExpireProcess()
{
	int ret = 0;
	ret=AC_TimeExpire(g_struAcTokenInfo.chAccessTokenExpire);

	if(ret == -1)
	{
        printf("Acess Token Expire\r\n");
		ret=AC_TimeExpire(g_struAcTokenInfo.chrefreshTokenExpire);
		if(ret == -1)
		{
            printf("Refresh Token Expire\r\n");
			ret = AC_GetToken();
		}
		else
		{
			ret = AC_UpdateToken();
		}
	}

	return ret;
}

/*************************************************
* Function: AC_GetUploadFileInfoCallback
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
static size_t AC_GetUploadFileInfoCallback(void *buffer, size_t size, size_t nmemb, void *stream)
{
    // printf("%s\r\n",buffer);
    cJSON *root = NULL;

    if(NULL == buffer)
    {
        printf("Get UploadFileInfo Fail!!!\r\n");
        printf("no body\r\n");
        g_int32ErrorCode = INVLIADBODYFORMAT;
        return nmemb;
    }

    root = cJSON_Parse(buffer);
    if(NULL == root)
    {
        printf("Get UploadFileInfo Fail!!!\r\n");
        printf("json parse error\r\n");
        g_int32ErrorCode = INVLIADBODYFORMAT;
        return nmemb;
    }

    cJSON *format = cJSON_GetObjectItem(root,"errorCode");

    if(NULL!=format)
    {
        g_int32ErrorCode = format->valueint;
    }
    else
    {   

        strcpy(g_struAcUploadInfo.chUploadToken,cJSON_GetObjectItem(root,"uptoken")->valuestring);
        strcpy(g_struAcUploadInfo.chStoreType,cJSON_GetObjectItem(root,"storeType")->valuestring);  
        g_int32ErrorCode = 0; 
        printf("Get UploadFileInfo OK!!!\r\n");
    }
    //printf("%s\r\n",(char*)buffer);
    cJSON_Delete(root);
    
    return nmemb; 
}

/*************************************************
* Function: AC_GetUploadFileInfo
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_GetUploadFileInfo(const char *bucketName, char *filename)
{
    cJSON *root = NULL;
    cJSON *fmt = NULL;
    char *out = NULL;
    int ret = 0;
    root=cJSON_CreateObject();
    cJSON_AddStringToObject(root,"bucket",bucketName);
    cJSON_AddStringToObject(root,"name",filename);
    cJSON_AddStringToObject(root,"scheme","https");
    cJSON_AddItemToObject(root, "acl", fmt=cJSON_CreateObject());
    cJSON_AddTrueToObject (fmt,"isPublicReadAllow");
    cJSON_AddTrueToObject (fmt,"isPublicWriteAllow");
    //cJSON_AddStringToObject(root,"metaData",g_struAcTokenInfo.chrefreshTokenExpire);
   // cJSON_AddStringToObject(root,"acl",g_struAcTokenInfo.chrefreshTokenExpire);
    
    out=cJSON_Print(root); 

    cJSON_Delete(root); 
    
    printf("UploadFileInfo Request:\r\n");
    printf("%s\r\n",out); 
    ret = AC_SendHttpRequest(AuthSchemaHttp,(const char *)out,"zc-blobstore/v1/uploadFileInfo",g_struAcTokenInfo.chAccessToken,(pFunWriteCallback)AC_GetUploadFileInfoCallback); 
    free(out);  /* Print to text, Delete the cJSON, print it, release the string. */
    return ret;
}

/*************************************************
* Function: AC_GetDownloadFileInfoCallback
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
static size_t AC_GetDownloadFileInfoCallback(void *buffer, size_t size, size_t nmemb, void *stream)
{
    // printf("%s\r\n",buffer);
    cJSON *root = NULL;
    cJSON *format = NULL;
    if (NULL == buffer)
    {
        printf("Get DownloadFileInfo Fail!!!\r\n");
        printf("no body\r\n");
        g_int32ErrorCode = INVLIADBODYFORMAT;
        return nmemb;
    }

    root = cJSON_Parse(buffer);
    if (NULL == root)
    {
        printf("Get DownloadFileInfo Fail!!!\r\n");
        printf("json parse error\r\n");
        g_int32ErrorCode = INVLIADBODYFORMAT;
        return nmemb;
    }

    if (NULL != format)
    {
        g_int32ErrorCode = format->valueint;
    }
    else
    {   

        strcpy(g_struAcDownloadInfo.chDownloadUrl,cJSON_GetObjectItem(root,"downloadUrl")->valuestring);
        strcpy(g_struAcDownloadInfo.chStoreType,cJSON_GetObjectItem(root,"storeType")->valuestring);    
        g_int32ErrorCode = CURLE_OK;
        printf("Get DownloadFileInfo OK!!!\r\n");
    }
    //printf("%s\r\n",(char*)buffer);
    cJSON_Delete(root);
    return nmemb; 
}

/*************************************************
* Function: AC_GetDownloadFileInfo
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_GetDownloadFileInfo(const char *bucketName,char *filename)
{
    cJSON *root = NULL;
    char *out = NULL;
    int ret = 0;
    
    root=cJSON_CreateObject(); 
    cJSON_AddStringToObject(root,"bucket",bucketName);
    cJSON_AddStringToObject(root,"name",filename);
    cJSON_AddStringToObject(root,"expireTime","3600");
    cJSON_AddStringToObject(root,"scheme","http");
    //cJSON_AddStringToObject(root,"metaData",g_struAcTokenInfo.chrefreshTokenExpire);
   // cJSON_AddStringToObject(root,"acl",g_struAcTokenInfo.chrefreshTokenExpire);
    
    out=cJSON_Print(root); 

    cJSON_Delete(root); 
    printf("DownloadFileInfo Request:\r\n");
    printf("%s\n",out); 
    ret = AC_SendHttpRequest(AuthSchemaHttp,(const char *)out,"zc-blobstore/v1/getDownloadUrl",g_struAcTokenInfo.chAccessToken,(pFunWriteCallback)AC_GetDownloadFileInfoCallback);     			
    free(out);  /* Print to text, Delete the cJSON, print it, release the string. */
    return ret;
}

/*************************************************
* Function: AC_CheckOtaFileInfoCallback
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
static size_t AC_CheckOtaFileInfoCallback(void *buffer, size_t size, size_t nmemb, void *stream)
{

    cJSON *root = NULL;
    size_t ret = 0;
    cJSON *format;
    cJSON *OtaFileMeta;
    int i = 0;
    
    if(NULL == buffer)
    {
        printf("no body\r\n");
        g_int32ErrorCode = INVLIADBODYFORMAT;
        return nmemb;
    }

    if(NULL == root)
    {
        g_int32ErrorCode = INVLIADBODYFORMAT;
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
        	g_int32ErrorCode = UPDATESTATUS_FILIENUMERROR;
            printf("Ota File num error\r\n");
            return nmemb;
        }
        g_struAcOtaFileInfo.IntFileNum = cJSON_GetArraySize(OtaFileMeta);
        if(g_struAcOtaFileInfo.IntFileNum > MAX_OTAFILENUM)
        {
            g_int32ErrorCode = UPDATESTATUS_NOTFILIEINFOR;
            printf("Ota File Info error\r\n");
            return nmemb;
        }
        printf("ote file num = %d\n",g_struAcOtaFileInfo.IntFileNum);
        g_struAcOtaFileInfo.IntStatus = cJSON_GetObjectItem(root,"status")->valueint;
        strcpy(g_struAcOtaFileInfo.chTargetVersion, cJSON_GetObjectItem(root,"targetVersion")->valuestring);                 
        g_struAcOtaFileInfo.IntOtaMode = cJSON_GetObjectItem(root,"otaMode")->valueint;
        strcpy(g_struAcOtaFileInfo.chUpgradeLog,cJSON_GetObjectItem(root,"upgradeLog")->valuestring);

        for(i=0; i<g_struAcOtaFileInfo.IntFileNum; i++)
        {

            strcpy(g_struAcOtaFileInfo.struFileInfo[i].chName,cJSON_GetObjectItem(cJSON_GetArrayItem(OtaFileMeta, i),"name")->valuestring);

            strcpy(g_struAcOtaFileInfo.struFileInfo[i].chDownloadUrl,cJSON_GetObjectItem(cJSON_GetArrayItem(OtaFileMeta, i),"downloadUrl")->valuestring);
            g_struAcOtaFileInfo.struFileInfo[i].IntFileType = cJSON_GetObjectItem(cJSON_GetArrayItem(OtaFileMeta, i),"type")->valueint;  
            g_struAcOtaFileInfo.struFileInfo[i].IntChecksum = cJSON_GetObjectItem(cJSON_GetArrayItem(OtaFileMeta, i),"checksum")->valueint;             
        } 
        printf("Get File Info OK!!!\r\n");
        g_int32ErrorCode = 0;
    }
    printf("%s\r\n",(char*)buffer);
    cJSON_Delete(root);

    return nmemb; 

}

/*************************************************
* Function: AC_CheckOtaFileInfo
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_CheckOtaFileInfo(int otaMode)
{
    cJSON *root = NULL;
    char *out = NULL;
    int ret = 0;
    
    root=cJSON_CreateObject(); 
    cJSON_AddStringToObject(root,"version",g_chModuleVersion);
    cJSON_AddStringToObject(root,"physicalDeviceId",g_chDeviceId);
    /*system update*/
    cJSON_AddNumberToObject(root,"otaType",otaMode);
    //cJSON_AddStringToObject(root,"metaData",g_struAcTokenInfo.chrefreshTokenExpire);
   // cJSON_AddStringToObject(root,"acl",g_struAcTokenInfo.chrefreshTokenExpire);
    
    out=cJSON_Print(root); 

    cJSON_Delete(root); 
    printf("OtaFileInfo Request:\r\n");
    printf("%s\r\n",out); 
    ret = AC_SendHttpRequest(AuthSchemaHttps,(const char *)out,"zc-ota/v1/checkUpdate",g_struAcTokenInfo.chAccessToken,(pFunWriteCallback)AC_CheckOtaFileInfoCallback); 
    free(out);  /* Print to text, Delete the cJSON, print it, release the string. */
    return ret;
}

/*************************************************
* Function: AC_OtaUpdateFileEnd
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_OtaUpdateFileEnd(int otaMode)
{
    cJSON *root = NULL;
    char *out = NULL;
    int ret = 0;
    
    root=cJSON_CreateObject(); 
    cJSON_AddStringToObject(root,"currentVersion",g_chModuleVersion);
    cJSON_AddStringToObject(root,"physicalDeviceId",g_chDeviceId);
    /*system update*/
    cJSON_AddNumberToObject(root,"otaType",otaMode);
    //cJSON_AddStringToObject(root,"metaData",g_struAcTokenInfo.chrefreshTokenExpire);
   // cJSON_AddStringToObject(root,"acl",g_struAcTokenInfo.chrefreshTokenExpire);
    
    out=cJSON_Print(root); 

    cJSON_Delete(root); 
    printf("OtaFileEnd Request:\r\n");
    printf("%s\r\n",out); 
    ret = AC_SendHttpRequest(AuthSchemaHttps,(const char *)out,"zc-ota/v1/otaMediaDone",g_struAcTokenInfo.chAccessToken,NULL); 
    free(out);  /* Print to text, Delete the cJSON, print it, release the string. */

    close(g_int32fd);
    //ret = system("/etc/init.d/ablecloud restart");
    return ret;
}

/*************************************************
* Function: AC_OtaUpdate
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_OtaUpdate(int otaMode, char *DonwloadOtaFilePath,AC_OtaFileInfo *DonwloadOtaFileInfo, int *FileNum, char *OtaDescription,char *OtaTargetVersion)
{
    int ret = 0;
    int i =0;
    char DownloadfileName[64] = {0};
    
    if((NULL==DonwloadOtaFilePath)||(NULL==DonwloadOtaFileInfo)||(NULL==FileNum)||(NULL==OtaDescription)||(NULL==OtaTargetVersion))
    {
    	printf("invliad param\r\n");
    	return -1;
    }

    ret = AC_TokenExpireProcess();
    if(ret != 0)
    {
    	return ret;
    }
    ret = AC_CheckOtaFileInfo(otaMode);
    if(ret == ACCESSTOKENEXPIRE)
    {
    	ret = AC_UpdateToken();
    	if(REFRESHTOKENEXPIRE==ret)
    	{
    		ret = AC_GetToken();
    		if(ret != 0)
    		{
    			return ret;
    		}
    	}
    	if(0== ret)
    	{
    		ret =  AC_CheckOtaFileInfo(otaMode);
    	}
    }
    
    if(ret != 0)
    {
        return ret;
    }

    for(i=0; i<g_struAcOtaFileInfo.IntFileNum;i++)
    {
        curl_msnprintf(DownloadfileName,64,"%s/%s",DonwloadOtaFilePath,g_struAcOtaFileInfo.struFileInfo[i].chName);
        ret = AC_GetFile(g_struAcOtaFileInfo.struFileInfo[i].chDownloadUrl,DownloadfileName,(pFunWriteCallback)AC_WriteFileCallback);

        if(ret != 0)
        {
            return ret;
        }
    }
    strcpy(OtaTargetVersion,g_struAcOtaFileInfo.chTargetVersion);
    strcpy(OtaDescription,g_struAcOtaFileInfo.chUpgradeLog);
    for(i = 0; i<g_struAcOtaFileInfo.IntFileNum;i++)
    {
        DonwloadOtaFileInfo[i] = g_struAcOtaFileInfo.struFileInfo[i];
    }
    *FileNum = g_struAcOtaFileInfo.IntFileNum;

    ret = AC_OtaUpdateFileEnd(otaMode);

    return ret;
}

/*************************************************
* Function: AC_ReadFileCallback
* Description: 
* Author: zw 
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
* Function: AC_AwsPutFile
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_AwsPutFile(char *file,char *url)
{
	CURL *curl;
	CURLcode res;
	FILE * hd_src ;
	struct stat file_info;
	int i  = 0;
	long httpCode;
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
     if(curl) 
     {
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
     		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
     		if (httpCode / 100 != 2) 
     		{
     			res= httpCode;
     		}
     		else
     		{
     			res = CURLE_OK;
                printf("UPloadFile OK!!!\r\n");
     		}
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
* Function: AC_QiniuPutFile
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_QiniuPutFile(const char *bucketName, char *pRemoteFileName,char *pLocalFilePath,char *uploadtoken)
{
    Qiniu_Client client;
    Qiniu_Error error;
    int ret = 0;
    char pRemoteFilePath[256];
    Qiniu_Global_Init(-1);                  /* 全局初始化函数，整个进程只需要调用一次 */
    Qiniu_Client_InitNoAuth(&client, 1024); /* HTTP客户端初始化。HTTP客户端是线程不安全的，不要在多个线程间共用 */
    
    curl_msnprintf(pRemoteFilePath,256,"%s/%s",bucketName,pRemoteFileName);
    error = Qiniu_Io_PutFile(&client, NULL, uploadtoken, pRemoteFilePath, pLocalFilePath, NULL);
    if (error.code != 200) 
    {
        ret = error.code;
    }
    else
    {
        printf("UPloadFile OK!!!\r\n");
        ret = CURLE_OK;
    }

    Qiniu_Client_Cleanup(&client);          /* 每个HTTP客户端使用完后释放 */
    Qiniu_Global_Cleanup();                 /* 全局清理函数，只需要在进程退出时调用一次 */
    return ret;
}

/*************************************************
* Function: AC_UploadFile
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_UploadFile(const char *bucketName, char *remotefilename, char *localfilepath)
{
    int ret = 0;

    if((NULL==bucketName)||(NULL==remotefilename)||(NULL==localfilepath))
    {
    	printf("invliad param\r\n");
    	return -1;
    }

    ret = AC_TokenExpireProcess();
    if(ret != 0)
    {
    	return ret;
    }
    ret = AC_GetUploadFileInfo(bucketName,remotefilename);

    if(ret == ACCESSTOKENEXPIRE)
    {
    	ret = AC_UpdateToken();
    	if(REFRESHTOKENEXPIRE==ret)
    	{
    		ret = AC_GetToken();
    		if(ret != 0)
    		{
    			return ret;
    		}
    	}
    	if(0== ret)
    	{
    		ret = AC_GetUploadFileInfo(bucketName,remotefilename);
    	}
    }
    

    if(ret != 0)
    {
        return ret;
    }
    if(!strcmp(g_struAcUploadInfo.chStoreType,"aws"))
    {
        ret = AC_AwsPutFile(localfilepath,g_struAcUploadInfo.chUploadToken);
    }
    else if(!strcmp(g_struAcUploadInfo.chStoreType,"qiniu"))
    {
        ret = AC_QiniuPutFile(bucketName,remotefilename,localfilepath,g_struAcUploadInfo.chUploadToken);
    }
    else
    {
        ret = -1;
    }
    return ret;
}

/*************************************************
* Function: AC_DownloadFile
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_DownloadFile(const char *bucketName,char *remotefilename,char *localfilepath)
{
	int ret = 0;

	if((NULL==bucketName)||(NULL==remotefilename)||(NULL==localfilepath))
    {
    	printf("invliad param\r\n");
    	return -1;
    }

	ret = AC_TokenExpireProcess();
	if(ret != 0)
	{
		return ret;
	}
	ret = AC_GetDownloadFileInfo(bucketName,remotefilename);
	if(ret == ACCESSTOKENEXPIRE)
	{
		ret = AC_UpdateToken();
		if(REFRESHTOKENEXPIRE==ret)
		{
			ret = AC_GetToken();
			if(ret != 0)
			{
				return ret;
			}
		}
		if(0== ret)
		{
			ret = AC_GetDownloadFileInfo(bucketName,remotefilename);
		}
	}
	

	if(ret != 0)
	{
		return ret;
	}
	ret = AC_GetFile(g_struAcDownloadInfo.chDownloadUrl,localfilepath,(pFunWriteCallback)AC_WriteFileCallback);
	return ret;
}

/*************************************************
* Function: AC_DeviceServiceInit
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
int AC_DeviceServiceInit(char *domain, char *subdomain, char *devid, char *version)
{
    CURL *curl;
    CURLcode res;
    char *tempspace = (char *)malloc(256);
    int ret = 0;
    
    if((NULL==domain)||(NULL==subdomain)||(NULL==devid)||(NULL==version))
    {
    	printf("invliad param\r\n");
    	return -1;
    }
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
    	printf("AC_ReadTokenInfo ok\r\n");
	    ret =  AC_TokenExpireProcess();
    }
    return ret; 
}

/*************************************************
* Function: main
* Description: 
* Author: zw 
* Returns: 
* Parameter: 
* History:
*************************************************/
void main()
{

    int ret =0;
    AC_OtaFileInfo fileInfo[MAX_OTAFILENUM];
    char otadescription[64];
    int otamode = 2;//system update
    int otadowloadfilenum = 0;
    int  i= 0;
    char deviceid[]="6666666666666666";


    ret = AC_DeviceServiceInit(MAJOR_DOMAIN,SUB_DOMAIN,deviceid,DEVICE_VERSION); 

    if(0 != ret)
    {
        printf("AC_Init errror=%d\n",ret);
    }
    else
    {
        ret = AC_UploadFile("test","test2","cJSON.c");
       ret =  AC_DownloadFile("test","test2","test.c");
    }
    printf("ret = %d\r\n",ret);
    //getchar();
   //mbedtls_rsa_self_test2(1);
    //AC_RsaTest(1);

}