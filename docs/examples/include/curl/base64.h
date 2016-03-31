#ifndef BASE64_H
#define BASE64_H

unsigned char * base64_encode(const unsigned char *src, int len,int *out_len);
unsigned char * base64_decode(const unsigned char *src, int len,int *out_len);

#endif
