#ifndef _TEA_H_
#define _TEA_H_

#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif

// TEA加密
void TEA_Encrypt(void* Data_In, uint32_t Len_In, void* Key, void* Data_Out, uint32_t* Len_Out);
// TEA解密
void TEA_Decrypt(void* Data_In, uint32_t Len_In, void* Key, void* Data_Out, uint32_t* Len_Out);

#ifdef __cplusplus
}
#endif

#endif // !_TEA_H_