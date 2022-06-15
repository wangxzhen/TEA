#include "TEA.h"

#include "string.h"

/**
 * @brief 加密函数
 * 
 * @param v 
 * @param k 
 * @return * void 
 */
void encrypt (uint32_t* v, uint32_t* k) {  
    uint32_t v0=v[0], v1=v[1], sum=0, i;           /* set up */  
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */  
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */  
    for (i=0; i < 32; i++) {                       /* basic cycle start */  
        sum += delta;  
        v0 += ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);  
        v1 += ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);  
    }                                              /* end cycle */  
    v[0]=v0; v[1]=v1;  
}

/**
 * @brief 解密函数
 * 
 * @param v 
 * @param k 
 * @return * void 
 */
void decrypt (uint32_t* v, uint32_t* k) {  
    uint32_t v0=v[0], v1=v[1], sum=0xC6EF3720, i;  /* set up */  
    uint32_t delta=0x9e3779b9;                     /* a key schedule constant */  
    uint32_t k0=k[0], k1=k[1], k2=k[2], k3=k[3];   /* cache key */  
    for (i=0; i<32; i++) {                         /* basic cycle start */  
        v1 -= ((v0<<4) + k2) ^ (v0 + sum) ^ ((v0>>5) + k3);  
        v0 -= ((v1<<4) + k0) ^ (v1 + sum) ^ ((v1>>5) + k1);  
        sum -= delta;  
    }                                              /* end cycle */  
    v[0]=v0; v[1]=v1;  
}

/**
 * @brief TEA加解密
 * 
 * @param Data_In 
 * @param Len_In 
 * @param Key 
 * @param Data_Out 
 * @param Len_Out 
 * @param Method : 加密/解密
 */
void TEA_Encrypt_Decrypt(void* Data_In, uint32_t Len_In, void* Key, void* Data_Out, uint32_t* Len_Out, void(*Method)(uint32_t* V, uint32_t* K))
{
    uint32_t Len = (Len_In%8) ? (Len_In/8+1)<<3 : Len_In;   // resize input data len
    uint32_t Loop = Len/8, i=0;
    uint32_t enData[2]={0}, enKey[4]={0};

    char* inDataBuf = (char*)Data_Out;
    char* outDataBuf = (char*)Data_Out;
    char* inKey = (char*)Key;

    memset(inDataBuf, 0, Len);                  // file zero
    memcpy(inDataBuf, Data_In, Len_In);         // copy input data

    if(strlen(inKey)!=16)
        inKey = "0000000000000000";
    memcpy(enKey, inKey, strlen(inKey));        // copy input key

    for(i=0; i<Loop; i++)
    {
        memcpy(enData, &inDataBuf[i*8], 8);     
        Method(enData, enKey);                  // encrypt or ecrypt
        memcpy(&outDataBuf[i*8], enData, 8);    // out encrypt or ecrypt result
    }
    *Len_Out = Len;
}

/**
 * @brief TEA加密
 * 
 * @param Data_In 待加密数据
 * @param Len_In 待加密数据长度
 * @param Key 加密密钥 [len: 16 byte]
 * @param Data_Out 加密后数据缓冲区 [size >= Len_In+8 ]
 * @param Len_Out 加密后数据长度
 */
void TEA_Encrypt(void* Data_In, uint32_t Len_In, void* Key, void* Data_Out, uint32_t* Len_Out)
{
    TEA_Encrypt_Decrypt(Data_In, Len_In, Key, Data_Out, Len_Out, encrypt);
}

/**
 * @brief TEA解密
 * 
 * @param Data_In 待解密数据
 * @param Len_In 待解密数据长度
 * @param Key 解密密钥 [len: 16 byte]
 * @param Data_Out 解密后数据缓冲区 [size >= Len_In+8 ]
 * @param Len_Out 解密后数据长度
 */
void TEA_Decrypt(void* Data_In, uint32_t Len_In, void* Key, void* Data_Out, uint32_t* Len_Out)
{
    TEA_Encrypt_Decrypt(Data_In, Len_In, Key, Data_Out, Len_Out, decrypt);
}

/* @example
int main(void)
{
	char* src = "{\"id\":432,\"type\":1,\"start_time\":1654828015,\"end_time\":1657468799,\"expire_time\":1657468799}";
    char* key = "XUWLwVUBeulupdUB";
    printf("src: %s\nkey: %s\n", src, key);

	uint8_t EnBuf[128]={0}, DeBuf[128]={0};
	uint32_t EnLen=0, DeLen=0;

	TEA_Encrypt(src, strlen(src), key, EnBuf, &EnLen);
	printf("TEA_Encrypt, Len[%d] : %s\n", EnLen, EnBuf);

	TEA_Decrypt(EnBuf, EnLen, key, DeBuf, &DeLen);
	printf("TEA_Decrypt, Len[%d] : %s\n", DeLen, DeBuf);
}
*/