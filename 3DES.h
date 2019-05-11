#ifndef __3DES_H_
#define __3DES_H_

#define ERR_DES_INVALID_INPUT_LENGTH    -1
/*
 * 3DES decrypt
 */
unsigned int des3_cbc_decrypt(unsigned char *pout, unsigned char *pdata, unsigned int nlen, unsigned char *pkey, unsigned int klen, unsigned char *piv);

/*
 * 3DES encrypt
 */
unsigned int des3_cbc_encrypt(unsigned char *pout, unsigned char *pdata, unsigned int nlen, unsigned char *pkey, unsigned int klen, unsigned char *piv);

/*
 * 3DES-ECB buffer encryption API
 */

unsigned int des3_ecb_encrypt(unsigned char *pout, unsigned char *pdata, unsigned int nlen, unsigned char *pkey, unsigned int klen);


/*
 * 3DES-ECB buffer decryption API
 */
unsigned int des3_ecb_decrypt(unsigned char *pout, unsigned char *pdata, unsigned int nlen, unsigned char *pkey, unsigned int klen);

#endif
