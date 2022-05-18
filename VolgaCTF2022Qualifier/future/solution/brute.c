#include <stdio.h>
#include <stdlib.h>
#include <string.h>

unsigned char ida_chars[] =
{
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 
  0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 
  0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 
  0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 
  0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 
  0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 
  0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 
  0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 
  0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 
  0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 
  0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 
  0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 
  0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 
  0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 
  0x8C, 0x8D, 0x8E, 0x8F, 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 
  0x96, 0x97, 0x98, 0x99, 0x9A, 0x9B, 0x9C, 0x9D, 0x9E, 0x9F, 
  0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9, 
  0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0xAF, 0xB0, 0xB1, 0xB2, 0xB3, 
  0xB4, 0xB5, 0xB6, 0xB7, 0xB8, 0xB9, 0xBA, 0xBB, 0xBC, 0xBD, 
  0xBE, 0xBF, 0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 
  0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD, 0xCE, 0xCF, 0xD0, 0xD1, 
  0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8, 0xD9, 0xDA, 0xDB, 
  0xDC, 0xDD, 0xDE, 0xDF, 0xE0, 0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 
  0xE6, 0xE7, 0xE8, 0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 
  0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 
  0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
};

unsigned char WORDS[256];


#define __int64 long
#define _BYTE unsigned char
#define __int8 char
#define LOBYTE(x)  (*(unsigned char *) &(x))

unsigned __int64 decryptElf(char *encryptedBytes, size_t ELF_SIZE, char *bufRand, size_t bufRandSz, char *ELF_buf)
{
  __int64 i; // rsi
  char *bufRandCopy_; // rcx
  char *WORDS_BYTE_PTR; // rdx
  int sum; // edi
  char wordsChar; // si
  char bufRandChar; // al
  char tmp; // r11
  __int64 byte_index; // rsi
  int a; // er11
  int b; // edi
  char words_charA; // bl
  char words_charB; // al
  _BYTE bufRandCopy[256]; // [rsp+0h] [rbp-218h] BYREF
  //char WORDS[256]; // [rsp+100h] [rbp-118h] BYREF
  char v23; // [rsp+200h] [rbp-18h] BYREF
  unsigned __int64 canary; // [rsp+208h] [rbp-10h]

  i = 0LL;
  //canary = __readfsqword(40u);
  bufRandCopy_ = bufRandCopy;
  // *(__m128i *)WORDS = _mm_load_si128((const __m128i *)byte_555555556030);
  // *(__m128i *)&WORDS[16] = _mm_load_si128((const __m128i *)&byte_555555556030[16]);
  // *(__m128i *)&WORDS[32] = _mm_load_si128((const __m128i *)&byte_555555556030[32]);
  // *(__m128i *)&WORDS[48] = _mm_load_si128((const __m128i *)&byte_555555556030[48]);
  // *(__m128i *)&WORDS[64] = _mm_load_si128((const __m128i *)&byte_555555556030[64]);
  // *(__m128i *)&WORDS[80] = _mm_load_si128((const __m128i *)&byte_555555556030[80]);
  // *(__m128i *)&WORDS[96] = _mm_load_si128((const __m128i *)&byte_555555556030[96]);
  // *(__m128i *)&WORDS[112] = _mm_load_si128((const __m128i *)&byte_555555556030[112]);
  // *(__m128i *)&WORDS[128] = _mm_load_si128((const __m128i *)&byte_555555556030[128]);
  // *(__m128i *)&WORDS[144] = _mm_load_si128((const __m128i *)&byte_555555556030[144]);
  // *(__m128i *)&WORDS[160] = _mm_load_si128((const __m128i *)&byte_555555556030[160]);
  // *(__m128i *)&WORDS[176] = _mm_load_si128((const __m128i *)&byte_555555556030[176]);
  // *(__m128i *)&WORDS[192] = _mm_load_si128((const __m128i *)&byte_555555556030[192]);
  // *(__m128i *)&WORDS[208] = _mm_load_si128((const __m128i *)&byte_555555556030[208]);
  // *(__m128i *)&WORDS[224] = _mm_load_si128((const __m128i *)&byte_555555556030[224]);
  // *(__m128i *)&WORDS[240] = _mm_load_si128((const __m128i *)&byte_555555556030[240]);
  do
  {
    bufRandCopy[i] = bufRand[i % (__int64)bufRandSz];//  just copies bufRand
    ++i;
  }
  while ( i != 256 );



  WORDS_BYTE_PTR = WORDS;
  LOBYTE(sum) = 0;
  do
  {
    wordsChar = *WORDS_BYTE_PTR;
    bufRandChar = *bufRandCopy_;
    ++WORDS_BYTE_PTR;
    ++bufRandCopy_;
    sum = (unsigned __int8)(sum + wordsChar + bufRandChar);



    tmp = WORDS[sum];
    WORDS[sum] = wordsChar;
    *(WORDS_BYTE_PTR - 1) = tmp;
  }
  while ( &WORDS[256] != WORDS_BYTE_PTR );
  //while ( &v23 != WORDS_BYTE_PTR );             // &v23 - first byte after WORDS
                                                // 


  if ( (__int64)ELF_SIZE > 0 )
  {
    byte_index = 0LL;
    LOBYTE(a) = 0;
    LOBYTE(b) = 0;
    do
    {

      a = (unsigned __int8)(a + 1);

      words_charA = WORDS[a];


      b = (unsigned __int8)(words_charA + b);


      words_charB = WORDS[b];


      WORDS[b] = words_charA;
      WORDS[a] = words_charB;



      ELF_buf[byte_index] = encryptedBytes[byte_index] ^ WORDS[(unsigned __int8)(WORDS[b] + words_charB)];
      ++byte_index;
    }
    while ( ELF_SIZE != byte_index );
  }
  //return canary - __readfsqword(0x28u);
	return 0x539;
}



int main()
{
	
	unsigned char ELF_ENCRYPTED_MAGICK[]={0x15, 0x88, 0x8C, 0x0E};
	unsigned char ELF_MAGICK[]={0x7f, 0x45, 0x4c, 0x46};
	unsigned char ELF_DECRYPTED[4];
	
	
	unsigned seed=time(0);
	//unsigned seed=0x000067C1BBFC; //1740749820
	unsigned char bufRand[256];
	
	
	for (;;)
	{
		memcpy(WORDS,ida_chars,256);
		memset(ELF_DECRYPTED,0,4);
		
		
		srand(seed);
		
		printf("Trying seed: %u\n",seed);
		
		for (int i=0;i<256;++i)
			bufRand[i]=rand()%256;
		
		
		
		decryptElf(ELF_ENCRYPTED_MAGICK,4,bufRand,256,ELF_DECRYPTED);
	
		if (memcmp(ELF_MAGICK,ELF_DECRYPTED,4)==0)
		{
			printf("Found seed: %u\n",seed);
			break;
		}
		
		++seed;
	}
	
	return 0;
}





