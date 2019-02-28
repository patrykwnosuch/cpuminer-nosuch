#include "cpuminer-config.h"
#include "miner.h"
#include "algo-gate-api.h"
//#include "amdlibm/include/amdlibm.h"

#include <string.h>
#include <stdint.h>

#include <inttypes.h>

#include "algo/blake/sph_blake.h"
#include "algo/bmw/sph_bmw.h"
#include "algo/groestl/sph_groestl.h"
#include "algo/jh/sph_jh.h"
#include "algo/keccak/sph_keccak.h"
#include "algo/skein/sph_skein.h"
#include "algo/luffa/sph_luffa.h"
#include "algo/cubehash/sph_cubehash.h"
#include "algo/shavite/sph_shavite.h"
#include "algo/simd/sph_simd.h"
#include "algo/echo/sph_echo.h"

#include "algo/binarium_hash_v1/hashing/streebog/stribog.h"
#include "algo/binarium_hash_v1/hashing/whirlpool/whirlpool.h"

#include "algo/binarium_hash_v1/encryption/gost2015_kuznechik/libgost15/libgost15.h"
#include "algo/binarium_hash_v1/encryption/three_fish/libskein_skein.h"
//#include "openssl/camellia.h"
#include "algo/binarium_hash_v1/open_ssl/camellia/camellia.h"

#include "algo/binarium_hash_v1/encryption/salsa20/ecrypt-sync.h"

#ifndef NO_AES_NI
#include "algo/groestl/aes_ni/hash-groestl.h"
#include "algo/echo/aes_ni/hash_api.h"
#endif

#include "algo/luffa/luffa_for_sse2.h"
#include "algo/cubehash/sse2/cubehash_sse2.h"
#include "algo/simd/nist.h"
#include "algo/blake/sse2/blake.c"  
#include "algo/keccak/sse2/keccak.c"
#include "algo/bmw/sse2/bmw.c"
#include "algo/skein/sse2/skein.c"
#include "algo/jh/sse2/jh_sse2_opt64.h"



#define I_ALGORITHM_RECONFIGURATION_TIME_PERIOD_IN_SECONDS 604800    // 600

#define I_PRIME_NUMBER_FOR_MEMORY_HARD_HASHING 3571

#define I_AMOUNT_OF_BYTES_FOR_MEMORY_HARD_FUNCTION 32 * 1024
#define I_MEMORY_BLOCK_SIZE_TO_ENCRYPTION_COMPUTATIONS_RATIO 1

const uint32_t GenesisBlock_nTime = 1516957200;

typedef void ( * TCryptographyFunction ) ( const void *, const uint32_t, const void *, void * ); // uint512

#define I_AMOUNT_OF_INTERMEDIATE_HASH_FUNCTIONS 14
#define I_AMOUNT_OF_INTERMEDIATE_ENCRYPTION_FUNCTIONS 3

TCryptographyFunction aIntermediateHashFunctions [ I_AMOUNT_OF_INTERMEDIATE_HASH_FUNCTIONS ];
TCryptographyFunction aIntermediateEncryptionFunctions [ I_AMOUNT_OF_INTERMEDIATE_ENCRYPTION_FUNCTIONS ];



//---Hashing.-------------------------------------------------------------
void IntermediateHashFunction_Blake ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    sph_blake512_context     ctx_blake;

    sph_blake512_init(&ctx_blake);
    sph_blake512 (&ctx_blake, _pData, _iDataSize);
    sph_blake512_close(&ctx_blake, _pResult);
}

void IntermediateHashFunction_BMW ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    sph_bmw512_context       ctx_bmw;

    sph_bmw512_init(&ctx_bmw);
    sph_bmw512 (&ctx_bmw, _pData, _iDataSize);
    sph_bmw512_close(&ctx_bmw, _pResult);
}

void IntermediateHashFunction_Groestl ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    sph_groestl512_context   ctx_groestl;

    sph_groestl512_init(&ctx_groestl);
    sph_groestl512 (&ctx_groestl, _pData, _iDataSize);
    sph_groestl512_close(&ctx_groestl, _pResult);
}

void IntermediateHashFunction_JH ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    sph_jh512_context        ctx_jh;

    sph_jh512_init(&ctx_jh);
    sph_jh512 (&ctx_jh, _pData, _iDataSize);
    sph_jh512_close(&ctx_jh, _pResult);
}

void IntermediateHashFunction_Keccak ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    sph_keccak512_context    ctx_keccak;

    sph_keccak512_init(&ctx_keccak);
    sph_keccak512 (&ctx_keccak, _pData, _iDataSize);
    sph_keccak512_close(&ctx_keccak, _pResult);
}

void IntermediateHashFunction_Skein ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    sph_skein512_context     ctx_skein;

    sph_skein512_init(&ctx_skein);
    sph_skein512 (&ctx_skein, _pData, _iDataSize);
    sph_skein512_close(&ctx_skein, _pResult);
}

void IntermediateHashFunction_Luffa ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    sph_luffa512_context     ctx_luffa;

    sph_luffa512_init(&ctx_luffa);
    sph_luffa512 (&ctx_luffa, _pData, _iDataSize);
    sph_luffa512_close(&ctx_luffa, _pResult);
}

void IntermediateHashFunction_Cubehash ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    sph_cubehash512_context  ctx_cubehash;

    sph_cubehash512_init(&ctx_cubehash);
    sph_cubehash512 (&ctx_cubehash, _pData, _iDataSize);
    sph_cubehash512_close(&ctx_cubehash, _pResult);
}

void IntermediateHashFunction_Shavite ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    sph_shavite512_context   ctx_shavite;

    sph_shavite512_init(&ctx_shavite);
    sph_shavite512(&ctx_shavite, _pData, _iDataSize);
    sph_shavite512_close(&ctx_shavite, _pResult);
}

void IntermediateHashFunction_Simd ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    sph_simd512_context      ctx_simd;

    sph_simd512_init(&ctx_simd);
    sph_simd512 (&ctx_simd, _pData, _iDataSize);
    sph_simd512_close(&ctx_simd, _pResult);
}

void IntermediateHashFunction_Echo ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    sph_echo512_context      ctx_echo;

    sph_echo512_init(&ctx_echo);
    sph_echo512 (&ctx_echo, _pData, _iDataSize);
    sph_echo512_close(&ctx_echo, _pResult);
}

void IntermediateHashFunction_GOST_2012_Streebog ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    hash_512 ( ( const unsigned char * ) _pData, _iDataSize, ( unsigned char * ) _pResult );
}

void IntermediateHashFunction_Whirlpool ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    whirlpool_ctx            structureWhirlpoolContext;

    rhash_whirlpool_init ( & structureWhirlpoolContext );
    rhash_whirlpool_update ( & structureWhirlpoolContext, ( const unsigned char * ) _pData, _iDataSize); 
    rhash_whirlpool_final ( & structureWhirlpoolContext, ( unsigned char * ) _pResult);
}

/*inline uint512 IntermediateHashFunction_SWIFFT ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    HashKey key ALIGN;
    HashState state ALIGN;
    SWIFFT_HashData data ALIGN;

    SwiFFT_initState ( state );
    SwiFFT_readKey ( ( const unsigned char * ) _pKey, & key );    
    SwiFFT_readData ( data, ( const unsigned char * ) _pData );
    SwiFFT ( key, state, data );

    memcpy ( _pResult, state, 64 );

    //SwiFFT_printState ( state );
    //SwiFFT_printKey ( key );
    //SwiFFT_printData ( data );
}*/

//---Encryption.----------------------------------------------------------------------
void IntermediateEncryptionFunction_GOST_2015_Kuznechik ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    /*char block_str [ 129 ];
    //char hash_str [ 129 ];
    char roundkeys_str [ 401 ];

    //uint32_t hash [ 1 ] [ 16 ];

    //uint64_t iIndex = GetUint64IndexFrom512BitsKey ( _pKey, 0 );
    //iIndex = iIndex % chainActive.Height ();

    //memcpy ( hash [ 0 ], _pData, 64 );

    bin2hex(roundkeys_str, (unsigned char *) _pData, 200 );
    applog ( LOG_DEBUG, "DEBUG: IntermediateEncryptionFunction_GOST_2015_Kuznechik () : roundkeys_str : %s.", roundkeys_str );

    bin2hex(block_str, (unsigned char *) _pResult, 64 );
    applog ( LOG_DEBUG, "DEBUG: IntermediateEncryptionFunction_GOST_2015_Kuznechik () : _pResult : %s.", block_str );

    bin2hex(block_str, (unsigned char *) _pKey, 64 );
    applog ( LOG_DEBUG, "DEBUG: IntermediateEncryptionFunction_GOST_2015_Kuznechik () : _pKey : %s.", block_str );*/
    encryptBlockWithGost15 ( _pKey, ( ( unsigned char * ) _pResult ) );           // _pKey
    /*bin2hex(block_str, (unsigned char *) _pResult, 64 );
    applog ( LOG_DEBUG, "DEBUG: IntermediateEncryptionFunction_GOST_2015_Kuznechik () : _pResult : %s.", block_str );

    bin2hex(block_str, (unsigned char *) _pData, 64 );
    applog ( LOG_DEBUG, "DEBUG: IntermediateEncryptionFunction_GOST_2015_Kuznechik () : _pData : %s.", block_str );*/
    encryptBlockWithGost15 ( _pData, ( ( unsigned char * ) _pResult + 16 ) );     // _pData
    /*bin2hex(block_str, (unsigned char *) _pResult, 64 );
    applog ( LOG_DEBUG, "DEBUG: IntermediateEncryptionFunction_GOST_2015_Kuznechik () : _pResult : %s.", block_str );*/

    /*decryptBlockWithGost15 ( _pData, ( ( unsigned char * ) _pResult + 16 ) );
    bin2hex(block_str, (unsigned char *) _pResult, 64 );
    applog ( LOG_DEBUG, "DEBUG: IntermediateEncryptionFunction_GOST_2015_Kuznechik () : _pResult decrypted : %s.", block_str );*/

    /*bin2hex(block_str, (unsigned char *) _pKey, 64 );
    applog ( LOG_DEBUG, "DEBUG: IntermediateEncryptionFunction_GOST_2015_Kuznechik () : _pKey : %s.", block_str );*/
    encryptBlockWithGost15 ( _pKey, ( ( unsigned char * ) _pResult + 32 ) );      // _pKey
    /*bin2hex(block_str, (unsigned char *) _pResult, 64 );
    applog ( LOG_DEBUG, "DEBUG: IntermediateEncryptionFunction_GOST_2015_Kuznechik () : _pResult : %s.", block_str );

    bin2hex(block_str, (unsigned char *) _pData, 64 );
    applog ( LOG_DEBUG, "DEBUG: IntermediateEncryptionFunction_GOST_2015_Kuznechik () : _pData : %s.", block_str );*/
    encryptBlockWithGost15 ( _pData, ( ( unsigned char * ) _pResult + 48 ) );     // _pData
    //bin2hex(block_str, (unsigned char *) _pResult, 64 );
    //applog ( LOG_DEBUG, "DEBUG: IntermediateEncryptionFunction_GOST_2015_Kuznechik () : _pResult : %s.", block_str );
}

void IntermediateEncryptionFunction_ThreeFish ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    char T[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        
    // Result, Key, Text.
    libskein_threefish_encrypt( ( char * ) _pResult, ( const char * ) _pKey, T, ( const char * ) _pData, 64, 512);
}

void IntermediateEncryptionFunction_Camellia ( const void * _pData, const uint32_t _iDataSize, const void * _pKey, void * _pResult ) {
    CAMELLIA_KEY stKey;
    Camellia_set_key ( ( const unsigned char * ) _pKey, 256, & stKey ); // userKey    
    Camellia_encrypt ( ( const unsigned char * ) _pData, ( unsigned char * ) _pResult, & stKey );        // in, out, key 
}



inline void HashGenerator_Init () {
    aIntermediateHashFunctions [ 0 ]        = & IntermediateHashFunction_Blake;
    aIntermediateHashFunctions [ 1 ]        = & IntermediateHashFunction_BMW;
    aIntermediateHashFunctions [ 2 ]        = & IntermediateHashFunction_Groestl;
    aIntermediateHashFunctions [ 3 ]        = & IntermediateHashFunction_JH;
    aIntermediateHashFunctions [ 4 ]        = & IntermediateHashFunction_Keccak;
    aIntermediateHashFunctions [ 5 ]        = & IntermediateHashFunction_Skein;
    aIntermediateHashFunctions [ 6 ]        = & IntermediateHashFunction_Luffa;
    aIntermediateHashFunctions [ 7 ]        = & IntermediateHashFunction_Cubehash;
    aIntermediateHashFunctions [ 8 ]        = & IntermediateHashFunction_Shavite;
    aIntermediateHashFunctions [ 9 ]        = & IntermediateHashFunction_Simd;
    aIntermediateHashFunctions [ 10 ]       = & IntermediateHashFunction_Echo;
    aIntermediateHashFunctions [ 11 ]       = & IntermediateHashFunction_GOST_2012_Streebog;
    aIntermediateHashFunctions [ 12 ]       = & IntermediateHashFunction_Whirlpool;
    //aIntermediateHashFunctions [ 13 ]       = & IntermediateHashFunction_SWIFFT;
    aIntermediateHashFunctions [ 13 ]       = & IntermediateHashFunction_GOST_2012_Streebog;

    aIntermediateEncryptionFunctions [ 0 ]         = & IntermediateEncryptionFunction_GOST_2015_Kuznechik;
    aIntermediateEncryptionFunctions [ 1 ]         = & IntermediateEncryptionFunction_ThreeFish;
    aIntermediateEncryptionFunctions [ 2 ]         = & IntermediateEncryptionFunction_Camellia;
}



inline uint64_t GetUint64IndexFrom512BitsKey ( const unsigned char * _pKey, int pos ) {
    //const uint8_t* ptr = ( const uint8_t * ) _pKey + pos * 8;
    //return ((uint64_t)ptr[0]) | \
           ((uint64_t)ptr[1]) << 8 | \
           ((uint64_t)ptr[2]) << 16 | \
           ((uint64_t)ptr[3]) << 24 | \
           ((uint64_t)ptr[4]) << 32 | \
           ((uint64_t)ptr[5]) << 40 | \
           ((uint64_t)ptr[6]) << 48 | \
           ((uint64_t)ptr[7]) << 56;

    uint64_t * pAdress = ( uint64_t * ) ( _pKey + pos );
    return pAdress [ 0 ] ^ pAdress [ 1 ] ^ pAdress [ 2 ] ^ pAdress [ 3 ] ^
           pAdress [ 4 ] ^ pAdress [ 5 ] ^ pAdress [ 6 ] ^ pAdress [ 7 ];

}

uint1024_XOROperator ( const char * _pDestinationData, const uint32_t _iDestinationOffsetInBytes, const unsigned char * _pData ) {
    uint32_t i;

    uint64_t * pDestinationNumbers = ( uint64_t * ) ( _pDestinationData + _iDestinationOffsetInBytes );
    uint64_t * pSourceNumbers = ( uint64_t * ) _pData;

    for ( i = 0; i < 512 / 8 / 8; i ++ ) { // 8 bits in byte and 8 bytes in uint64_t.
        //fprintf(stdout, "uint512.XOROperator () : %i .\n", i * 8 );

        /** ( ( uint64_t * ) ( begin () + _iDestinationOffsetInBytes + i * 8 ) ) = 
            * ( ( uint64_t * ) ( begin () + _iDestinationOffsetInBytes + i * 8 ) ) ^
            * ( ( uint64_t * ) ( _pData + i * 8 ) );*/

        pDestinationNumbers [ i ] = pDestinationNumbers [ i ] ^ pSourceNumbers [ i ];

    } //-for

}



typedef struct {
    hashState_luffa         luffa;
    cubehashParam           cube;
    hashState_sd            simd;
    sph_shavite512_context  shavite;
#ifdef NO_AES_NI
    sph_groestl512_context  groestl;
    sph_echo512_context     echo;
#else
    hashState_echo          echo;
    hashState_groestl       groestl;
#endif
} Binarium_hash_v1_ctx_holder;

Binarium_hash_v1_ctx_holder Binarium_hash_v1_ctx;

void init_Binarium_hash_v1_ctx()
{
     init_luffa( &Binarium_hash_v1_ctx.luffa, 512 );
     cubehashInit( &Binarium_hash_v1_ctx.cube, 512, 16, 32 );
     sph_shavite512_init( &Binarium_hash_v1_ctx.shavite );
     init_sd( &Binarium_hash_v1_ctx.simd, 512 );
#ifdef NO_AES_NI
     sph_groestl512_init( &Binarium_hash_v1_ctx.groestl );
     sph_echo512_init( &Binarium_hash_v1_ctx.echo );
#else
     init_echo( &Binarium_hash_v1_ctx.echo, 512 );
     init_groestl( &Binarium_hash_v1_ctx.groestl, 64 );
#endif
}



void Binarium_hash_v1_hash_Implementation ( void *state, const void *input, uint32_t len, uint32_t _iTimeFromGenesisBlock )
{
    uint32_t * p_nBits = ( input + 4 + 32 + 32 + 4 );

    uint32_t hash [ 11 ] [ 16 ];
    uint32_t uint512AdditionalHash [ 16 ];
    uint32_t uint1024CombinedHashes [ 32 ];

    uint64_t iIndexOfBlcok;
    uint64_t iWeekNumber;
    uint64_t iIndexFromWeekChangeBlock;
    uint64_t iIndex;

    uint32_t i = 0;
    uint32_t j = 0;

    char sBlockData [ 161 ];
    char hash_str[129];
    char hash_1024_str[257];



    // Important!
    memset ( hash, 0, sizeof(hash) ); 



    //applog ( LOG_DEBUG, "DEBUG: p_nBits : %i.", * p_nBits );

    //bin2hex ( sBlockData, (unsigned char *) input, 80 );
    //applog ( LOG_DEBUG, "DEBUG: Binarium_hash_v1_hash_Implementation () : sBlockData : %s.", sBlockData );

    // blake512
    aIntermediateHashFunctions [ 0 ] ( input, len, NULL, hash [ 0 ] );
    //bin2hex(hash_str, (unsigned char *)hash [ 0 ], 64);
    //applog ( LOG_DEBUG, "DEBUG: Binarium_hash_v1_hash_Implementation () : blake512 : %s.", hash_str );

    // bmw512
    aIntermediateHashFunctions [ 1 ] ( hash [ 0 ], 64, NULL, uint512AdditionalHash );
    //bin2hex(hash_str, (unsigned char *) uint512AdditionalHash, 64);
    //applog ( LOG_DEBUG, "DEBUG: Binarium_hash_v1_hash_Implementation () : bmw512 : %s.", hash_str );

    iWeekNumber = _iTimeFromGenesisBlock / I_ALGORITHM_RECONFIGURATION_TIME_PERIOD_IN_SECONDS * I_ALGORITHM_RECONFIGURATION_TIME_PERIOD_IN_SECONDS;
    iIndex = ( iWeekNumber + * p_nBits ) % I_AMOUNT_OF_INTERMEDIATE_HASH_FUNCTIONS;
    aIntermediateHashFunctions [ iIndex ] ( uint512AdditionalHash, 64, NULL, hash [ 1 ] );
    //bin2hex(hash_str, (unsigned char *)hash [ 1 ], 64);
    //applog ( LOG_DEBUG, "DEBUG: Binarium_hash_v1_hash_Implementation () : aIntermediateHashFunctions 1 : %s.", hash_str );

    // groestl512
    aIntermediateHashFunctions [ 2 ] ( hash [ 1 ], 64, NULL, hash [ 2 ] );
    //bin2hex(hash_str, (unsigned char *)hash [ 2 ], 64);
    //applog ( LOG_DEBUG, "DEBUG: Binarium_hash_v1_hash_Implementation () : groestl512 : %s.", hash_str );

    // skein512
    for ( i = 0; i < 32; i ++ )
        uint1024CombinedHashes [ i ] = 0;
    //aIntermediateHashFunctions [ 5 ] ( hash [ 2 ], 64, NULL, uint1024CombinedHashes + 64 );
    aIntermediateHashFunctions [ 5 ] ( hash [ 2 ], 64, NULL, ( (unsigned char *) uint1024CombinedHashes + 64 ) );
    //aIntermediateHashFunctions [ 5 ] ( hash [ 2 ], 64, NULL, hash [ 3 ] );
    //bin2hex ( hash_1024_str, ( unsigned char * ) uint1024CombinedHashes, 128 );
    //applog ( LOG_DEBUG, "DEBUG: Binarium_hash_v1_hash_Implementation () : skein512 : %s.", hash_1024_str );
    //bin2hex(hash_str, (unsigned char *)hash [ 3 ], 64);
    //bin2hex(hash_1024_str, (unsigned char *)hash [ 3 ], 64);
    //applog ( LOG_DEBUG, "DEBUG: Binarium_hash_v1_hash_Implementation () : skein512 : %s.", hash_1024_str );

    //-Streebog.--------------------------------------
    // jh512    

    aIntermediateHashFunctions [ 3 ] ( ( ( unsigned char * ) uint1024CombinedHashes + 64 ), 64, NULL, uint1024CombinedHashes );
    //bin2hex(hash_1024_str, (unsigned char *)uint1024CombinedHashes, 128);
    //applog ( LOG_DEBUG, "DEBUG: Binarium_hash_v1_hash_Implementation () : jh512 : %s.", hash_1024_str );



    ECRYPT_ctx structECRYPT_ctx;

    unsigned char aMemoryArea [ I_AMOUNT_OF_BYTES_FOR_MEMORY_HARD_FUNCTION ];
    memset ( aMemoryArea, 0, I_AMOUNT_OF_BYTES_FOR_MEMORY_HARD_FUNCTION );

    ECRYPT_keysetup ( & structECRYPT_ctx, hash[1], ECRYPT_MAXKEYSIZE, ECRYPT_MAXIVSIZE );
    ECRYPT_ivsetup ( & structECRYPT_ctx, hash[2] );

    uint64_t iWriteIndex;

    // Amplifying data and making random write accesses to memory.
    // Block size is 64 bytes. ECRYPT_BLOCKLENGTH .
    // Hash size is 64 bytes.
    for ( i = 0; i < I_AMOUNT_OF_BYTES_FOR_MEMORY_HARD_FUNCTION / ( 64 ) / 2; i ++ ) {
        iWriteIndex =
            (
                //  % I_AMOUNT_OF_BYTES_FOR_MEMORY_HARD_FUNCTION here is to prevent integer overflow
                // on subsequent addition operation.
                GetUint64IndexFrom512BitsKey ( ( ( unsigned char * ) uint1024CombinedHashes + 64 ), 0 ) % I_AMOUNT_OF_BYTES_FOR_MEMORY_HARD_FUNCTION +
                i * I_PRIME_NUMBER_FOR_MEMORY_HARD_HASHING )
            %
            ( I_AMOUNT_OF_BYTES_FOR_MEMORY_HARD_FUNCTION - 8 * ECRYPT_BLOCKLENGTH );

        // From previous encryption result in memory to next encryption result in memory.
        ECRYPT_encrypt_blocks ( & structECRYPT_ctx,
            ( ( unsigned char * ) uint1024CombinedHashes + 64 ),
            & ( aMemoryArea [ iWriteIndex ] ),
            1 );  // 8

        //uint1024CombinedHashes.XOROperator ( 64, & ( aMemoryArea [ iWriteIndex ] ) );
        uint1024_XOROperator ( uint1024CombinedHashes, 64, & ( aMemoryArea [ iWriteIndex ] ) );

    } //-for
    
    for ( i = 0; i < I_AMOUNT_OF_BYTES_FOR_MEMORY_HARD_FUNCTION / 64; i ++ ) {
        //uint1024CombinedHashes.XOROperator ( 64, & ( aMemoryArea [ i * 64 ] ) );
        uint1024_XOROperator ( uint1024CombinedHashes, 64, & ( aMemoryArea [ i * 64 ] ) );

    } //-for

    //bin2hex(hash_1024_str, (unsigned char *) uint1024CombinedHashes, 128);
    //applog ( LOG_DEBUG, "DEBUG: Binarium_hash_v1_hash_Implementation () : Memory hard hashing function : %s.", hash_1024_str );

    //-Whirlpool--------------------------------------
    // keccak512
    aIntermediateHashFunctions [ 4 ] ( uint1024CombinedHashes, 128, NULL, hash[5] );
    //bin2hex(hash_str, (unsigned char *)hash [ 5 ], 64);
    //applog ( LOG_DEBUG, "DEBUG: Binarium_hash_v1_hash_Implementation () : keccak512 : %s.", hash_str );

    //-SWIFFT.----------------------------------------
    // luffa512
    aIntermediateHashFunctions [ 6 ] ( hash[5], 64, NULL, hash[6] );
    //bin2hex(hash_str, (unsigned char *)hash [ 6 ], 64);
    //applog ( LOG_DEBUG, "DEBUG: Binarium_hash_v1_hash_Implementation () : luffa512 : %s.", hash_str );

    // cubehash512
    aIntermediateHashFunctions [ 7 ] ( hash[6], 64, NULL, hash[7] );
    //bin2hex(hash_str, (unsigned char *)hash [ 7 ], 64);
    //applog ( LOG_DEBUG, "DEBUG: Binarium_hash_v1_hash_Implementation () : cubehash512 : %s.", hash_str );

    //-GOST 2015_Kuznechik.---------------------------
    memcpy ( hash [ 6 ], hash [ 7 ], 64 );
    iIndex = ( iWeekNumber + * p_nBits ) % I_AMOUNT_OF_INTERMEDIATE_ENCRYPTION_FUNCTIONS;
    //bin2hex(hash_str, (unsigned char *)hash [ 6 ], 64);
    //applog ( LOG_DEBUG, "DEBUG: Binarium_hash_v1_hash_Implementation () : Data : %s.", hash_str );
    //bin2hex(hash_str, (unsigned char *)hash [ 0 ], 64);
    //applog ( LOG_DEBUG, "DEBUG: Binarium_hash_v1_hash_Implementation () : Key : %s.", hash_str );
    aIntermediateEncryptionFunctions [ iIndex ] ( hash[6], 64, hash[0], hash[7] );
    //bin2hex(hash_str, (unsigned char *)hash [ 7 ], 64);
    //applog ( LOG_DEBUG, "DEBUG: Binarium_hash_v1_hash_Implementation () : aIntermediateEncryptionFunctions 1 : %i , %s.", iIndex, hash_str );

    // shavite512
    aIntermediateHashFunctions [ 8 ] ( hash[7], 64, NULL, hash[8] );
    //bin2hex(hash_str, (unsigned char *)hash [ 8 ], 64);
    //applog ( LOG_DEBUG, "DEBUG: Binarium_hash_v1_hash_Implementation () : shavite512 : %s.", hash_str );

    //---ThreeFish.----------------------------------

    // simd512
    aIntermediateHashFunctions [ 9 ] ( hash[8], 64, NULL, uint512AdditionalHash );
    //bin2hex(hash_str, (unsigned char *) uint512AdditionalHash, 64);
    //applog ( LOG_DEBUG, "DEBUG: Binarium_hash_v1_hash_Implementation () : simd512 : %s.", hash_str );

    iIndex = ( iWeekNumber + * p_nBits + 10 ) % I_AMOUNT_OF_INTERMEDIATE_HASH_FUNCTIONS;
    aIntermediateHashFunctions [ iIndex ] ( uint512AdditionalHash, 64, NULL, hash[9] );
    //bin2hex(hash_str, (unsigned char *)hash [ 9 ], 64);
    //applog ( LOG_DEBUG, "DEBUG: Binarium_hash_v1_hash_Implementation () : aIntermediateHashFunctions 2 : %s.", hash_str );

    //---Camellia.-----------------------------------    

    // echo512
    aIntermediateHashFunctions [ 10 ] ( hash[9], 64, NULL, hash[10] );
    //bin2hex(hash_str, (unsigned char *)hash [ 10 ], 64);
    //applog ( LOG_DEBUG, "DEBUG: Binarium_hash_v1_hash_Implementation () : echo512 : %s.\n", hash_str );



    //return hash[10].trim256();
    //memcpy ( state, hash[10], 32 );
    memcpy ( state, hash[10], 32 );
    //memcpy( state, hash, 32 );

    //bin2hex(hash_str, (unsigned char *) state, 32);
    //applog ( LOG_DEBUG, "DEBUG: Binarium_hash_v1_hash_Implementation () : resulting hash : %s.\n", hash_str );
    
}



typedef struct {
    hashState_luffa         luffa;
    cubehashParam           cube;
    hashState_sd            simd;
    sph_shavite512_context  shavite;
#ifdef NO_AES_NI
    sph_groestl512_context  groestl;
    sph_echo512_context     echo;
#else
    hashState_echo          echo;
    hashState_groestl       groestl;
#endif
} x11_ctx_holder;

x11_ctx_holder x11_ctx;

void Binarium_init_x11_ctx_implementation()
{
     init_luffa( &x11_ctx.luffa, 512 );
     cubehashInit( &x11_ctx.cube, 512, 16, 32 );
     sph_shavite512_init( &x11_ctx.shavite );
     init_sd( &x11_ctx.simd, 512 );
#ifdef NO_AES_NI
     sph_groestl512_init( &x11_ctx.groestl );
     sph_echo512_init( &x11_ctx.echo );
#else
     init_echo( &x11_ctx.echo, 512 );
     init_groestl( &x11_ctx.groestl, 64 );
#endif
}

static void Binarium_x11_hash_implementation( void *state, const void *input )
{
     unsigned char hash[128] __attribute__ ((aligned (32)));
     unsigned char hashbuf[128] __attribute__ ((aligned (16)));
     sph_u64 hashctA;
     sph_u64 hashctB;
     x11_ctx_holder ctx;
     memcpy( &ctx, &x11_ctx, sizeof(x11_ctx) );
     size_t hashptr;

     DECL_BLK;
     BLK_I;
     BLK_W;
     BLK_C;

     DECL_BMW;
     BMW_I;
     BMW_U;
     #define M(x)    sph_dec64le_aligned(data + 8 * (x))
     #define H(x)    (h[x])
     #define dH(x)   (dh[x])
     BMW_C;
     #undef M
     #undef H
     #undef dH

#ifdef NO_AES_NI
     sph_groestl512 (&ctx.groestl, hash, 64);
     sph_groestl512_close(&ctx.groestl, hash);
#else
     update_and_final_groestl( &ctx.groestl, (char*)hash, (char*)hash, 512 );
//     update_groestl( &ctx.groestl, (char*)hash, 512 );
//     final_groestl( &ctx.groestl, (char*)hash );
#endif

     DECL_SKN;
     SKN_I;
     SKN_U;
     SKN_C;

     DECL_JH;
     JH_H;

     DECL_KEC;
     KEC_I;
     KEC_U;
     KEC_C;

//   asm volatile ("emms");

     update_luffa( &ctx.luffa, (const BitSequence*)hash, 64 );
     final_luffa( &ctx.luffa, (BitSequence*)hash+64 );

     cubehashUpdate( &ctx.cube, (const byte*) hash+64, 64 );
     cubehashDigest( &ctx.cube, (byte*)hash );

     sph_shavite512( &ctx.shavite, hash, 64 );
     sph_shavite512_close( &ctx.shavite, hash+64 );

     update_sd( &ctx.simd, (const BitSequence *)hash+64, 512 );
     final_sd( &ctx.simd, (BitSequence *)hash );

#ifdef NO_AES_NI
     sph_echo512 (&ctx.echo, hash, 64 );
     sph_echo512_close(&ctx.echo, hash+64 );
#else
     update_echo ( &ctx.echo, (const BitSequence *) hash, 512 );
     final_echo( &ctx.echo, (BitSequence *) hash+64 );
#endif

//        asm volatile ("emms");
     memcpy( state, hash+64, 32 );
}



static void Binarium_hash_v1_hash( void *state, const void *input )
{
    HashGenerator_Init ();

    uint32_t iTimeFromGenesisBlock;
    //uint32_t iAlgorithmSelector;
    //uint32_t iHashFunctionsAmount;
    uint32_t * p_nTime = ( input + 4 + 32 + 32 );

    //applog ( LOG_DEBUG, "DEBUG: nTime : %i.", * p_nTime );

    iTimeFromGenesisBlock = * p_nTime - GenesisBlock_nTime;
    //iHashFunctionsAmount = 2;
    //iAlgorithmSelector = iTimeFromGenesisBlock < 3528000 ? 0 : 1;

    //return (this->*(aHashFunctions[iAlgorithmSelector]))( pPrevBlockIndex, iTimeFromGenesisBlock );
    if ( iTimeFromGenesisBlock >= 3528000 )
        Binarium_hash_v1_hash_Implementation ( state, input, 80, iTimeFromGenesisBlock );

    else {
        Binarium_init_x11_ctx_implementation ();
        Binarium_x11_hash_implementation ( state, input );
    }

}

int scanhash_Binarium_hash_v1( int thr_id, struct work *work, uint32_t max_nonce,
                  uint64_t *hashes_done )
{
        uint32_t endiandata[20] __attribute__((aligned(64)));
        uint32_t hash64[8] __attribute__((aligned(64)));
        uint32_t *pdata = work->data;
        uint32_t *ptarget = work->target;
	uint32_t n = pdata[19] - 1;
	const uint32_t first_nonce = pdata[19];
	const uint32_t Htarg = ptarget[7];
        uint64_t htmax[] = {
                0,
                0xF,
                0xFF,
                0xFFF,
                0xFFFF,
                0x10000000
        };
        uint32_t masks[] = {
                0xFFFFFFFF,
                0xFFFFFFF0,
                0xFFFFFF00,
                0xFFFFF000,
                0xFFFF0000,
                0
        };

        char hash_str[129];



        // big endian encode 0..18 uint32_t, 64 bits at a time
        swab32_array( endiandata, pdata, 20 );

        /*for (int m=0; m < 6; m++) {
          applog ( LOG_DEBUG, "DEBUG : scanhash_Binarium_hash_v1 () : Htarg : %u, mask : %u, m : %u .", Htarg, htmax[m], m );
          if (Htarg <= htmax[m])
          {
            //applog ( LOG_DEBUG, "DEBUG : scanhash_Binarium_hash_v1 () : Htarg : %u, mask : %u, m : %u .", Htarg, htmax[m], m );
            uint32_t mask = masks[m];*/
            do
            {
              pdata[19] = ++n;
              //---For testing [.-------------------------------
              //pdata[19] = 0;
              //n = 0;
              //---] For testing.-------------------------------
              be32enc( &endiandata[19], n );
              Binarium_hash_v1_hash( hash64, &endiandata );

              /*applog ( LOG_DEBUG, "DEBUG : scanhash_Binarium_hash_v1 () : n : %u, hash64[7] : %u, Htarg : %u .", n, hash64[7], Htarg );
              bin2hex(hash_str, (unsigned char *) hash64, 32);
              applog ( LOG_DEBUG, "DEBUG: scanhash_Binarium_hash_v1 () : hash64 :\n%s.\n", hash_str );
              bin2hex(hash_str, (unsigned char *) ptarget, 32);
              applog ( LOG_DEBUG, "DEBUG: scanhash_Binarium_hash_v1 () : ptarget :\n%s.\n", hash_str );*/

              //if ( ( hash64[7] & mask ) == 0 )
              //{
              //   applog ( LOG_DEBUG, "DEBUG : scanhash_Binarium_hash_v1 () : hash64 [ 7 ] : %u, mask : %u .", hash64[7], mask );
                 //if ( fulltest( hash64, ptarget ) )
                 if (hash64[7] < Htarg && fulltest(hash64, ptarget))
                 {
                    *hashes_done = n - first_nonce + 1;
                    //applog ( LOG_DEBUG, "DEBUG : scanhash_Binarium_hash_v1 () : Proof of work found : %" PRIu64 " .", *hashes_done );
                    return true;
                 }
              //}
            } while ( n < max_nonce && !work_restart[thr_id].restart );
          /*}

        } //-for*/

        *hashes_done = n - first_nonce + 1;
        pdata[19] = n;
        return 0;
}

bool register_Binarium_hash_v1_algo( algo_gate_t* gate )
{
  gate->optimizations = SSE2_OPT | AES_OPT | AVX_OPT | AVX2_OPT;
  init_Binarium_hash_v1_ctx();
  gate->scanhash  = (void*)&scanhash_Binarium_hash_v1;
  gate->hash      = (void*)&Binarium_hash_v1_hash;
  gate->get_max64 = (void*)&get_max64_0x3ffff;
  return true;
};

