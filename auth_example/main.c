/*
 *
 * Copyright 2018,2019 NXP
 * SPDX-License-Identifier: Apache-2.0
 */

/* ************************************************************************** */
/* Includes                                                                   */
/* ************************************************************************** */
#include <assert.h>
#include <string.h>
#include <ex_sss.h>
#include <ex_sss_boot.h>
#include <fsl_sss_se05x_apis.h>
#include <se05x_APDU.h>
#include <nxEnsure.h>
#include <nxLog_App.h>
#include <ax_reset.h>
#include <se05x_ecc_curves_values.h>

#define EC_KEY_BIT_LEN 256
#define SCP03_MAX_AUTH_KEY_SIZE 52

/* clang-format off */
#define EX_SSS_AUTH_SE05X_KEY_HOST_ECDSA_KEY                              \
    {                                                                     \
        0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13,                   \
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,                   \
        0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D,                   \
        0x03, 0x01, 0x07, 0x04, 0x6D, 0x30, 0x6B, 0x02,                   \
        0x01, 0x01, 0x04, 0x20,                                           \
        0x6D, 0x2F, 0x43, 0x2F, 0x8A, 0x2F, 0x45, 0xEC,                   \
        0xD5, 0x82, 0x84, 0x7E, 0xC0, 0x83, 0xBB, 0xEB,                   \
        0xC2, 0x3F, 0x1D, 0xF4, 0xF0, 0xDD, 0x2A, 0x6F,                   \
        0xB8, 0x1A, 0x24, 0xE7, 0xB6, 0xD5, 0x4C, 0x7F,                   \
        0xA1, 0x44, 0x03, 0x42, 0x00,                                     \
        0x04, 0x3C, 0x9E, 0x47, 0xED, 0xF0, 0x51, 0xA3,                   \
        0x58, 0x9F, 0x67, 0x30, 0x2D, 0x22, 0x56, 0x7C,                   \
        0x2E, 0x17, 0x22, 0x9E, 0x88, 0x83, 0x33, 0x8E,                   \
        0xC3, 0xB7, 0xD5, 0x27, 0xF9, 0xEE, 0x71, 0xD0,                   \
        0xA8, 0x1A, 0xAE, 0x7F, 0xE2, 0x1C, 0xAA, 0x66,                   \
        0x77, 0x78, 0x3A, 0xA8, 0x8D, 0xA6, 0xD6, 0xA8,                   \
        0xAD, 0x5E, 0xC5, 0x3B, 0x10, 0xBC, 0x0B, 0x11,                   \
        0x09, 0x44, 0x82, 0xF0, 0x4D, 0x24, 0xB5, 0xBE,                   \
        0xC4                                                              \
    }

// This is in accordance with the Delete and Provision example of edgelock
// You can get the full EdgeLock SE05x Plug & Trust Middleware here: https://www.nxp.com/webapp/Download?colCode=SE05x-PLUG-TRUST-MW&appType=license
enum
{
    kEX_SSS_ObjID_UserID_Auth = 0x7DA00001u,
    kEX_SSS_ObjID_APPLETSCP03_Auth,
    kEX_SSS_objID_ECKEY_Auth,
};

static sss_status_t se05x_prepare_host_eckey(SE05x_AuthCtx_ECKey_t *host_eckey, sss_openssl_key_store_t *host_key_store)
{
    sss_status_t status = kStatus_SSS_Fail;

    /* Init allocate Host ECDSA Key pair */
    sss_openssl_object_t *host_ecdsa_obj = (sss_openssl_object_t *) &host_eckey->pStatic_ctx->HostEcdsaObj;
    memset(host_ecdsa_obj, 0, sizeof(sss_openssl_object_t));
    host_ecdsa_obj->keyStore = host_key_store;
    status = sss_openssl_key_object_allocate_handle(host_ecdsa_obj, MAKE_TEST_ID(__LINE__), kSSS_KeyPart_Pair, kSSS_CipherType_EC_NIST_P, 256, kKeyObject_Mode_Persistent);
    assert(status == kStatus_SSS_Success);

    /* Set Host ECDSA Key pair */
    uint8_t hostEcdsakey[] = EX_SSS_AUTH_SE05X_KEY_HOST_ECDSA_KEY;
    size_t keylen = sizeof(hostEcdsakey);
    status = sss_openssl_key_store_set_key(host_key_store, host_ecdsa_obj, hostEcdsakey, keylen, 256, NULL, 0);
    if (status == kStatus_SSS_Fail) {
        return status;
    }

    /* Init allocate Host ECKA Key pair */
    sss_openssl_object_t *host_ec_key_pair = (sss_openssl_object_t *) &host_eckey->pStatic_ctx->HostEcKeypair;
    memset(host_ec_key_pair, 0, sizeof(sss_openssl_object_t));
    host_ec_key_pair->keyStore = host_key_store;
    status = sss_openssl_key_object_allocate_handle(host_ec_key_pair, MAKE_TEST_ID(__LINE__), kSSS_KeyPart_Pair, kSSS_CipherType_EC_NIST_P, 256, kKeyObject_Mode_Persistent);
    assert(status == kStatus_SSS_Success);

    /* Generate Host EC Key pair */
    status = sss_openssl_key_store_generate_key(host_key_store, host_ec_key_pair, 256, NULL);
    if (status != kStatus_SSS_Success) {
        return status;
    }

    /* Init allocate SE ECKA Public Key */
    sss_openssl_object_t *se_ec_pubkey = (sss_openssl_object_t *) &host_eckey->pStatic_ctx->SeEcPubKey;
    memset(se_ec_pubkey, 0, sizeof(sss_openssl_object_t));
    se_ec_pubkey->keyStore = host_key_store;
    status = sss_openssl_key_object_allocate_handle(se_ec_pubkey, MAKE_TEST_ID(__LINE__), kSSS_KeyPart_Public, kSSS_CipherType_EC_NIST_P, 256, kKeyObject_Mode_Persistent);
    assert(status == kStatus_SSS_Success);

    status = sss_openssl_key_store_generate_key(host_key_store, se_ec_pubkey, 256, NULL);
    assert(status == kStatus_SSS_Success);

    /* Init Allocate Master Secret */
    sss_openssl_object_t *master_sec = (sss_openssl_object_t *) &host_eckey->pStatic_ctx->masterSec;
    memset(master_sec, 0, sizeof(sss_openssl_object_t));
    master_sec->keyStore = host_key_store;
    status = sss_openssl_key_object_allocate_handle(master_sec, MAKE_TEST_ID(__LINE__), kSSS_KeyPart_Default, kSSS_CipherType_AES, SCP03_MAX_AUTH_KEY_SIZE, kKeyObject_Mode_Transient);
    assert(status == kStatus_SSS_Success);

    /* Init Allocate ENC Session Key */
    sss_openssl_object_t *enc = (sss_openssl_object_t *) &host_eckey->pDyn_ctx->Enc;
    memset(enc, 0, sizeof(sss_openssl_object_t));
    enc->keyStore = host_key_store;
    status = sss_openssl_key_object_allocate_handle(enc, MAKE_TEST_ID(__LINE__), kSSS_KeyPart_Default, kSSS_CipherType_AES, SCP03_MAX_AUTH_KEY_SIZE, kKeyObject_Mode_Transient);
    assert(status == kStatus_SSS_Success);

    /* Init Allocate MAC Session Key */
    sss_openssl_object_t *mac = (sss_openssl_object_t *) &host_eckey->pDyn_ctx->Mac;
    memset(mac, 0, sizeof(sss_openssl_object_t));
    mac->keyStore = host_key_store;
    status = sss_openssl_key_object_allocate_handle(mac, MAKE_TEST_ID(__LINE__), kSSS_KeyPart_Default, kSSS_CipherType_AES, SCP03_MAX_AUTH_KEY_SIZE, kKeyObject_Mode_Transient);
    assert(status == kStatus_SSS_Success);

    /* Init Allocate DEK Session Key */
    sss_openssl_object_t *rmac = (sss_openssl_object_t *) &host_eckey->pDyn_ctx->Rmac;
    memset(rmac, 0, sizeof(sss_openssl_object_t));
    rmac->keyStore = host_key_store;
    status = sss_openssl_key_object_allocate_handle(rmac, MAKE_TEST_ID(__LINE__), kSSS_KeyPart_Default, kSSS_CipherType_AES, SCP03_MAX_AUTH_KEY_SIZE, kKeyObject_Mode_Transient);
    assert(status == kStatus_SSS_Success);

    return status;
}

typedef struct poc_context_t {
    SE_Connect_Ctx_t se05x_connection_ctx;
    sss_se05x_session_t session;
    sss_se05x_key_store_t key_store;
    sss_openssl_key_store_t host_key_store;
} poc_context_t;

static void poc_init(poc_context_t *poc_ctx) {
    memset(poc_ctx, 0, sizeof(poc_context_t));
    poc_ctx->se05x_connection_ctx.auth.ctx.eckey.pStatic_ctx = malloc(sizeof(NXECKey03_StaticCtx_t));
    poc_ctx->se05x_connection_ctx.auth.ctx.eckey.pDyn_ctx = malloc(sizeof(NXSCP03_DynCtx_t));
    memset(poc_ctx->se05x_connection_ctx.auth.ctx.eckey.pStatic_ctx, 0, sizeof(NXECKey03_StaticCtx_t));
    memset(poc_ctx->se05x_connection_ctx.auth.ctx.eckey.pDyn_ctx, 0, sizeof(NXSCP03_DynCtx_t));

    poc_ctx->se05x_connection_ctx.connType = kType_SE_Conn_Type_T1oI2C;
    poc_ctx->se05x_connection_ctx.portName = "/dev/i2c-0";
    poc_ctx->host_key_store.session = malloc(sizeof(sss_openssl_session_t));
    assert(NULL != poc_ctx->host_key_store.session);
    poc_ctx->host_key_store.session->subsystem = kType_SSS_OpenSSL;

    poc_ctx->host_key_store.max_object_count = KS_N_ENTIRES;
    poc_ctx->host_key_store.objects = (sss_openssl_object_t **) malloc(sizeof(sss_openssl_object_t *) * KS_N_ENTIRES);
    assert(NULL != poc_ctx->host_key_store.objects);
    memset(poc_ctx->host_key_store.objects, 0, sizeof(sss_openssl_object_t *) * KS_N_ENTIRES);
    ks_sw_fat_allocate(&poc_ctx->host_key_store.keystore_shadow);
    ks_sw_fat_load(poc_ctx->host_key_store.session->szRootPath, poc_ctx->host_key_store.keystore_shadow);

    OpenSSL_add_all_algorithms();
}

static void session_close(poc_context_t *poc_ctx)
{
    if (poc_ctx->session.subsystem != kType_SSS_SubSystem_NONE) {
        sss_se05x_session_close(&poc_ctx->session);
    }

    if (poc_ctx->host_key_store.session->subsystem != kType_SSS_SubSystem_NONE) {
        sss_openssl_session_close(poc_ctx->host_key_store.session);
    }

    if (poc_ctx->host_key_store.session != NULL) {
        sss_openssl_key_store_context_free(&poc_ctx->host_key_store);
    }

    if (poc_ctx->key_store.session != NULL) {
        sss_se05x_key_store_context_free(&poc_ctx->key_store);
    }
}

/**
 * Create and set parameters for a secp256k1 curve
 * 
 * See AN12413 - sections 4.8.1 and 4.8.2
*/
static smStatus_t create_secp256k1_curve(Se05xSession_t *s_ctx) {
    smStatus_t sm_status = Se05x_API_CreateECCurve(s_ctx, kSE05x_ECCurve_Secp256k1);
    if (sm_status != SM_OK) {
        LOG_E("Se05x_API_CreateECCurve failed");
        return sm_status;
    }
    const uint8_t ecc_a[] = {EC_PARAM_secp256k1_a};
    sm_status = Se05x_API_SetECCurveParam(s_ctx, kSE05x_ECCurve_Secp256k1, kSE05x_ECCurveParam_PARAM_A, ecc_a, ARRAY_SIZE(ecc_a));
    if (sm_status != SM_OK) {
        LOG_E("Se05x_API_SetECCurveParam failed");
        return sm_status;
    }
    const uint8_t ecc_b[] = {EC_PARAM_secp256k1_b};
    sm_status = Se05x_API_SetECCurveParam(s_ctx, kSE05x_ECCurve_Secp256k1, kSE05x_ECCurveParam_PARAM_B, ecc_b, ARRAY_SIZE(ecc_b));
    if (sm_status != SM_OK) {
        LOG_E("Se05x_API_SetECCurveParam failed");
        return sm_status;
    }
    const uint8_t ecc_G[] = {0x04, EC_PARAM_secp256k1_x, EC_PARAM_secp256k1_y};
    sm_status = Se05x_API_SetECCurveParam(s_ctx, kSE05x_ECCurve_Secp256k1, kSE05x_ECCurveParam_PARAM_G, ecc_G, ARRAY_SIZE(ecc_G));
    if (sm_status != SM_OK) {
        LOG_E("Se05x_API_SetECCurveParam failed");
        return sm_status;
    }
    const uint8_t ecc_ordern[] = {EC_PARAM_secp256k1_order};
    sm_status = Se05x_API_SetECCurveParam(s_ctx, kSE05x_ECCurve_Secp256k1, kSE05x_ECCurveParam_PARAM_N, ecc_ordern, ARRAY_SIZE(ecc_ordern));
    if (sm_status != SM_OK) {
        LOG_E("Se05x_API_SetECCurveParam failed");
        return sm_status;
    }
    const uint8_t ecc_prime[] = {EC_PARAM_secp256k1_prime};
    sm_status = Se05x_API_SetECCurveParam(s_ctx, kSE05x_ECCurve_Secp256k1, kSE05x_ECCurveParam_PARAM_PRIME, ecc_prime, ARRAY_SIZE(ecc_prime));
    return sm_status;
}

/**
 * Generates a new key pair on the SE050.
 * 
 * To generate a key pair on the device, we need to set both the private and public keys to NULL.
 * See AN12413 - section 4.7.1.1 - WriteECKey
*/
static smStatus_t generate_key(Se05xSession_t *s_ctx, uint32_t key_id) {
    smStatus_t sm_status = Se05x_API_WriteECKey(s_ctx,
                                                NULL,
                                                SE05x_MaxAttemps_NA,
                                                key_id,
                                                kSE05x_ECCurve_Secp256k1,
                                                NULL,
                                                0,
                                                NULL,
                                                0,
                                                kSE05x_INS_NA,
                                                kSE05x_KeyPart_Pair);
    return sm_status;
}

sss_status_t poc_main(poc_context_t *poc_ctx)
{
    LOG_I("Running Signing example");

    smStatus_t sm_status;
    sm_status = create_secp256k1_curve(&poc_ctx->session.s_ctx);
    if (sm_status != SM_OK) {
        LOG_E("create_secp256k1_curve failed");
        return kStatus_SSS_Fail;
    }
    else {
        LOG_I("create_secp256k1_curve successful");
    }

    // Generate a new secp256k1 keypair on the SE050
    uint32_t public_key_id = MAKE_TEST_ID(__LINE__);
    sm_status = generate_key(&poc_ctx->session.s_ctx, public_key_id);
    if (sm_status != SM_OK) {
        LOG_E("generate_key failed");
        return kStatus_SSS_Fail;
    }

    // Read the public key we've just generated
    // See AN12413 - sections 4.7.3.1 - ReadObject
    uint8_t pub_key[65] = {0};
    size_t pub_key_len = sizeof(pub_key);
    sm_status = Se05x_API_ReadObject(&poc_ctx->session.s_ctx, public_key_id, 0, 0, pub_key, &pub_key_len);
    if (sm_status != SM_OK) {
        LOG_E("Se05x_API_ReadObject failed");
        return kStatus_SSS_Fail;
    }
    LOG_AU8_I(pub_key, pub_key_len);
    
    // Sign hashed data with the generated keypair
    // See AN12413 - section 4.10.1.1 - ECDSASign
    // SHA256 of "Some host-hashed data..." string
    uint8_t digest[]  = {
            0xca, 0x79, 0x65, 0x0c, 0x67, 0x0a, 0xb9, 0x35,
            0x16, 0x16, 0x9e, 0x82, 0x7d, 0xd6, 0x92, 0x01,
            0xb3, 0x60, 0x9e, 0x6d, 0xd1, 0xd2, 0xb8, 0xc1,
            0x04, 0x44, 0xfe, 0x08, 0xff, 0x64, 0xfc, 0x02
        };
    uint8_t signature[72] = {0};
    size_t signature_len = sizeof(signature);
    sm_status = Se05x_API_ECDSASign(&poc_ctx->session.s_ctx,
                                    public_key_id,
                                    kSE05x_ECSignatureAlgo_SHA_256,
                                    digest,
                                    sizeof(digest),
                                    signature,
                                    &signature_len);
    if (sm_status != SM_OK) {
        LOG_E("Se05x_API_ECDSASign failed");
        return kStatus_SSS_Fail;
    }
    LOG_AU8_I(signature, signature_len);

    return kStatus_SSS_Success;
}

int main(int argc, const char *argv[])
{
    int ret;
    sss_status_t status = kStatus_SSS_Fail;
    smStatus_t sm_status = SM_NOT_OK;

    poc_context_t poc_ctx;
    poc_init(&poc_ctx);

    // Reset SE hardware
    axReset_HostConfigure();
    axReset_PowerUp();

    /* Initialise Logging locks */
    if (nLog_Init() != 0) {
        LOG_E("Lock initialisation failed");
    }

    // Prepare the host context to receive all the session keys
    status = se05x_prepare_host_eckey(&poc_ctx.se05x_connection_ctx.auth.ctx.eckey, &poc_ctx.host_key_store);
    if (kStatus_SSS_Success != status) {
        LOG_E("Host: ex_sss_se05x_prepare_host_<type=(SE_AuthType_t)%d> failed", kSSS_AuthType_ECKey);
        return status;
    }
    poc_ctx.se05x_connection_ctx.auth.authType = kSSS_AuthType_ECKey;

    LOG_I("Opening session");
    // Opening session. See se05x_CreateECKeySession for the generation of session keys
    status = sss_se05x_session_open(&poc_ctx.session, kType_SSS_SE_SE05x, kEX_SSS_objID_ECKEY_Auth, kSSS_ConnectionType_Encrypted, &poc_ctx.se05x_connection_ctx);
    if (kStatus_SSS_Success != status) {
        LOG_E("sss_session_open failed");
    }

    sm_status = Se05x_API_DeleteAll_Iterative(&poc_ctx.session.s_ctx);
    if (sm_status != SM_OK) {
        LOG_E("Se05x_API_DeleteAll_Iterative failed");
        goto cleanup;
    }

    status = sss_se05x_key_store_context_init(&poc_ctx.key_store, &poc_ctx.session);
    if (kStatus_SSS_Success != status) {
        LOG_E("sss_key_store_context_init Failed");
        goto cleanup;
    }

    status = sss_se05x_key_store_allocate(&poc_ctx.key_store, __LINE__);
    if (kStatus_SSS_Success != status) {
        LOG_E("sss_key_store_allocate Failed");
        goto cleanup;
    }

    // Setup host session
    if (poc_ctx.host_key_store.session == NULL) {
        LOG_E("Host session invalid! Aborting...");
        goto cleanup;
    }

    status = poc_main(&poc_ctx);
    if (kStatus_SSS_Success != status) {
        LOG_E("ex_sss_entry Failed");
        goto cleanup;
    }

    // Delete locks for pthreads
    nLog_DeInit();
    goto cleanup;

cleanup:
    session_close(&poc_ctx);
    if (kStatus_SSS_Success == status) {
        ret = 0;
        axReset_PowerDown();
        axReset_HostUnconfigure();
    }
    else {
        LOG_E("!ERROR! ret != 0.");
        ret = 1;
    }

    return ret;
}
