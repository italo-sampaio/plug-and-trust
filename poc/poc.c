#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <fsl_sss_se05x_apis.h>
#include <se05x_APDU_apis.h>
#include <se05x_ecc_curves_values.h>

static void remove_existing_key(Se05xSession_t *s_ctx, uint32_t key_id) {
    SE05x_Result_t exists = kSE05x_Result_NA;
    // Calls CheckObjectExists from the SE function with the key_id as parameter  (AN12413 - section 4.7.4.4)
    smStatus_t sm_status = Se05x_API_CheckObjectExists(s_ctx, key_id, &exists);
    assert(sm_status == SM_OK);
    assert(exists != kSE05x_Result_NA);
    if (exists == kSE05x_Result_SUCCESS) {
        printf("Key with id %d already exists, erasing...\n", key_id);
        // Calls DeleteSecureObject from the SE function with the key_id as parameter  (AN12413 - section 4.7.4.5)
        sm_status = Se05x_API_DeleteSecureObject(s_ctx, key_id);
        assert(sm_status == SM_OK);
    } else {
        printf("Key with %d does not exist\n", key_id);
    }
}

/**
 * Create and set parameters for a secp256k1 curve
 * 
 * See AN12413 - sections 4.8.1 and 4.8.2
*/
static void create_secp256k1_curve(Se05xSession_t *s_ctx) {
    smStatus_t sm_status = Se05x_API_CreateECCurve(s_ctx, kSE05x_ECCurve_Secp256k1);
    assert(sm_status == SM_OK);
    const uint8_t ecc_a[] = {EC_PARAM_secp256k1_a};
    sm_status = Se05x_API_SetECCurveParam(s_ctx, kSE05x_ECCurve_Secp256k1, kSE05x_ECCurveParam_PARAM_A, ecc_a, ARRAY_SIZE(ecc_a));
    assert(sm_status == SM_OK);
    const uint8_t ecc_b[] = {EC_PARAM_secp256k1_b};
    sm_status = Se05x_API_SetECCurveParam(s_ctx, kSE05x_ECCurve_Secp256k1, kSE05x_ECCurveParam_PARAM_B, ecc_b, ARRAY_SIZE(ecc_b));
    assert(sm_status == SM_OK);
    const uint8_t ecc_G[] = {0x04, EC_PARAM_secp256k1_x, EC_PARAM_secp256k1_y};
    sm_status = Se05x_API_SetECCurveParam(s_ctx, kSE05x_ECCurve_Secp256k1, kSE05x_ECCurveParam_PARAM_G, ecc_G, ARRAY_SIZE(ecc_G));
    assert(sm_status == SM_OK);
    const uint8_t ecc_ordern[] = {EC_PARAM_secp256k1_order};
    sm_status = Se05x_API_SetECCurveParam(s_ctx, kSE05x_ECCurve_Secp256k1, kSE05x_ECCurveParam_PARAM_N, ecc_ordern, ARRAY_SIZE(ecc_ordern));
    assert(sm_status == SM_OK);
    const uint8_t ecc_prime[] = {EC_PARAM_secp256k1_prime};
    sm_status = Se05x_API_SetECCurveParam(s_ctx, kSE05x_ECCurve_Secp256k1, kSE05x_ECCurveParam_PARAM_PRIME, ecc_prime, ARRAY_SIZE(ecc_prime));
    assert(sm_status == SM_OK);
}

/**
 * Generates a new key pair on the SE050.
 * 
 * To generate a key pair on the device, we need to set both the private and public keys to NULL.
 * See AN12413 - section 4.7.1.1 - WriteECKey
*/
static void generate_key(Se05xSession_t *s_ctx, uint32_t key_id) {
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
    assert(sm_status == SM_OK);
}

int main(int argc, const char *argv[]) {
    /**
     * Now we setup I2C connection to the SE050.
     * 
     * We can set multiple configurations here:
     * - The connection type (see sss_type_t)
     * - The i2c port to connect
     * - The authentication type, if any (see SE_AuthType_t)
     * 
     * This will also query the applet version to make sure it is compatible with the hostlib.
    */
    SE05x_Connect_Ctx_t connectionData = {0};
    memset(&connectionData, 0, sizeof(connectionData));
    connectionData.connType = kType_SSS_SE_SE05x;
    connectionData.auth.authType = kSSS_AuthType_None;
    connectionData.portName = "/dev/i2c-0";
    sss_se05x_session_t session = {0};
    memset(&session, 0, sizeof(session));
    sss_status_t sss_status = sss_se05x_session_open(&session, kType_SSS_SE_SE05x, 0, kSSS_ConnectionType_Plain, &connectionData);
    assert(sss_status == kStatus_SSS_Success);

    uint32_t key_id = 200;
    create_secp256k1_curve(&session.s_ctx);
    remove_existing_key(&session.s_ctx, key_id);
    generate_key(&session.s_ctx, key_id);

    // Read the public key
    uint8_t pub_key[65] = {0};
    size_t pub_key_len = sizeof(pub_key);
    // See AN12413 - sections 4.7.3.1 - ReadObject
    smStatus_t sm_status = Se05x_API_ReadObject(&session.s_ctx, key_id, 0, 0, pub_key, &pub_key_len);
    assert(sm_status == SM_OK);

    printf("Public key (%d bytes): ", pub_key_len);
    for (int i = 0; i < pub_key_len; i++) {
        printf("%02x", pub_key[i]);
    }
    printf("\n");

    // Let's sign!
    // SHA256 of "Some host-hashed data..."
    uint8_t digest[]  = {
            0xca, 0x79, 0x65, 0x0c, 0x67, 0x0a, 0xb9, 0x35,
            0x16, 0x16, 0x9e, 0x82, 0x7d, 0xd6, 0x92, 0x01,
            0xb3, 0x60, 0x9e, 0x6d, 0xd1, 0xd2, 0xb8, 0xc1,
            0x04, 0x44, 0xfe, 0x08, 0xff, 0x64, 0xfc, 0x02
        };
    // Just to be sure
    assert(sizeof(digest) == 32);

    uint8_t signature[72] = {0};
    size_t signature_len = sizeof(signature);
    // See AN12413 - section 4.10.1.1 - ECDSASign
    sm_status = Se05x_API_ECDSASign(&session.s_ctx,
                                    key_id,
                                    kSE05x_ECSignatureAlgo_SHA_256,
                                    digest,
                                    sizeof(digest),
                                    signature,
                                    &signature_len);
    assert(sm_status == SM_OK);

    printf("Digest (%d bytes): ", sizeof(digest));
    for (int i = 0; i < sizeof(digest); i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
        
    printf("Signature (%d bytes): ", signature_len);
    for (int i = 0; i < signature_len; i++) {
        printf("%02x", signature[i]);
    }
    printf("\n");

    return 0;
}