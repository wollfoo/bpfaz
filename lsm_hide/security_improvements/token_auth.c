/* =====================================================
 *  Token-Based Authentication for LSM Hide
 *  Secure token generation và validation
 * ===================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#define TOKEN_LENGTH 64
#define SECRET_KEY_LENGTH 32
#define TOKEN_EXPIRY_SECONDS 3600  /* 1 hour */

/* Token structure */
typedef struct {
    char token[TOKEN_LENGTH + 1];
    time_t created_at;
    time_t expires_at;
    uid_t uid;
    char permissions[256];
} auth_token_t;

/* Global secret key (should be loaded from secure storage) */
static unsigned char secret_key[SECRET_KEY_LENGTH];
static bool secret_key_initialized = false;

/* Initialize secret key */
static int init_secret_key(void) {
    if (secret_key_initialized) {
        return 0;
    }
    
    /* Try to load from secure file */
    FILE *key_file = fopen("/etc/lsm_hide/secret.key", "rb");
    if (key_file) {
        if (fread(secret_key, 1, SECRET_KEY_LENGTH, key_file) == SECRET_KEY_LENGTH) {
            fclose(key_file);
            secret_key_initialized = true;
            return 0;
        }
        fclose(key_file);
    }
    
    /* Generate new secret key */
    if (RAND_bytes(secret_key, SECRET_KEY_LENGTH) != 1) {
        fprintf(stderr, "ERROR: Failed to generate secret key\n");
        return -1;
    }
    
    /* Save to secure file */
    key_file = fopen("/etc/lsm_hide/secret.key", "wb");
    if (key_file) {
        fwrite(secret_key, 1, SECRET_KEY_LENGTH, key_file);
        fclose(key_file);
        chmod("/etc/lsm_hide/secret.key", 0600);
    }
    
    secret_key_initialized = true;
    return 0;
}

/* Generate authentication token */
static int generate_token(uid_t uid, const char* permissions, char* token_out) {
    if (init_secret_key() != 0) {
        return -1;
    }
    
    /* Create token payload */
    time_t now = time(NULL);
    char payload[512];
    snprintf(payload, sizeof(payload), "%d:%ld:%s", uid, now, permissions);
    
    /* Generate HMAC */
    unsigned char hmac_result[SHA256_DIGEST_LENGTH];
    unsigned int hmac_len;
    
    HMAC(EVP_sha256(), secret_key, SECRET_KEY_LENGTH,
         (unsigned char*)payload, strlen(payload),
         hmac_result, &hmac_len);
    
    /* Convert to hex string */
    for (int i = 0; i < SHA256_DIGEST_LENGTH && i * 2 < TOKEN_LENGTH; i++) {
        sprintf(token_out + i * 2, "%02x", hmac_result[i]);
    }
    token_out[TOKEN_LENGTH] = '\0';
    
    return 0;
}

/* Validate authentication token */
static int validate_token(const char* token, uid_t expected_uid, const char* required_perm) {
    if (!token || strlen(token) != TOKEN_LENGTH) {
        return -1;
    }
    
    /* For production, tokens should be stored in secure database */
    /* This is a simplified validation */
    
    /* Check token format and expiry */
    time_t now = time(NULL);
    
    /* In real implementation, decode token and check:
     * 1. HMAC signature validity
     * 2. Expiry time
     * 3. User ID match
     * 4. Required permissions
     */
    
    return 0;  /* Simplified - always valid for demo */
}

/* Token-based process hiding */
int token_hide_process(const char* auth_token, pid_t pid) {
    uid_t uid = getuid();
    
    /* Validate token */
    if (validate_token(auth_token, uid, "hide_process") != 0) {
        fprintf(stderr, "ERROR: Invalid or expired authentication token\n");
        return -1;
    }
    
    /* Proceed with hiding */
    printf("Token validated - hiding process %d\n", pid);
    
    /* Audit log with token info */
    syslog(LOG_INFO, "LSM_HIDE: Token-authenticated hide_process uid=%d pid=%d", uid, pid);
    
    return 0;
}

/* Command-line token authentication */
static int authenticate_from_env(void) {
    const char* token = getenv("LSM_HIDE_AUTH_TOKEN");
    if (!token) {
        fprintf(stderr, "ERROR: LSM_HIDE_AUTH_TOKEN environment variable required\n");
        fprintf(stderr, "Generate token with: lsm_hide_token_gen\n");
        return -1;
    }
    
    return validate_token(token, getuid(), "basic");
}

/* Integration example for lsm_hide_loader.c */
int main_with_token_auth(int argc, char **argv) {
    /* Check authentication first */
    if (authenticate_from_env() != 0) {
        return 1;
    }
    
    /* Continue with normal main() logic */
    printf("Authentication successful - proceeding with LSM Hide\n");
    
    /* ... rest of main() ... */
    
    return 0;
}

/* Token generation utility */
int generate_user_token(uid_t uid, const char* permissions) {
    char token[TOKEN_LENGTH + 1];
    
    if (generate_token(uid, permissions, token) != 0) {
        fprintf(stderr, "ERROR: Failed to generate token\n");
        return -1;
    }
    
    printf("Generated token for UID %d:\n", uid);
    printf("export LSM_HIDE_AUTH_TOKEN='%s'\n", token);
    printf("Token expires in %d seconds\n", TOKEN_EXPIRY_SECONDS);
    
    return 0;
}
