/* =====================================================
 *  RBAC Security Model for LSM Hide
 *  Role-Based Access Control với fine-grained permissions
 * ===================================================== */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <sys/capability.h>

/* Security Roles */
typedef enum {
    ROLE_ADMIN = 1,      /* Full access */
    ROLE_OPERATOR = 2,   /* Limited operations */
    ROLE_VIEWER = 3,     /* Read-only access */
    ROLE_NONE = 0        /* No access */
} security_role_t;

/* Permissions */
typedef enum {
    PERM_HIDE_PROCESS = 1 << 0,
    PERM_UNHIDE_PROCESS = 1 << 1,
    PERM_VIEW_HIDDEN = 1 << 2,
    PERM_CONFIGURE = 1 << 3,
    PERM_AUDIT = 1 << 4
} permission_t;

/* Role-Permission Mapping */
static const struct {
    security_role_t role;
    permission_t permissions;
    const char* description;
} role_permissions[] = {
    {ROLE_ADMIN, 
     PERM_HIDE_PROCESS | PERM_UNHIDE_PROCESS | PERM_VIEW_HIDDEN | 
     PERM_CONFIGURE | PERM_AUDIT,
     "Full administrative access"},
    
    {ROLE_OPERATOR,
     PERM_HIDE_PROCESS | PERM_VIEW_HIDDEN,
     "Operational access - can hide processes"},
     
    {ROLE_VIEWER,
     PERM_VIEW_HIDDEN | PERM_AUDIT,
     "Read-only access for monitoring"},
     
    {ROLE_NONE, 0, "No access"}
};

/* User-Role Mapping (could be loaded from config file) */
static const struct {
    uid_t uid;
    const char* username;
    security_role_t role;
} user_roles[] = {
    {0, "root", ROLE_ADMIN},
    {1000, "admin", ROLE_ADMIN},
    {1001, "operator", ROLE_OPERATOR},
    {1002, "monitor", ROLE_VIEWER}
};

/* Get user role */
static security_role_t get_user_role(uid_t uid) {
    for (size_t i = 0; i < sizeof(user_roles)/sizeof(user_roles[0]); i++) {
        if (user_roles[i].uid == uid) {
            return user_roles[i].role;
        }
    }
    return ROLE_NONE;
}

/* Check permission */
static bool check_permission(uid_t uid, permission_t required_perm) {
    security_role_t role = get_user_role(uid);
    
    for (size_t i = 0; i < sizeof(role_permissions)/sizeof(role_permissions[0]); i++) {
        if (role_permissions[i].role == role) {
            return (role_permissions[i].permissions & required_perm) != 0;
        }
    }
    return false;
}

/* Enhanced authentication with capability checking */
static int authenticate_user(permission_t required_perm) {
    uid_t uid = getuid();
    uid_t euid = geteuid();
    
    /* Check if running as root */
    if (euid != 0) {
        fprintf(stderr, "ERROR: LSM Hide requires root privileges\n");
        return -1;
    }
    
    /* Check RBAC permissions */
    if (!check_permission(uid, required_perm)) {
        struct passwd *pw = getpwuid(uid);
        fprintf(stderr, "ERROR: User %s (UID: %d) lacks required permission\n",
                pw ? pw->pw_name : "unknown", uid);
        return -1;
    }
    
    /* Check required capabilities */
    cap_t caps = cap_get_proc();
    if (!caps) {
        perror("cap_get_proc");
        return -1;
    }
    
    cap_flag_value_t cap_value;
    if (cap_get_flag(caps, CAP_SYS_ADMIN, CAP_EFFECTIVE, &cap_value) != 0 ||
        cap_value != CAP_SET) {
        fprintf(stderr, "ERROR: CAP_SYS_ADMIN capability required\n");
        cap_free(caps);
        return -1;
    }
    
    cap_free(caps);
    return 0;
}

/* Audit logging */
static void audit_log(const char* action, uid_t uid, const char* details) {
    struct passwd *pw = getpwuid(uid);
    syslog(LOG_INFO, "LSM_HIDE_AUDIT: user=%s uid=%d action=%s details=%s",
           pw ? pw->pw_name : "unknown", uid, action, details);
}

/* Example usage in main functions */
int secure_hide_process(pid_t pid) {
    uid_t uid = getuid();
    
    /* Authenticate and authorize */
    if (authenticate_user(PERM_HIDE_PROCESS) != 0) {
        return -1;
    }
    
    /* Audit log */
    char details[256];
    snprintf(details, sizeof(details), "pid=%d", pid);
    audit_log("HIDE_PROCESS", uid, details);
    
    /* Proceed with hiding process */
    // ... existing hide logic ...
    
    return 0;
}

int secure_configure_system(const char* config) {
    uid_t uid = getuid();
    
    /* Authenticate and authorize */
    if (authenticate_user(PERM_CONFIGURE) != 0) {
        return -1;
    }
    
    /* Audit log */
    audit_log("CONFIGURE", uid, config);
    
    /* Proceed with configuration */
    // ... existing config logic ...
    
    return 0;
}
