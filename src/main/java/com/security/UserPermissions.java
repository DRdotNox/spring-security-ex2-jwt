package com.security;

import lombok.Getter;

@Getter
public enum UserPermissions {
    USER_READ("user:read"),
    USER_WRITE("user:write"),
    ADMIN_READ("admin:read"),
    ADMIN_WRITE("admin:write"),
    ;

    private final String permission;

    UserPermissions(String permission) {
        this.permission = permission;
    }


}
