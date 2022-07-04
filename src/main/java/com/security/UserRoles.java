package com.security;

import lombok.Getter;

import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.security.UserPermissions.ADMIN_READ;
import static com.security.UserPermissions.ADMIN_WRITE;
import static com.security.UserPermissions.USER_READ;
import static com.security.UserPermissions.USER_WRITE;
@Getter
public enum UserRoles {
    USER(Stream.of(USER_READ, USER_WRITE)
            .collect(Collectors.toCollection(HashSet::new))),
    ADMIN(Stream.of(USER_READ, USER_WRITE, ADMIN_READ, ADMIN_WRITE)
            .collect(Collectors.toCollection(HashSet::new)));

    private final Set<UserPermissions> permissions;

     UserRoles(Set<UserPermissions> permissions) {
    this.permissions = permissions;
    }
}
