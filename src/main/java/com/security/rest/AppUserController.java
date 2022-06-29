package com.security.rest;


import com.security.model.AppUser;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/v1/user")
public class AppUserController {

    private static final List<AppUser> USERS = Arrays.asList(
            new AppUser("1", "user1"),
            new AppUser("2", "user2"),
            new AppUser("3", "user3")
    );

    @GetMapping("/info")
    public AppUser getUserInfo(@RequestParam("id") String id) {

        return USERS.stream()
                .filter(user -> id.equals(user.getId()))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("User " + id + " not found"));

    }


}
