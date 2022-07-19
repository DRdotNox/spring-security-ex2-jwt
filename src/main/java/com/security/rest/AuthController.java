package com.security.rest;


import com.security.config.security.jwt.UsernamePasswordAuthRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.NoSuchElementException;

@RestController
@RequestMapping("/")

public class AuthController {

    private final UserDetailsService userDetailsService;

    @Autowired
    public AuthController(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/auth")
    public ResponseEntity<?> authenticate(@RequestBody UsernamePasswordAuthRequest request) {
        try {
            userDetailsService.loadUserByUsername(request.getUsername());

        } catch (NoSuchElementException e) {
            return ResponseEntity.ok().build();
        }
        return ResponseEntity.ok().build();
    }
}
