package com.security.rest;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/public")
public class PublicInfoController {

    @GetMapping("/info")
    public ResponseEntity<String> getPublicInfo(){
        return ResponseEntity.ok("Public info exposed");
    }
}
