package com.security.rest;

import com.security.model.AppUser;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/v1/user")
public class CrudController {

    private static final List<AppUser> USERS = Arrays.asList(
            new AppUser("1", "user1"),
            new AppUser("2", "user2"),
            new AppUser("3", "user3")
    );

    @GetMapping("/all")
    public ResponseEntity<List<AppUser>> findAllUsers(){

        return ResponseEntity.ok(USERS);
    }
    @PostMapping("/create")
    public ResponseEntity<String> createUser(@RequestBody AppUser user){

        return ResponseEntity.ok("userCreated");
    }

    @DeleteMapping("/delete")
    public ResponseEntity<String> deleteUser(@RequestParam String id){

        return ResponseEntity.ok("user deleted");
    }

    @PutMapping("/update")
    public ResponseEntity<String> update(@RequestParam String id, @RequestBody AppUser user) {

        return ResponseEntity.ok("user created");
    }
}
