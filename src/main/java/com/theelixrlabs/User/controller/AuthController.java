package com.theelixrlabs.User.controller;

import com.theelixrlabs.User.dto.LoginResponse;
import com.theelixrlabs.User.model.Users;
import com.theelixrlabs.User.service.JwtService;
import com.theelixrlabs.User.service.MyUserDetailsService;
import com.theelixrlabs.User.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final UserService userService;
    private final MyUserDetailsService userDetailsService;

    public AuthController(AuthenticationManager authenticationManager, JwtService jwtService, UserService userService, MyUserDetailsService userDetailsService) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.userService = userService;
        this.userDetailsService = userDetailsService;
    }

    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody Users users) {
        String response = userService.verify(users);
        if (response.equals("User not found")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("User is not Registered");
        } else if (response.equals("Invalid password")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("The Password is incorrect");
        } else {
            LoginResponse loginResponse = LoginResponse.builder()
                    .username(users.getUsername())
                    .token(response)
                    .build();
            // Return 200 OK with the JWT token
            return ResponseEntity.ok(loginResponse); // response contains the JWT token
        }
    }

    @PostMapping("/verify")
    public ResponseEntity<String> verifyToken(@RequestHeader("Authorization") String token) {
        try {
            // Extract the token (removing "Bearer " prefix)
            String jwtToken = token.substring(7);
            String username = jwtService.extractUserName(jwtToken); // Extract username from JWT

            if (username != null) {
                UserDetails user = userDetailsService.loadUserByUsername(username);
                boolean isValid = jwtService.validateToken(jwtToken, user);
                return isValid ? ResponseEntity.ok(username) : ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token is invalid");
            } else {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token is invalid");
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token is invalid");
        }
    }

}
