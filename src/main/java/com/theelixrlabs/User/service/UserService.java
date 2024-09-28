package com.theelixrlabs.User.service;

import com.theelixrlabs.User.model.Users;
import com.theelixrlabs.User.repository.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    @Autowired
    private AuthenticationManager authManager;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserRepo userRepo; // Assuming you have a UserRepo for database access

    @Autowired
    private PasswordEncoder passwordEncoder; // Use your password encoder

    public String verify(Users user) {
        // Fetch user from the database
        Users foundUser = userRepo.findByUsername(user.getUsername());
        if (foundUser == null) {
            return "User not found"; // Handle user not found case
        }

        // Check if the provided password matches the stored password
        if (!passwordEncoder.matches(user.getPassword(), foundUser.getPassword())) {
            return "Invalid password"; // Handle password mismatch case
        }

        // Authenticate the user
        Authentication authentication = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword())
        );

        if (authentication.isAuthenticated()) {
            return jwtService.generateToken(foundUser.getUsername());
        } else {
            return "Authentication failed"; // Handle general authentication failure
        }
    }
}
