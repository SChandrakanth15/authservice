package com.theelixrlabs.User.service;

import com.theelixrlabs.User.constants.UserConstant;
import com.theelixrlabs.User.model.Users;
import com.theelixrlabs.User.repository.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class UserService {
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);
    @Autowired
    private AuthenticationManager authManager;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private PasswordEncoder passwordEncoder;

    public String verify(Users user) {
        logger.info("Verifying user login for username: {}", user.getUsername()); // INFO log for login attempt
        Users foundUser = userRepo.findByUsername(user.getUsername());
        if (foundUser == null) {
            logger.warn("User not found: {}", user.getUsername());// WARN log for user not found
            return UserConstant.USER_NOT_FOUND;
        }

        if (!passwordEncoder.matches(user.getPassword(), foundUser.getPassword())) {
            logger.warn("Invalid password for User: {}", user.getUsername());// WARN log for incorrect password
            return UserConstant.INVALID_PASSWORD;
        }
        try {
            Authentication authentication = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword())
            );
            if (authentication.isAuthenticated()) {
                logger.debug("User Authenticated Successfully: {}", user.getUsername());  // DEBUG log for successful authentication
                return jwtService.generateToken(foundUser.getUsername());
            } else {
                logger.error("Authentication failed for the user: {}", user.getUsername()); // ERROR log for failed authentication
                return UserConstant.AUTHENTICATION_FAILED;
            }
        } catch (Exception e) {
            logger.error("Exception occured during authentication for user: {}", user.getUsername());// ERROR log for exception
            return UserConstant.AUTHENTICATION_FAILED;
        }
    }
}