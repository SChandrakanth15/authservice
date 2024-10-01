package com.theelixrlabs.User.service;

import com.theelixrlabs.User.constants.UserConstant;
import com.theelixrlabs.User.model.Users;
import com.theelixrlabs.User.repository.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepo userRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Users user = userRepo.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException(UserConstant.USER_NOT_FOUND);
        }
        return User.builder()
                .username(user.getUsername())
                .password(user.getPassword())
                .build(); // Return the Users instance directly
    }
}