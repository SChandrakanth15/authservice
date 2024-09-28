package com.theelixrlabs.User.repository;

import com.theelixrlabs.User.model.Users;
import org.springframework.data.mongodb.repository.MongoRepository;

import java.util.UUID;


public interface UserRepo extends MongoRepository<Users, UUID> {
    Users findByUsername(String username);
}
