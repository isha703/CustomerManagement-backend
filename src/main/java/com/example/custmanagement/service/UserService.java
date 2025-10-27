package com.example.custmanagement.service;

import com.example.custmanagement.model.User;
import org.springframework.security.oauth2.core.user.OAuth2User;

public interface UserService {
    User findByUsername(String username);
    User createUserIfNotExistsFromOAuth(OAuth2User oauth2User);
}
