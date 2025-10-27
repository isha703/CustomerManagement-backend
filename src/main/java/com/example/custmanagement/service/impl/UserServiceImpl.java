package com.example.custmanagement.service.impl;

import com.example.custmanagement.model.User;
import com.example.custmanagement.model.Role;
import com.example.custmanagement.repository.UserRepository;
import com.example.custmanagement.repository.RoleRepository;
import com.example.custmanagement.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.Set;
import java.util.HashSet;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    @Override
    public User findByUsername(String username) {
        return userRepository.findByUsername(username).orElse(null);
    }
    @Override
    public User createUserIfNotExistsFromOAuth(OAuth2User oauth2User) {
        String email = (String) oauth2User.getAttributes().getOrDefault("email", oauth2User.getName());
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("OAuth2 user does not have an email attribute");
        }

        // Extract user name (Google provides 'name' or 'given_name')
        String name = (String) oauth2User.getAttributes().getOrDefault(
                "name", oauth2User.getAttributes().getOrDefault("given_name", email)
        );

        // Check if the user already exists by email
        Optional<User> existingUser = userRepository.findByEmail(email);
        if (existingUser.isPresent()) {
            return existingUser.get();
        }

        // Ensure default role exists
        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseGet(() -> roleRepository.save(Role.builder().name("ROLE_USER").build()));

        // Create new user entry
        User newUser = User.builder()
                .username(name)           // Full name from Google
                .email(email)             // Google email
                .password(null)           // No password for OAuth users
                .enabled(true)
                .roles(Set.of(userRole))
                .createdAt(Instant.now())
                .updatedAt(Instant.now())
                .registered_by("GOOGLE")   // Indicate registration method
                .build();

        return userRepository.save(newUser);
    }



}
