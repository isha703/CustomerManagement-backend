package com.example.custmanagement.security;

import com.example.custmanagement.model.User;
import com.example.custmanagement.model.Role;
import com.example.custmanagement.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // treat the incoming identifier as email first (most clients send email), fall back to username
        User user = userRepository.findByEmail(username)
                .or(() -> userRepository.findByUsername(username))
                .orElseThrow(() -> new UsernameNotFoundException("User not found by email or username"));
        Set<GrantedAuthority> authorities = user.getRoles() == null ? Set.of() : user.getRoles().stream()
                .map(Role::getName)
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
        return org.springframework.security.core.userdetails.User.builder()
                // use email as the principal name so downstream code (Authentication.getName()) returns the email
                .username(user.getEmail() == null ? user.getUsername() : user.getEmail())
                .password(user.getPassword() == null ? "" : user.getPassword())
                .authorities(authorities)
                .accountLocked(false)
                .disabled(!user.isEnabled())
                .build();
    }
}
