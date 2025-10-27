package com.example.custmanagement.controller;

import com.example.custmanagement.dto.SetPasswordRequest;
import com.example.custmanagement.dto.TokenResponse;
import com.example.custmanagement.model.User;
import com.example.custmanagement.repository.UserRepository;
import com.example.custmanagement.security.JwtService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletResponse;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;

    @org.springframework.beans.factory.annotation.Value("${app.cookies.secure:false}")
    private boolean cookieSecureOverride;

    @PostMapping("/login")
    public ResponseEntity<Map<String, Object>> login(
            @RequestBody Map<String, String> reqBody,
            HttpServletResponse response,
            HttpServletRequest request) {

        String email = reqBody.get("email");
        String encryptedData = reqBody.get("data"); // Encrypted password payload

        if (email == null || email.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Email cannot be null or blank"));
        }
        if (encryptedData == null || encryptedData.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Password cannot be null or blank"));
        }

        try {
            // 🔐 Decrypt the encrypted password from frontend
            String decryptedPassword = jwtService.decryptPayload(encryptedData);

            // 🔎 Find user
            User user = userRepository.findByEmail(email).orElse(null);
            if (user == null) {
                return ResponseEntity.status(404).body(Map.of("error", "User not found"));
            }

            // 🧩 If user was created via OAuth only
            if (user.getPassword() == null || user.getPassword().isBlank()) {
                return ResponseEntity.status(403).body(Map.of("error", "account_password_required"));
            }

            // ✅ Authenticate with Spring Security
            try {
                Authentication auth = authenticationManager.authenticate(
                        new UsernamePasswordAuthenticationToken(email, decryptedPassword)
                );
                SecurityContextHolder.getContext().setAuthentication(auth);
            } catch (org.springframework.security.core.AuthenticationException ex) {
                return ResponseEntity.status(401).body(Map.of("error", "Invalid credentials"));
            }

            // 🔥 Generate JWT tokens using same logic as OAuth success
            String accessToken = jwtService.generateAccessToken(user);
            String refreshToken = jwtService.generateRefreshToken(user);

            boolean secure = request.isSecure() || cookieSecureOverride;
            String sameSite = secure ? "None" : "Lax";

            addCookieHeader(response, "access_token", accessToken, (int) jwtService.getExpiresIn(), secure, sameSite);
            addCookieHeader(response, "refresh_token", refreshToken, (int) jwtService.getRefreshExpiresIn(), secure, sameSite);

            Map<String, Object> userInfo = Map.of(
                    "id", user.getId(),
                    "username", user.getUsername(),
                    "email", user.getEmail(),
                    "roles", user.getRoles() == null ? List.of() :
                            user.getRoles().stream().map(r -> r.getName()).toList()
            );

            Map<String, Object> body = Map.of(
                    "success", true,
                    "user", userInfo
            );

            return ResponseEntity.ok(body);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of("error", "Internal server error: " + e.getMessage()));
        }
    }


    @PostMapping("/refresh")
    public ResponseEntity<TokenResponse> refresh(@RequestHeader(value = "Authorization", required = false) String authorization) {
        if (authorization == null || !authorization.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().build();
        }
        String refresh = authorization.substring(7);
        try {
            String username = jwtService.validateRefreshTokenAndGetSubject(refresh);
            User user = userRepository.findByUsername(username).orElse(null);
            if (user == null) return ResponseEntity.badRequest().build();

            // rotate: issue a new refresh token
            String newRefresh = jwtService.generateRefreshToken(user);
            String accessToken = jwtService.generateAccessToken(user);

            TokenResponse tr = TokenResponse.builder()
                    .accessToken(accessToken)
                    .expiresIn(jwtService.getExpiresIn())
                    .refreshToken(newRefresh)
                    .user(Map.of("username", user.getUsername()))
                    .build();
            return ResponseEntity.ok(tr);
        } catch (org.springframework.security.oauth2.jwt.JwtException ex) {
            return ResponseEntity.badRequest().build();
        }
    }


    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> me() {
        Authentication auth = org.springframework.security.core.context.SecurityContextHolder.getContext().getAuthentication();

        if (auth == null || !auth.isAuthenticated() || auth.getPrincipal() == null || "anonymousUser".equals(auth.getPrincipal())) {
            return ResponseEntity.status(401).build();
        }

        if (auth instanceof OAuth2AuthenticationToken oauthToken) {
            System.out.println("Auth class: " + auth.getClass());
            System.out.println("Principal: " + auth.getPrincipal());
            System.out.println("Is authenticated: " + auth.isAuthenticated());

            OAuth2User oauthUser = oauthToken.getPrincipal();

            // Extract email from attributes
            String email = (String) oauthUser.getAttribute("email");
            System.out.println("Extracted email: " + email);

            // Fetch user from DB
            User user = userRepository.findByEmail(email).orElse(null);
            if (user == null) {
                Map<String, Object> error = Map.of(
                        "error", "User not found in database",
                        "email", email == null ? "N/A" : email
                );
                return ResponseEntity.status(404).body(error);
            }

            Map<String, Object> payload = Map.of(
                    "username", user.getUsername(),
                    "email", user.getEmail() == null ? "" : user.getEmail(),
                    "name", user.getUsername(),
                    "roles", user.getRoles() == null ? List.of() : user.getRoles().stream().map(r -> r.getName()).toList()
            );

            // Serialize and encrypt payload for frontend consumption
            try {
                com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
                String json = mapper.writeValueAsString(payload);
                String enc = jwtService.encryptPayload(json);
                return ResponseEntity.ok(Map.of("enc", enc));
            } catch (Exception ex) {
                return ResponseEntity.status(500).body(Map.of("error", "failed_to_encrypt_payload"));
            }
        }

        return ResponseEntity.status(400).body(Map.of("error", "Unsupported authentication type"));
    }

    @PostMapping("/set-password")
    public ResponseEntity<String> setPassword(@RequestBody SetPasswordRequest req) {
        try {

            String decryptedPassword = jwtService.decryptPayload(req.getData());


            User user = userRepository.findByEmail(req.getEmail())
                    .orElseThrow(() -> new IllegalArgumentException("User not found"));


            String hashed = passwordEncoder.encode(decryptedPassword);


            user.setPassword(hashed);
            userRepository.save(user);

            return ResponseEntity.ok("Password updated successfully");
        } catch (Exception ex) {
            ex.printStackTrace();
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body("Failed to update password: " + ex.getMessage());
        }
    }
    private void addCookieHeader(HttpServletResponse response, String name, String value, int maxAge, boolean secure, String sameSite) {
        // Use ResponseCookie to ensure proper formatting including SameSite
        org.springframework.http.ResponseCookie cookie = org.springframework.http.ResponseCookie.from(name, value)
                .httpOnly(true)
                .secure(secure)
                .path("/")
                .maxAge(maxAge)
                .sameSite(sameSite)
                .build();
        String header = cookie.toString();
        response.addHeader("Set-Cookie", header);
        response.addHeader("X-Debug-Set-Cookie-" + name, header);

    }


}
