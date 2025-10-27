package com.example.custmanagement.security;

import com.example.custmanagement.model.User;
import com.example.custmanagement.model.Role;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class JwtService {
    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;

    @Value("${JWT_EXPIRES_IN:3600}")
    private long expiresIn;

    @Value("${JWT_REFRESH_EXPIRES_IN:604800}") // default 7 days
    private long refreshExpiresIn;

    @Value("${JWT_SECRET:}")
    private String jwtSecret;
    private static final Logger log = LoggerFactory.getLogger(JwtService.class);


    public JwtService(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder) {
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
    }

     public String generateAccessToken(User user) {
        Instant now = Instant.now();
        Set<String> roles = (user.getRoles() == null || user.getRoles().isEmpty())
                ? Collections.emptySet()
                : user.getRoles().stream().map(Role::getName).collect(Collectors.toSet());

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expiresIn))
                .subject(user.getUsername())
                .claim("username", user.getUsername())
                .claim("roles", roles)
                .claim("type", "access")
                .build();

        try {
            return jwtEncoder.encode(org.springframework.security.oauth2.jwt.JwtEncoderParameters.from(claims)).getTokenValue();
        } catch (org.springframework.security.oauth2.jwt.JwtEncodingException ex) {
            // Fallback: manual HS256 compact JWT encoding using configured secret
            log.warn("JwtEncoder failed, falling back to manual HS256 encoding: {}", ex.getMessage());
            return manualEncode(claims);
        }
     }

     public String generateRefreshToken(User user) {
        Instant now = Instant.now();
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(refreshExpiresIn))
                .subject(user.getUsername())
                .claim("type", "refresh")
                .build();

        try {
            return jwtEncoder.encode(org.springframework.security.oauth2.jwt.JwtEncoderParameters.from(claims)).getTokenValue();
        } catch (org.springframework.security.oauth2.jwt.JwtEncodingException ex) {
            log.warn("JwtEncoder failed, falling back to manual HS256 encoding for refresh token: {}", ex.getMessage());
            return manualEncode(claims);
        }
     }

    // Manual compact HS256 encode using jwtSecret as base64 or raw bytes
    private String manualEncode(JwtClaimsSet claims) {
        try {
            com.fasterxml.jackson.databind.ObjectMapper mapper = new com.fasterxml.jackson.databind.ObjectMapper();
            mapper.findAndRegisterModules();

            Map<String, Object> header = new HashMap<>();
            header.put("alg", "HS256");
            header.put("typ", "JWT");

            String headerJson = mapper.writeValueAsString(header);
            Map<String, Object> payload = new HashMap<>(claims.getClaims());
            // ensure standard claims are present and in proper types
            if (claims.getSubject() != null) payload.put("sub", claims.getSubject());
            if (claims.getIssuedAt() != null) payload.put("iat", claims.getIssuedAt().getEpochSecond());
            if (claims.getExpiresAt() != null) payload.put("exp", claims.getExpiresAt().getEpochSecond());
            // avoid JwtClaimsSet.getIssuer() which may attempt URL conversion; use raw claim if present
            Object issObj = claims.getClaims().get("iss");
            if (issObj != null) payload.put("iss", issObj.toString());
            // Add a jti if not provided to help with single-use or tracking if needed
            if (!payload.containsKey("jti")) payload.put("jti", java.util.UUID.randomUUID().toString());

            String headerB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(headerJson.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String payloadJson = mapper.writeValueAsString(payload);
            String payloadB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(payloadJson.getBytes(java.nio.charset.StandardCharsets.UTF_8));

            String signingInput = headerB64 + "." + payloadB64;

            byte[] keyBytes;
            try {
                keyBytes = java.util.Base64.getDecoder().decode(jwtSecret);
            } catch (IllegalArgumentException ex) {
                keyBytes = jwtSecret.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            }

            javax.crypto.Mac mac = javax.crypto.Mac.getInstance("HmacSHA256");
            javax.crypto.spec.SecretKeySpec secretKey = new javax.crypto.spec.SecretKeySpec(keyBytes, "HmacSHA256");
            mac.init(secretKey);
            byte[] sig = mac.doFinal(signingInput.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            String sigB64 = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(sig);

            return signingInput + "." + sigB64;
        } catch (Exception e) {
            throw new RuntimeException("Manual JWT encoding failed", e);
        }
    }

    /**
     * Validate a refresh token and return the subject (username).
     * Throws org.springframework.security.oauth2.jwt.JwtException on invalid/expired token.
     */
    public String validateRefreshTokenAndGetSubject(String token) {
        Jwt jwt = jwtDecoder.decode(token);
        Object type = jwt.getClaims().get("type");
        if (type == null || !"refresh".equals(type.toString())) {
            throw new org.springframework.security.oauth2.jwt.JwtException("Not a refresh token");
        }
        return jwt.getSubject();
    }

    /**
     * Decode any JWT (access or refresh). Caller must inspect claims.
     * Throws JwtException on invalid/expired token.
     */
    public Jwt decodeJwt(String token) {
        return jwtDecoder.decode(token);
    }

    /**
     * Encrypt a small plaintext (token) for safe transfer to frontend.
     * Returns base64(iv || ciphertext).
     */
    public String encryptPayload(String plaintext) {
        try {
            if (jwtSecret == null || jwtSecret.isBlank()) {
                throw new IllegalStateException("JWT_SECRET must be set to encrypt payload");
            }
            // jwtSecret is expected to be base64 (as set in application.yml)
            byte[] keyBytes;
            try {
                keyBytes = java.util.Base64.getDecoder().decode(jwtSecret);
            } catch (IllegalArgumentException ex) {
                // fallback: use raw bytes of secret string (not recommended)
                keyBytes = jwtSecret.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            }
            // Use first 16/24/32 bytes depending on key length
            int keyLen = Math.min(keyBytes.length, 32);
            byte[] aesKey = new byte[keyLen];
            System.arraycopy(keyBytes, 0, aesKey, 0, keyLen);
            SecretKey key = new SecretKeySpec(aesKey, "AES");

            byte[] iv = new byte[12]; // GCM nonce
            SecureRandom rnd = new SecureRandom();
            rnd.nextBytes(iv);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.ENCRYPT_MODE, key, spec);
            byte[] cipherText = cipher.doFinal(plaintext.getBytes(java.nio.charset.StandardCharsets.UTF_8));

            byte[] out = new byte[iv.length + cipherText.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(cipherText, 0, out, iv.length, cipherText.length);

            return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(out);
        } catch (Exception ex) {
            throw new RuntimeException("Failed to encrypt payload", ex);
        }
    }

    /**
     * Decrypt a payload previously produced by encryptPayload.
     * Accepts base64url(iv || ciphertext) and returns plaintext string.
     */
    public String decryptPayload(String encrypted) {
        try {
            if (jwtSecret == null || jwtSecret.isBlank()) {
                throw new IllegalStateException("JWT_SECRET must be set to decrypt payload");
            }
            byte[] keyBytes;
            try {
                keyBytes = java.util.Base64.getDecoder().decode(jwtSecret);
            } catch (IllegalArgumentException ex) {
                keyBytes = jwtSecret.getBytes(java.nio.charset.StandardCharsets.UTF_8);
            }
            int keyLen = Math.min(keyBytes.length, 32);
            byte[] aesKey = new byte[keyLen];
            System.arraycopy(keyBytes, 0, aesKey, 0, keyLen);
            SecretKey key = new SecretKeySpec(aesKey, "AES");

            byte[] in = java.util.Base64.getUrlDecoder().decode(encrypted);
            if (in.length < 12) throw new IllegalArgumentException("Invalid encrypted payload");
            byte[] iv = java.util.Arrays.copyOfRange(in, 0, 12);
            byte[] cipherText = java.util.Arrays.copyOfRange(in, 12, in.length);

            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec spec = new GCMParameterSpec(128, iv);
            cipher.init(Cipher.DECRYPT_MODE, key, spec);
            byte[] plain = cipher.doFinal(cipherText);
            return new String(plain, java.nio.charset.StandardCharsets.UTF_8);
        } catch (Exception ex) {
            throw new RuntimeException("Failed to decrypt payload", ex);
        }
    }

    public long getExpiresIn() {
        return expiresIn;
    }

    public long getRefreshExpiresIn() {
        return refreshExpiresIn;
    }
}
