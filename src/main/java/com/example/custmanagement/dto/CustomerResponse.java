package com.example.custmanagement.dto;

import lombok.Builder;
import lombok.Data;

import java.time.Instant;

@Data
@Builder
public class CustomerResponse {
    private Long id;
    private String firstName;
    private String lastName;
    private String email;
    private String phone;
    private Instant createdAt;
    private Instant updatedAt;
    private String createdBy;
    private String encryptedId; // Encrypted id (AES-GCM base64url) for use by SPA when calling update/delete without exposing raw id
}
