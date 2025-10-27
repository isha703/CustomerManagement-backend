package com.example.custmanagement.dto;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class TokenResponse {
    private String accessToken;
    private long expiresIn;
    private String refreshToken;
    private Object user;
}
