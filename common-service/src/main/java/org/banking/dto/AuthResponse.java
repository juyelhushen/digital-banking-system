package org.banking.dto;

public record AuthResponse(
        String accessToken,
        String refreshToken
) {}

