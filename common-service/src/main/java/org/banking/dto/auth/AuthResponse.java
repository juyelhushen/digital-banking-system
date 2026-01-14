package org.banking.dto.auth;

public record AuthResponse(
        String accessToken,
        String refreshToken
) {}

