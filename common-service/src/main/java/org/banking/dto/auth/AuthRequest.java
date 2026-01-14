package org.banking.dto.auth;

public record AuthRequest(
        String username,
        String password
) {
}
