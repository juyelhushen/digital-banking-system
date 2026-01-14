package org.banking.dto.auth;

public record RegisterRequest(
        String firstName,
        String lastName,
        String username,
        String password
) {
}
