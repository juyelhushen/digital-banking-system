package org.banking.authserver.service;

import lombok.RequiredArgsConstructor;
import org.banking.authserver.entity.RefreshToken;
import org.banking.authserver.entity.User;
import org.banking.authserver.repository.RefreshTokenRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private final RefreshTokenRepository repository;
    private final PasswordEncoder encoder;
    private static final long REFRESH_TOKEN_DAYS = 30;

    public String createRefreshToken(User user) {
        String rawToken = UUID.randomUUID().toString();

        RefreshToken token = new RefreshToken();
        token.setUser(user);
        token.setTokenHash(encoder.encode(rawToken));
        token.setExpiryDate(Instant.now().plus(REFRESH_TOKEN_DAYS, ChronoUnit.DAYS));
        token.setRevoked(false);
        repository.save(token);

        return rawToken; // ONLY time raw token is visible
    }

    public RefreshToken validateRefreshToken(String rawToken) {
        return repository.findAll().stream()
                .filter(t -> !t.isRevoked())
                .filter(t -> encoder.matches(rawToken, t.getTokenHash()))
                .findFirst()
                .orElseThrow(() -> new SecurityException("Invalid refresh token"));
    }

    public void revokeAllForUser(User user) {
        repository.findByUserAndRevokedFalse(user)
                .forEach(t -> t.setRevoked(true));
    }
}
