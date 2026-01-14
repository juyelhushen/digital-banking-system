package org.banking.authserver.service;

import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.banking.authserver.entity.RefreshToken;
import org.banking.authserver.entity.User;
import org.banking.authserver.repository.UserRepository;
import org.banking.authserver.security.JwtUtils;
import org.banking.dto.auth.*;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtUtils jwtUtils;
    private final RefreshTokenService refreshTokenService;

    public AuthResponse register(RegisterRequest request) {

        // 1️⃣ Validate username uniqueness
        if (userRepository.existsByUsername(request.username()))
            throw new IllegalArgumentException("Username already exists!!!");


        // 2️⃣ Create User
        User user = new User();
        user.setFirstName(request.firstName());
        user.setLastName(request.lastName());
        user.setUsername(request.username());
        user.setPassword(passwordEncoder.encode(request.password()));

        // Secure defaults
        user.setRole(Role.CUSTOMER);
        user.setEnabled(true);
        user.setAccountLocked(false);
        user.setFailedLoginAttempts(0);

        userRepository.save(user);

        // 3️⃣ Generate Access Token (JWT)
        String accessToken = jwtUtils.generateAccessToken(
                user.getId(),
                user.getUsername(),
                user.getRole()
        );

        // 4️⃣ Generate Refresh Token (DB-backed, hashed)
        String refreshToken = refreshTokenService.createRefreshToken(user);

        // 5️⃣ Return tokens
        return new AuthResponse(accessToken, refreshToken);
    }

    public AuthResponse login(AuthRequest request) {

        User user = userRepository.findByUsername(request.username())
                .orElseThrow(() -> new SecurityException("Invalid credentials"));

        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            throw new SecurityException("Invalid credentials");
        }

        // ROTATE old refresh tokens
        refreshTokenService.revokeAllForUser(user);

        String accessToken =
                jwtUtils.generateAccessToken(user.getId(), user.getUsername(), user.getRole());

        String refreshToken =
                refreshTokenService.createRefreshToken(user);

        return new AuthResponse(accessToken, refreshToken);
    }

    public AuthResponse refresh(RefreshTokenRequest request) {

        RefreshToken oldToken =
                refreshTokenService.validateRefreshToken(request.refreshToken());

        if (oldToken.getExpiryDate().isBefore(Instant.now())) {
            throw new SecurityException("Refresh token expired");
        }

        // ROTATION
        oldToken.setRevoked(true);

        User user = oldToken.getUser();

        String newAccessToken =
                jwtUtils.generateAccessToken(user.getId(), user.getUsername(), user.getRole());

        String newRefreshToken =
                refreshTokenService.createRefreshToken(user);

        return new AuthResponse(newAccessToken, newRefreshToken);
    }

    public void logout(User user) {
        refreshTokenService.revokeAllForUser(user);
    }
}
