package org.banking.authserver.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.banking.authserver.service.AuthService;
import org.banking.dto.auth.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<APIResponse> register(@RequestBody RegisterRequest request) {
        AuthResponse response = authService.register(request);

        log.info("Registration Response: {}", response.toString());

        APIResponse apiResponse = new APIResponse(
                true,
                "Registration successful",
                HttpStatus.OK.value(), response
        );

        return ResponseEntity.ok(apiResponse);
    }

    @PostMapping("/login")
    public ResponseEntity<APIResponse> login(@RequestBody AuthRequest request) {
        AuthResponse response = authService.login(request);

        log.info("Response: {}", response.toString());

        APIResponse apiResponse = new APIResponse(
                true,
                "Login successful",
                HttpStatus.OK.value(),
                response
        );

        return ResponseEntity.ok(apiResponse);
    }

    @PostMapping("/refresh")
    public AuthResponse refresh(@RequestBody RefreshTokenRequest request) {
        return authService.refresh(request);
    }
}
