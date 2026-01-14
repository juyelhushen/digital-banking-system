package org.banking.dto.auth;

public record APIResponse(
        boolean success,
        String message,
        int code,
        Object data
) {
    public APIResponse(boolean success, String message, int code, Object data) {
        this.success = success;
        this.message = message;
        this.code = code;
        this.data = data;
    }
}