package com.drm.sandbox.security;

public record Tokens(String accessToken,
                     String accessTokenExpiry,
                     String refreshToken,
                     String refreshTokenExpiry) {
}
