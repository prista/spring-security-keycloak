package com.drm.sandbox.security;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.function.Function;

public class AccessTokenJwsStringSerializer implements Function<Token, String> {

    private final JWSSigner jwsSigner;
    private JWSAlgorithm jwsAlgorithm = JWSAlgorithm.HS256;

    public AccessTokenJwsStringSerializer(final JWSSigner jwsSigner,
                                          final JWSAlgorithm jwsAlgorithm) {
        this.jwsSigner = jwsSigner;
        this.jwsAlgorithm = jwsAlgorithm;
    }

    public AccessTokenJwsStringSerializer(final JWSSigner jwsSigner) {
        this.jwsSigner = jwsSigner;
    }

    @Override
    public String apply(final Token token) {
        var jwsHeader = new JWSHeader.Builder(this.jwsAlgorithm) // header
                .keyID(token.id().toString())
                .build();
        var claimsSet = new JWTClaimsSet.Builder() // payload
                .jwtID(token.id().toString())
                .subject(token.subject())
                .issueTime(Date.from(token.createdAt()))
                .expirationTime(Date.from(token.expiresAt()))
                .claim("authorities", token.authorities())
                .build();
        var signedJWT = new SignedJWT(jwsHeader, claimsSet); // signature
        try {
            signedJWT.sign(this.jwsSigner); // JWT - header.payload.signature (in Base64)
            return signedJWT.serialize();
        } catch (JOSEException e) {
            LoggerFactory.getLogger(AccessTokenJwsStringSerializer.class).error(e.getMessage(), e);
        }
        return null; // better throw exception
    }
}
