package com.drm.sandbox.security;

import com.drm.sandbox.Token;
import com.nimbusds.jose.*;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.util.Date;
import java.util.function.Function;

@Slf4j
@RequiredArgsConstructor
@AllArgsConstructor
public class TokenCookieJweStringSerializer
        implements Function<Token, String> {

    private final JWEEncrypter jweEncrypter;
    @Setter
    private JWEAlgorithm jweAlgorithm = JWEAlgorithm.DIR;
    @Setter
    private EncryptionMethod encryptionMethod = EncryptionMethod.A128GCM;

    @Override
    public String apply(Token token) {
        var jwsHeader = new JWEHeader.Builder(this.jweAlgorithm, this.encryptionMethod) // JWE header (alg + enc + kid)
                .keyID(token.id().toString())
                .build();
        var claimsSet = new JWTClaimsSet.Builder() // payload (JWT claims)
                .jwtID(token.id().toString())
                .subject(token.subject())
                .issueTime(Date.from(token.createdAt()))
                .expirationTime(Date.from(token.expiresAt()))
                .claim("authorities", token.authorities())
                .build();
        var encryptedJWT = new EncryptedJWT(jwsHeader, claimsSet); // combine header + claims, not yet encrypted
        try {
            encryptedJWT.encrypt(this.jweEncrypter);  // produces 5-part JWE: header.encKey.iv.ciphertext.tag (Base64)

            return encryptedJWT.serialize();
        } catch (JOSEException exception) {
            log.error(exception.getMessage(), exception);
        }

        return null; // TODO: better to throw instead of returning null
    }
}
