package com.drm.sandbox.security;

import com.drm.sandbox.Token;
import com.nimbusds.jose.*;
import com.nimbusds.jwt.EncryptedJWT;
import com.nimbusds.jwt.JWTClaimsSet;
import lombok.Setter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Date;
import java.util.function.Function;

public class RefreshTokenJweStringSerializer implements Function<Token, String> {

    private final JWEEncrypter jweEncrypter;
    @Setter
    private JWEAlgorithm jweAlgorithm = JWEAlgorithm.DIR;
    @Setter
    private EncryptionMethod encryptionMethod = EncryptionMethod.A128GCM;
    private Logger logger = LoggerFactory.getLogger(RefreshTokenJweStringSerializer.class);

    public RefreshTokenJweStringSerializer(JWEEncrypter jweEncrypter) {
        this.jweEncrypter = jweEncrypter;
    }

    public RefreshTokenJweStringSerializer(final JWEEncrypter jweEncrypter,
                                           final JWEAlgorithm jweAlgorithm,
                                           final EncryptionMethod encryptionMethod) {
        this.jweEncrypter = jweEncrypter;
        this.jweAlgorithm = jweAlgorithm;
        this.encryptionMethod = encryptionMethod;
    }

    @Override
    public String apply(final Token token) {
        var jweHeader = new JWEHeader.Builder(this.jweAlgorithm, this.encryptionMethod) // JWE header (alg + enc + kid)
                .keyID(token.id().toString())
                .build();
        var claimsSet = new JWTClaimsSet.Builder() // payload (JWT claims)
                .jwtID(token.id().toString())
                .subject(token.subject())
                .issueTime(Date.from(token.createdAt()))
                .expirationTime(Date.from(token.expiresAt()))
                .claim("authorities", token.authorities())
                .build();
        var encryptedJWT = new EncryptedJWT(jweHeader, claimsSet); // combine header + claims, not yet encrypted
        try {
            encryptedJWT.encrypt(this.jweEncrypter); // produces 5-part JWE: header.encKey.iv.ciphertext.tag (Base64)
            return encryptedJWT.serialize();
        } catch (JOSEException e) {
            logger.error(e.getMessage(), e);
        }
        return null; // TODO: better to throw instead of returning null
    }
}
