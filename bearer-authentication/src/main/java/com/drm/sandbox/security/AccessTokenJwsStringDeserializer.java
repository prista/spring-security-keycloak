package com.drm.sandbox.security;

import com.drm.sandbox.Token;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.SignedJWT;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.text.ParseException;
import java.util.UUID;
import java.util.function.Function;

@Slf4j
@RequiredArgsConstructor
public class AccessTokenJwsStringDeserializer implements Function<String, Token> {

    private final JWSVerifier jwsVerifier;

    @Override
    public Token apply(String s) {
        try {
            var signedJWT = SignedJWT.parse(s);
            if (signedJWT.verify(this.jwsVerifier)) {
                var jwtClaimsSet = signedJWT.getJWTClaimsSet();
                return new Token(UUID.fromString(
                        jwtClaimsSet.getJWTID()),
                        jwtClaimsSet.getSubject(),
                        jwtClaimsSet.getStringListClaim("authorities"),
                        jwtClaimsSet.getIssueTime().toInstant(),
                        jwtClaimsSet.getExpirationTime().toInstant());
            }
        } catch (ParseException | JOSEException e) {
            log.error(e.getMessage(), e);
        }
        return null;
    }
}
