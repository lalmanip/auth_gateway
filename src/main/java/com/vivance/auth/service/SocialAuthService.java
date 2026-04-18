package com.vivance.auth.service;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.vivance.auth.exception.AuthException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.net.URL;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

@Service
public class SocialAuthService {

    private final List<String> googleClientIds;
    private final String appleClientId;
    private final String appleIssuer;
    private final String appleKeysUrl;

    public SocialAuthService(
            @Value("${auth.google.client-ids}") String googleClientIds,
            @Value("${auth.apple.client-id}") String appleClientId,
            @Value("${auth.apple.issuer}") String appleIssuer,
            @Value("${auth.apple.keys-url}") String appleKeysUrl) {
        this.googleClientIds = Arrays.asList(googleClientIds.split(","));
        this.appleClientId = appleClientId;
        this.appleIssuer = appleIssuer;
        this.appleKeysUrl = appleKeysUrl;
    }

    public SocialUserInfo verifyGoogle(String idTokenString) {
        try {
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(
                    new NetHttpTransport(), GsonFactory.getDefaultInstance())
                    .setAudience(googleClientIds)
                    .build();

            GoogleIdToken idToken = verifier.verify(idTokenString);
            if (idToken == null) throw AuthException.unauthorized("Invalid Google ID token");

            GoogleIdToken.Payload payload = idToken.getPayload();
            return new SocialUserInfo(payload.getSubject(), payload.getEmail());
        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            throw AuthException.unauthorized("Google token verification failed: " + e.getMessage());
        }
    }

    public SocialUserInfo verifyApple(String identityToken) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(identityToken);
            JWKSet jwkSet = JWKSet.load(new URL(appleKeysUrl));
            RSAKey rsaKey = (RSAKey) jwkSet.getKeyByKeyId(signedJWT.getHeader().getKeyID());

            if (rsaKey == null) throw AuthException.unauthorized("Apple key ID not found");

            JWSVerifier verifier = new RSASSAVerifier(rsaKey);
            if (!signedJWT.verify(verifier)) throw AuthException.unauthorized("Apple token signature invalid");

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            if (!appleIssuer.equals(claims.getIssuer()))
                throw AuthException.unauthorized("Apple token issuer mismatch");

            if (!claims.getAudience().contains(appleClientId))
                throw AuthException.unauthorized("Apple token audience mismatch");

            if (new Date().after(claims.getExpirationTime()))
                throw AuthException.unauthorized("Apple token has expired");

            return new SocialUserInfo(claims.getSubject(), claims.getStringClaim("email"));
        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            throw AuthException.unauthorized("Apple token verification failed: " + e.getMessage());
        }
    }

    public record SocialUserInfo(String providerUid, String email) {}
}
