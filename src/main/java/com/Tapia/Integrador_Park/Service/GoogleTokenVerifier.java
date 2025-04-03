package com.Tapia.Integrador_Park.Service;

import com.Tapia.Integrador_Park.Exceptions.InvalidTokenException;
import com.Tapia.Integrador_Park.Model.GoogleTokenPayload;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import com.google.api.client.util.Value;
import org.springframework.stereotype.Service;

import java.util.Collections;

@Service
public class GoogleTokenVerifier {

    @Value("${google.client.id}")
    private String clientId;

    private final GoogleIdTokenVerifier verifier;

    public GoogleTokenVerifier() {
        this.verifier = new GoogleIdTokenVerifier.Builder(
                new NetHttpTransport(),
                new GsonFactory())
                .setAudience(Collections.singletonList(clientId))
                .build();
    }

    public GoogleTokenPayload verify(String idToken) throws InvalidTokenException {
        try {
            GoogleIdToken googleIdToken = verifier.verify(idToken);
            if (googleIdToken == null) {
                throw new InvalidTokenException("Token inválido");
            }

            GoogleIdToken.Payload payload = googleIdToken.getPayload();
            return new GoogleTokenPayload(payload);

        } catch (Exception e) {
            throw new InvalidTokenException("Error al verificar el token: " + e.getMessage());
        }
    }
}