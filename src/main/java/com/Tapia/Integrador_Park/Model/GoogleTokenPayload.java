package com.Tapia.Integrador_Park.Model;

import java.util.Map;

/**
 * Representa los datos del usuario obtenidos del token de Google OAuth2
 */
public class GoogleTokenPayload {
    private String googleId;          // ID único de Google (sub)
    private String email;            // Dirección de correo electrónico
    private String fullName;         // Nombre completo
    private String givenName;        // Primer nombre
    private String familyName;       // Apellido
    private String pictureUrl;       // URL de la imagen de perfil
    private String locale;           // Idioma/localización
    private boolean emailVerified;   // Si el email está verificado
    private String issuer;           // Quién emitió el token
    private long expirationTime;     // Tiempo de expiración (timestamp)
    private long issuedAt;           // Cuando fue emitido (timestamp)

    // Constructor basado en el mapa de claims del token
    public GoogleTokenPayload(Map<String, Object> claims) {
        this.googleId = (String) claims.get("sub");
        this.email = (String) claims.get("email");
        this.fullName = (String) claims.get("name");
        this.givenName = (String) claims.get("given_name");
        this.familyName = (String) claims.get("family_name");
        this.pictureUrl = (String) claims.get("picture");
        this.locale = (String) claims.get("locale");
        this.emailVerified = Boolean.TRUE.equals(claims.get("email_verified"));
        this.issuer = (String) claims.get("iss");
        this.expirationTime = Long.parseLong(claims.get("exp").toString());
        this.issuedAt = Long.parseLong(claims.get("iat").toString());
    }

    // Getters
    public String getGoogleId() {
        return googleId;
    }

    public String getEmail() {
        return email;
    }

    public String getFullName() {
        return fullName;
    }

    public String getGivenName() {
        return givenName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public String getPictureUrl() {
        return pictureUrl;
    }

    public String getLocale() {
        return locale;
    }

    public boolean isEmailVerified() {
        return emailVerified;
    }

    public String getIssuer() {
        return issuer;
    }

    public long getExpirationTime() {
        return expirationTime;
    }

    public long getIssuedAt() {
        return issuedAt;
    }

    // Métodos útiles
    public boolean isTokenExpired() {
        return System.currentTimeMillis() > (this.expirationTime * 1000);
    }

    public boolean isValidIssuer() {
        return this.issuer != null &&
                (this.issuer.equals("https://accounts.google.com") ||
                        this.issuer.equals("accounts.google.com"));
    }

    @Override
    public String toString() {
        return "GoogleTokenPayload{" +
                "googleId='" + googleId + '\'' +
                ", email='" + email + '\'' +
                ", fullName='" + fullName + '\'' +
                ", emailVerified=" + emailVerified +
                '}';
    }
}