package com.Tapia.Integrador_Park.Model;

import jakarta.validation.constraints.NotBlank;

public class GoogleAuthRequest {
    @NotBlank
    private String token;

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }
}
