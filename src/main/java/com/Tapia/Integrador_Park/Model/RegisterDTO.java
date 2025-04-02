package com.Tapia.Integrador_Park.Model;

import com.Tapia.Integrador_Park.Role.Role;

public class RegisterDTO {
    private String username;
    private String password;
    private Role role;

    public RegisterDTO() {
    }

    public RegisterDTO(String username, String password, Role role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Role getRole() {
        return role;
    }

    public void setRole(Role role) {
        this.role = role;
    }
}
