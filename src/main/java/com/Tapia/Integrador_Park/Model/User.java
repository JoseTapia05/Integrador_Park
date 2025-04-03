package com.Tapia.Integrador_Park.Model;

import com.Tapia.Integrador_Park.Role.AuthProvider;
import com.Tapia.Integrador_Park.Role.Role;
import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "users")
public class User {
    @Id
    private String id;
    @Indexed(unique = true)
    private String username;
    private String password;
    private Role role;
    @Indexed(unique = true, sparse = true)
    private String email;
    private String fullName;
    private String pictureUrl;
    private AuthProvider provider;

    public User(){

    }

    // Constructor para registro tradicional
    public User(String username, String password, Role role, AuthProvider authProvider) {
        this.username = username;
        this.password = password;
        this.role = role;
        this.provider = authProvider;
    }

    // Constructor para OAuth
    public User(String email, Role role, AuthProvider authProvider) {
        this.username = email; // Usamos email como username
        this.email = email;
        this.role = role;
        this.provider = authProvider;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
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

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getPictureUrl() {
        return pictureUrl;
    }

    public void setPictureUrl(String pictureUrl) {
        this.pictureUrl = pictureUrl;
    }

    public AuthProvider getProvider() {
        return provider;
    }

    public void setProvider(AuthProvider provider) {
        this.provider = provider;
    }
}