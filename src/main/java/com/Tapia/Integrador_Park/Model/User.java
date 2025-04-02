package com.Tapia.Integrador_Park.Model;

import com.Tapia.Integrador_Park.Role.Role;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "users")
public class User {
    private Integer id;
    private String userName;  // Consider renaming to 'username' for Spring Security compatibility
    private String password;
    private Role role;       // Assuming Role is an enum (ADMIN, USER, etc.)

    public User(Integer id, String userName, String password, Role role) {
        this.id = id;
        this.userName = userName;
        this.password = password;
        this.role = role;
    }

    public Integer getId() {
        return id;
    }

    public void setId(Integer id) {
        this.id = id;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
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