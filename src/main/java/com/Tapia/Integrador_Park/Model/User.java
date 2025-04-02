package com.Tapia.Integrador_Park.Model;

import com.Tapia.Integrador_Park.Role.Role;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "users")
public class User {
    private String id;
    private String username;
    private String password;
    private Role role;

    public User(){

    }

    public User(String username, String password, Role role) {
        this.username = username;
        this.password = password;
        this.role = role;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUserName() {
        return username;
    }

    public void setUserName(String userName) {
        this.username = userName;
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