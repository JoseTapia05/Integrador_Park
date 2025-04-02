package com.Tapia.Integrador_Park.Model;

import com.Tapia.Integrador_Park.Role.Role;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "users")
public class User {
    private Integer id;
    private String username;
    private String password;
    private Role role;

    public User(){

    }

    public User(Integer id, String username, String password, Role role) {
        this.id = id;
        this.username = username;
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