package com.Tapia.Integrador_Park.Service;

import com.Tapia.Integrador_Park.Model.User;
import com.Tapia.Integrador_Park.Role.Role;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class UserService {
    private final List<User> users;

    public UserService(PasswordEncoder passwordEncoder) {
        this.users = new ArrayList<>();
        initializeUsers(passwordEncoder);
    }

    private void initializeUsers(PasswordEncoder passwordEncoder) {
        this.users.addAll(List.of(
                new User(1, "admin", passwordEncoder.encode("admin123"), Role.ADMIN),
                new User(2, "user", passwordEncoder.encode("user123"), Role.USER),
                new User(3, "owner", passwordEncoder.encode("owner123"), Role.OWNER)
        ));
    }

    public Optional<User> findByUsername(String username) {
        return users.stream()
                .filter(user -> user.getUserName().equals(username))
                .findFirst();
    }
}