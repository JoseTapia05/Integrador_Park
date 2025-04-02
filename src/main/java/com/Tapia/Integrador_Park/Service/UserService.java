package com.Tapia.Integrador_Park.Service;

import com.Tapia.Integrador_Park.Model.User;
import com.Tapia.Integrador_Park.Repository.UserRepository;
import com.Tapia.Integrador_Park.Role.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        initializeDefaultUsers();
    }

    private void initializeDefaultUsers() {
        if (userRepository.count() == 0) {
            userRepository.save(new User("admin", passwordEncoder.encode("admin123"), Role.ADMIN));
            userRepository.save(new User("user", passwordEncoder.encode("user123"), Role.USER));
            userRepository.save(new User("owner", passwordEncoder.encode("owner123"), Role.OWNER));
        }
    }

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public User registerUser(User user) {
        if (userRepository.existsByUsername(user.getUserName())) {
            throw new RuntimeException("Username already exists");
        }
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }
}