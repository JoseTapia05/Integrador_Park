package com.Tapia.Integrador_Park.Service;

import com.Tapia.Integrador_Park.Exceptions.UserAlreadyExistsException;
import com.Tapia.Integrador_Park.Model.GoogleTokenPayload;
import com.Tapia.Integrador_Park.Model.RegisterDTO;
import com.Tapia.Integrador_Park.Model.User;
import com.Tapia.Integrador_Park.Repository.UserRepository;
import com.Tapia.Integrador_Park.Role.AuthProvider;
import com.Tapia.Integrador_Park.Role.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsername(username);
    }

    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public User registerUser(User user) {
        if (userRepository.existsByUsername(user.getUsername())) {
            throw new UserAlreadyExistsException("Username already exists");
        }
        if (user.getEmail() != null && userRepository.existsByEmail(user.getEmail())) {
            throw new UserAlreadyExistsException("Email already registered");
        }

        if (user.getPassword() != null) {
            user.setPassword(passwordEncoder.encode(user.getPassword()));
        }

        return userRepository.save(user);
    }

    public User registerLocalUser(RegisterDTO registerDTO) {
        User user = new User();
        user.setUsername(registerDTO.getUsername());
        user.setPassword(passwordEncoder.encode(registerDTO.getPassword()));
        user.setEmail(registerDTO.getEmail());
        user.setRole(Role.USER);
        user.setProvider(AuthProvider.LOCAL);

        return userRepository.save(user);
    }

    public User processGoogleUser(GoogleTokenPayload payload) {
        return findByEmail(payload.getEmail())
                .map(existingUser -> {
                    if (existingUser.getFullName() == null) {
                        existingUser.setFullName(payload.getFullName());
                    }

                    return userRepository.save(existingUser);
                })
                .orElseGet(() -> {
                    User newUser = new User();
                    newUser.setUsername(payload.getEmail()); // Usamos el email como username
                    newUser.setEmail(payload.getEmail());
                    newUser.setFullName(payload.getFullName());
                    newUser.setRole(Role.USER);
                    newUser.setProvider(AuthProvider.GOOGLE);
                    newUser.setPassword(null);

                    return userRepository.save(newUser);
                });
    }

    public void updateUserPassword(User user, String newPassword) {
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }

    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }
}