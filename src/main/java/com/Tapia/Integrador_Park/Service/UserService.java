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
            userRepository.save(new User("admin", passwordEncoder.encode("admin123"), Role.ADMIN, AuthProvider.LOCAL));
            userRepository.save(new User("user", passwordEncoder.encode("user123"), Role.USER, AuthProvider.LOCAL));
            userRepository.save(new User("owner", passwordEncoder.encode("owner123"), Role.OWNER, AuthProvider.LOCAL));
        }
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

        // Solo codifica la contraseña si no es un usuario OAuth (que no tiene contraseña)
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
        user.setRole(Role.USER); // Rol por defecto
        user.setProvider(AuthProvider.LOCAL);

        return userRepository.save(user);
    }

    /**
     * Procesa un usuario que viene de autenticación con Google
     * - Si el usuario existe por email, lo actualiza
     * - Si no existe, lo crea como nuevo usuario
     */
    public User processGoogleUser(GoogleTokenPayload payload) {
        // Buscar por email primero
        return findByEmail(payload.getEmail())
                .map(existingUser -> {
                    // Actualizar datos del usuario existente si es necesario
                    if (existingUser.getFullName() == null) {
                        existingUser.setFullName(payload.getFullName());
                    }

                    return userRepository.save(existingUser);
                })
                .orElseGet(() -> {
                    // Crear nuevo usuario para Google
                    User newUser = new User();
                    newUser.setUsername(payload.getEmail()); // Usamos el email como username
                    newUser.setEmail(payload.getEmail());
                    newUser.setFullName(payload.getFullName());
                    newUser.setRole(Role.USER); // Rol por defecto
                    newUser.setProvider(AuthProvider.GOOGLE); // Indicamos que viene de Google
                    newUser.setPassword(null); // No tiene contraseña tradicional

                    return userRepository.save(newUser);
                });
    }

    public boolean existsByUsername(String username) {
        return userRepository.existsByUsername(username);
    }

    public boolean existsByEmail(String email) {
        return userRepository.existsByEmail(email);
    }
}