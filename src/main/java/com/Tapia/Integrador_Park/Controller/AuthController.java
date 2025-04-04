package com.Tapia.Integrador_Park.Controller;

import com.Tapia.Integrador_Park.Exceptions.InvalidTokenException;
import com.Tapia.Integrador_Park.Exceptions.UserAlreadyExistsException;
import com.Tapia.Integrador_Park.Model.*;
import com.Tapia.Integrador_Park.Role.AuthProvider;
import com.Tapia.Integrador_Park.Role.Role;
import com.Tapia.Integrador_Park.Service.GoogleTokenVerifier;
import com.Tapia.Integrador_Park.Service.UserService;
import com.Tapia.Integrador_Park.Util.JwtUtil;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;

import java.util.*;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.beans.factory.annotation.Value;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collections;

@RestController
@RequestMapping("/auth")
public class AuthController {

    @Value("${google.client.id}")  // Inyección desde properties
    private String idClient;

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    private final UserService userService;
    private final GoogleTokenVerifier googleTokenVerifier;

    public AuthController(
            AuthenticationManager authenticationManager,
            JwtUtil jwtUtil,
            UserDetailsService userDetailsService,
            UserService userService,
            GoogleTokenVerifier googleTokenVerifier) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
        this.userService = userService;
        this.googleTokenVerifier = googleTokenVerifier;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody UserDTO user) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword())
        );

        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        String role = userDetails.getAuthorities().stream()
                .findFirst()
                .map(grantedAuthority -> grantedAuthority.getAuthority().replace("ROLE_", ""))
                .orElse("USER");

        String token = jwtUtil.generateToken(user.getUsername(), role);

        // Crear respuesta con token y datos del usuario
        Map<String, Object> response = new HashMap<>();
        response.put("token", token);
        response.put("user", Map.of(
                "username", user.getUsername(),
                "role", role
        ));

        return ResponseEntity.ok(response);
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterDTO registerDTO) {
        try {
            User user = new User();
            user.setUsername(registerDTO.getUsername());
            user.setPassword(registerDTO.getPassword());
            user.setRole(registerDTO.getRole() != null ? registerDTO.getRole() : Role.USER);
            user.setEmail(registerDTO.getEmail());
            user.setProvider(AuthProvider.LOCAL);

            userService.registerUser(user);
            return ResponseEntity.ok("User registered successfully");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    @PostMapping("/google-login")
    public ResponseEntity<?> googleLogin(@RequestBody Map<String, String> request) {
        System.out.println("Intentando validar token de Google...");

        String idToken = request.get("idToken");
        if (idToken == null) {
            return ResponseEntity.badRequest().body("El token de Google no puede estar vacío.");
        }

        try {
            GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier.Builder(
                    new NetHttpTransport(),
                    JacksonFactory.getDefaultInstance())
                    .setAudience(Collections.singletonList(idClient))
                    .build();

            GoogleIdToken googleIdToken = verifier.verify(idToken);
            if (googleIdToken != null) {
                GoogleIdToken.Payload payload = googleIdToken.getPayload();

                // Extraer información del usuario
                String email = payload.getEmail();
                String name = (String) payload.get("name");

                // Verificar si el usuario ya existe
                Optional<User> existingUser = userService.findByEmail(email);

                User user;
                if (existingUser.isPresent()) {
                    // Usuario existe, lo actualizamos si es necesario
                    user = existingUser.get();
                    if (user.getFullName() == null || !user.getFullName().equals(name)) {
                        user.setFullName(name);
                        user = userService.registerUser(user);
                    }
                } else {
                    // Usuario no existe, lo creamos
                    user = new User();
                    user.setUsername(email);
                    user.setEmail(email);
                    user.setFullName(name);
                    user.setRole(Role.USER); // Rol por defecto
                    user.setProvider(AuthProvider.GOOGLE);
                    user = userService.registerUser(user);
                }

                // Generar JWT con el rol actual del usuario
                String jwt = jwtUtil.generateToken(user.getUsername(), user.getRole().name());

                // Construir respuesta
                Map<String, Object> body = new HashMap<>();
                body.put("token", jwt);
                body.put("user", Map.of(
                        "username", user.getUsername(),
                        "name", user.getFullName(),
                        "email", user.getEmail(),
                        "role", user.getRole().name()
                ));

                return ResponseEntity.ok(body);
            } else {
                return ResponseEntity.badRequest().body("Token de Google inválido.");
            }
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("Error al validar el token de Google.");
        } catch (UserAlreadyExistsException e) {
            // Esto no debería ocurrir ya que verificamos antes de crear
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

    //ENDPOINT OPCIONAL/ALTERNATIVO AL PRIMERO - NO TIENE USO//
    @PostMapping("/oauth2/google")
    public ResponseEntity<?> handleGoogleLogin(@RequestBody GoogleAuthRequest request) {
        try {
            // 1. Verificar token y obtener payload
            GoogleTokenPayload payload = googleTokenVerifier.verify(request.getToken());

            // 2. Validaciones adicionales
            if (!payload.isEmailVerified()) {
                return ResponseEntity.badRequest().body("Email no verificado");
            }

            if (payload.isTokenExpired()) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Token expirado");
            }

            // 3. Crear/actualizar usuario en tu sistema
            User user = userService.processGoogleUser(payload);

            // 4. Generar tu JWT
            String jwtToken = jwtUtil.generateToken(user.getUsername(), user.getRole().name());

            return ResponseEntity.ok(new AuthResponse(jwtToken, user.getRole().name()));

        } catch (InvalidTokenException e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(e.getMessage());
        }
    }
}