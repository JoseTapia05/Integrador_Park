package com.Tapia.Integrador_Park.Controller;

import com.Tapia.Integrador_Park.Exceptions.InvalidTokenException;
import com.Tapia.Integrador_Park.Model.*;
import com.Tapia.Integrador_Park.Role.Role;
import com.Tapia.Integrador_Park.Service.GoogleTokenVerifier;
import com.Tapia.Integrador_Park.Service.UserService;
import com.Tapia.Integrador_Park.Util.JwtUtil;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import java.util.Collections;
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
import java.util.HashMap;
import java.util.Map;

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
    public ResponseEntity<String> login(@RequestBody UserDTO user) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword())
        );

        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getUsername());
        String role = userDetails.getAuthorities().stream()
                .findFirst()
                .map(grantedAuthority -> grantedAuthority.getAuthority().replace("ROLE_", ""))
                .orElse("USER");

        String token = jwtUtil.generateToken(user.getUsername(), role);
        return ResponseEntity.ok(token);
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterDTO registerDTO) {
        try {
            User user = new User();
            user.setUsername(registerDTO.getUsername());
            user.setPassword(registerDTO.getPassword());
            user.setRole(registerDTO.getRole() != null ? registerDTO.getRole() : Role.USER);

            userService.registerUser(user);
            return ResponseEntity.ok("User registered successfully");
        } catch (RuntimeException e) {
            return ResponseEntity.badRequest().body(e.getMessage());
        }
    }

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
                    .setAudience(Collections.singletonList(idClient))  // Usa el clientId inyectado
                    .build();

            GoogleIdToken googleIdToken = verifier.verify(idToken);
            if (googleIdToken != null) {
                GoogleIdToken.Payload payload = googleIdToken.getPayload();

                // Extraer información del usuario
                String username = payload.getEmail();
                String name = (String) payload.get("name");
                String role = "USER";  // Rol por defecto o lógica personalizada

                // Generar JWT
                String jwt = jwtUtil.generateToken(username, role);

                // Construir respuesta
                Map<String, Object> body = new HashMap<>();
                body.put("token", jwt);
                body.put("username", username);
                body.put("name", name);
                body.put("role", role);

                return ResponseEntity.ok(body);
            } else {
                return ResponseEntity.badRequest().body("Token de Google inválido.");
            }
        } catch (GeneralSecurityException | IOException e) {
            e.printStackTrace();
            return ResponseEntity.internalServerError().body("Error al validar el token de Google.");
        }
    }
}