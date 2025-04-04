package com.Tapia.Integrador_Park.Controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
@PreAuthorize("hasRole('USER')")
@CrossOrigin(origins = "http://localhost:5173")
public class UserController {

    @GetMapping("/dashboard")
    public String userDashboard() {
        return "Bienvenido al panel de usuario";
    }
}