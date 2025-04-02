package com.Tapia.Integrador_Park.Controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin")
@PreAuthorize("hasRole('ADMIN')")  // Uncommented and activated
public class AdminController {

    @GetMapping("/dashboard")
    public String adminDashboard() {
        return "Bienvenido al panel de administración";
    }
}