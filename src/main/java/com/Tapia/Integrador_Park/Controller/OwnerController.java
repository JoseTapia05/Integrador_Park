package com.Tapia.Integrador_Park.Controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/owner")
@PreAuthorize("hasRole('OWNER')")
@CrossOrigin(origins = "http://localhost:5173")
public class OwnerController {

    @GetMapping("/dashboard")
    public String ownerDashboard() {
        return "Bienvenido al panel de Propietario";
    }
}