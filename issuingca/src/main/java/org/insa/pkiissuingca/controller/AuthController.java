package org.insa.pkiissuingca.controller;

import org.insa.pkiissuingca.dto.LoginRequest;
import org.insa.pkiissuingca.dto.LoginResponse;
import org.insa.pkiissuingca.model.Role;
import org.insa.pkiissuingca.model.User;
import org.insa.pkiissuingca.repository.UserRepository;
import org.insa.pkiissuingca.security.JwtUtil;
import org.insa.pkiissuingca.service.AuditService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/auth")
public class AuthController {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private AuditService auditService;

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest loginRequest) {
        User user = userRepository.findByUsername(loginRequest.getUsername()).orElse(null);

        if (user == null || !passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            auditService.log(loginRequest.getUsername(), "LOGIN", "Failed login attempt", "FAILURE", "127.0.0.1");
            return ResponseEntity.status(401).body("Invalid username or password");
        }

        if (!user.isEnabled()) {
            auditService.log(loginRequest.getUsername(), "LOGIN", "Disabled user login attempt", "FAILURE", "127.0.0.1");
            return ResponseEntity.status(403).body("User account is disabled");
        }

        // Get the first role or default role
        String roleName = user.getRoles().stream()
                .findFirst()
                .map(Role::getName)
                .orElse("ROLE_END_ENTITY");

        try {
            String token = jwtUtil.generateToken(user.getUsername(), roleName);
            auditService.log(user.getUsername(), "LOGIN", "Successful login", "SUCCESS", "127.0.0.1");
            return ResponseEntity.ok(new LoginResponse(token, user.getUsername(), roleName));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body("Error generating JWT: " + e.getMessage());
        }
    }
}
