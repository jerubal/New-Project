package org.insa.pkiissuingca.controller;

import org.insa.pkiissuingca.dto.LoginRequest;
import org.insa.pkiissuingca.dto.LoginResponse;
import org.insa.pkiissuingca.model.Role;
import org.insa.pkiissuingca.model.User;
import org.insa.pkiissuingca.repository.UserRepository;
import org.insa.pkiissuingca.security.JwtUtil;
import org.insa.pkiissuingca.service.AuditService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.context.annotation.Profile;
import org.springframework.web.bind.annotation.*;

import jakarta.validation.Valid;

@RestController
@RequestMapping("/api/v1/auth")
@Profile("!ocsp")
public class AuthController {

    private static final Logger log = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private AuditService auditService;

    private static final String DUMMY_HASH = "$2a$10$x8R8/Roxp.Cq1L1QeF6rkuO1gW5XN1d8O1L5uL1oG1U1d1S1.1T1.";

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest) {
        User user = userRepository.findByUsername(loginRequest.getUsername()).orElse(null);

        boolean passwordMatches;
        if (user != null) {
            passwordMatches = passwordEncoder.matches(loginRequest.getPassword(), user.getPassword());
        } else {
            passwordEncoder.matches(loginRequest.getPassword(), DUMMY_HASH);
            passwordMatches = false;
        }

        if (user == null || !passwordMatches) {
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
            log.error("Failed to generate JWT for user {}: {}", user.getUsername(), e.getMessage(), e);
            return ResponseEntity.internalServerError().body("Authentication error. Please try again.");
        }
    }
}
