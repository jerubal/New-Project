package org.insa.pkiissuingca.config;

import org.insa.pkiissuingca.model.Role;
import org.insa.pkiissuingca.model.User;
import org.insa.pkiissuingca.repository.RoleRepository;
import org.insa.pkiissuingca.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import java.util.Collections;
import java.util.HashSet;

@Component
@Profile("!ocsp")
public class DataInitializer implements CommandLineRunner {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Value("${pki.security.admin-password}")
    private String adminPassword;

    @Value("${pki.security.operator-password}")
    private String operatorPassword;

    @Override
    public void run(String... args) throws Exception {
        // Create standard roles
        String[] roleNames = {"ROLE_CA_ADMIN", "ROLE_RA_OPERATOR", "ROLE_SECURITY_OFFICER", "ROLE_AUDITOR", "ROLE_END_ENTITY"};
        for (String roleName : roleNames) {
            if (roleRepository.findByName(roleName).isEmpty()) {
                Role role = new Role();
                role.setName(roleName);
                roleRepository.save(role);
            }
        }

        // Create default CA Admin user
        if (userRepository.findByUsername("admin").isEmpty()) {
            User admin = new User();
            admin.setUsername("admin");
            admin.setPassword(passwordEncoder.encode(adminPassword));
            admin.setEmail("admin@example.com");
            admin.setEnabled(true);
            admin.setRequiresPasswordChange(true);

            Role adminRole = roleRepository.findByName("ROLE_CA_ADMIN")
                    .orElseThrow(() -> new IllegalStateException("ROLE_CA_ADMIN role not found"));
            admin.setRoles(new HashSet<>(Collections.singletonList(adminRole)));
            userRepository.save(admin);
        }

        // Create default RA Operator user
        if (userRepository.findByUsername("operator").isEmpty()) {
            User operator = new User();
            operator.setUsername("operator");
            operator.setPassword(passwordEncoder.encode(operatorPassword));
            operator.setEmail("operator@example.com");
            operator.setEnabled(true);
            operator.setRequiresPasswordChange(true);

            Role operatorRole = roleRepository.findByName("ROLE_RA_OPERATOR")
                    .orElseThrow(() -> new IllegalStateException("ROLE_RA_OPERATOR role not found"));
            operator.setRoles(new HashSet<>(Collections.singletonList(operatorRole)));
            userRepository.save(operator);
        }
    }
}
