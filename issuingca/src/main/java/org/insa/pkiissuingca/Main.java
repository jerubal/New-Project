package org.insa.pkiissuingca;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.insa.pkiissuingca.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.security.Security;

@SpringBootApplication
public class Main {
    public static void main(String[] args) {
        SpringApplication.run(Main.class, args);
    }
    @Bean
    public CommandLineRunner initData(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            // Update pki_user
            userRepository.findByUsername("pki_user").ifPresent(user -> {
                user.setPassword(passwordEncoder.encode("pki_pass"));
                user.setEnabled(true);
                userRepository.save(user);
            });

            // Update pki_admin
            userRepository.findByUsername("pki_admin").ifPresent(user -> {
                user.setPassword(passwordEncoder.encode("pki_pass"));
                user.setEnabled(true); // Ensure account is enabled
                userRepository.save(user);
                System.out.println("Credentials/Status updated for pki_admin!");
            });
        };
    }
    static {
        Security.addProvider(new BouncyCastleProvider());
    }
}