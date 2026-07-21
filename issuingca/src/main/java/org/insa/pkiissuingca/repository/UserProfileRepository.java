package org.insa.pkiissuingca.repository;

import org.insa.pkiissuingca.model.UserProfileEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.Optional;

@Repository
public interface UserProfileRepository extends JpaRepository<UserProfileEntity, Long> {
    Optional<UserProfileEntity> findByUsername(String username);
    Optional<UserProfileEntity> findByEmail(String email);
}
