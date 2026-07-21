package org.insa.pkiissuingca.repository;

import org.insa.pkiissuingca.model.KeyPairEntity;
import org.insa.pkiissuingca.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface KeyPairRepository extends JpaRepository<KeyPairEntity, Long> {
    List<KeyPairEntity> findByUser(User user);
}
