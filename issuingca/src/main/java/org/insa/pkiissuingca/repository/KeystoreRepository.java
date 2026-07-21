package org.insa.pkiissuingca.repository;

import org.insa.pkiissuingca.model.KeystoreEntity;
import org.insa.pkiissuingca.model.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface KeystoreRepository extends JpaRepository<KeystoreEntity, Long> {
    List<KeystoreEntity> findByUser(User user);
}
