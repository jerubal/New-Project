package org.insa.pkiissuingca.service;

import org.insa.pkiissuingca.model.CertificateEntity;
import org.insa.pkiissuingca.model.CrlEntity;

public interface LdapPublisherService {

    /**
     * Publishes an issued certificate to the directory.
     */
    void publishCertificate(CertificateEntity cert);

    /**
     * Publishes a newly generated CRL to the directory.
     */
    void publishCrl(CrlEntity crl);
}
