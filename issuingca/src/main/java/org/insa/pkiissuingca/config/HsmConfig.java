package org.insa.pkiissuingca.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

import jakarta.annotation.PostConstruct;
import java.security.Provider;
import java.security.Security;

@Configuration
public class HsmConfig {

    private static final Logger logger = LoggerFactory.getLogger(HsmConfig.class);

    @Value("${pki.hsm.enabled:false}")
    private boolean hsmEnabled;

    @Value("${pki.hsm.library:/usr/lib/softhsm/libsofthsm2.so}")
    private String hsmLibrary;

    @Value("${pki.hsm.slot:0}")
    private String hsmSlot;

    @PostConstruct
    public void initHsmProvider() {
        if (!hsmEnabled) {
            logger.info("HSM Integration is disabled.");
            return;
        }

        try {
            logger.info("Initializing SunPKCS11 Provider with library: {}", hsmLibrary);
            String pkcs11Config = "name = SoftHSM\n" +
                                  "library = " + hsmLibrary + "\n" +
                                  "slot = " + hsmSlot + "\n" +
                                  "attributes = generate,CKO_PRIVATE_KEY,* {\n" +
                                  "  CKA_SENSITIVE = true\n" +
                                  "  CKA_EXTRACTABLE = false\n" +
                                  "}\n";

            Provider pkcs11Provider = Security.getProvider("SunPKCS11");
            if (pkcs11Provider != null) {
                pkcs11Provider = pkcs11Provider.configure(pkcs11Config);
                Security.addProvider(pkcs11Provider);
                logger.info("SunPKCS11 Provider (SoftHSM) successfully added.");
            } else {
                logger.warn("SunPKCS11 provider not found in this JVM! HSM Integration will fail.");
            }
        } catch (Exception e) {
            logger.error("Failed to initialize SunPKCS11 Provider: {}", e.getMessage(), e);
        }
    }
}
