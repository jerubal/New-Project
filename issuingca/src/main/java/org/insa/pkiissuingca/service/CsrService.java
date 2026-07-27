package org.insa.pkiissuingca.service;

import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.security.auth.x500.X500Principal;
import java.io.StringReader;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.List;

@Service
public class CsrService {

    @Autowired
    private SerializationService serializationService;

    @Autowired
    private CryptoService cryptoService;

    /**
     * Programmatically builds a standardized PKCS#10 CSR.
     */
    public String generateCsr(KeyPair keyPair, String subjectDN, List<String> sans, String sigAlg) throws Exception {
        X500Principal principal = new X500Principal(subjectDN);
        JcaPKCS10CertificationRequestBuilder builder = new JcaPKCS10CertificationRequestBuilder(principal, keyPair.getPublic());

        if (sans != null && !sans.isEmpty()) {
            List<GeneralName> generalNamesList = new ArrayList<>();
            for (String san : sans) {
                if (san.startsWith("DNS:")) {
                    generalNamesList.add(new GeneralName(GeneralName.dNSName, san.substring(4).trim()));
                } else if (san.startsWith("IP:")) {
                    generalNamesList.add(new GeneralName(GeneralName.iPAddress, san.substring(3).trim()));
                } else if (san.startsWith("URI:")) {
                    generalNamesList.add(new GeneralName(GeneralName.uniformResourceIdentifier, san.substring(4).trim()));
                } else if (san.startsWith("email:")) {
                    generalNamesList.add(new GeneralName(GeneralName.rfc822Name, san.substring(6).trim()));
                } else {
                    generalNamesList.add(new GeneralName(GeneralName.dNSName, san.trim()));
                }
            }
            GeneralNames generalNames = new GeneralNames(generalNamesList.toArray(new GeneralName[0]));
            ExtensionsGenerator extGen = new ExtensionsGenerator();
            extGen.addExtension(Extension.subjectAlternativeName, false, generalNames);
            builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        }

        ContentSigner signer = cryptoService.getContentSigner(keyPair.getPrivate(), sigAlg);
        PKCS10CertificationRequest csr = builder.build(signer);

        return serializationService.convertToPem(csr);
    }

    /**
     * Programmatically verifies the internal digital signature of a CSR (Proof-of-Possession).
     */
    public boolean verifyCsrSignature(PKCS10CertificationRequest csr) throws Exception {
        ContentVerifierProvider verifierProvider = new JcaContentVerifierProviderBuilder()
                .setProvider("BC")
                .build(csr.getSubjectPublicKeyInfo());
        return csr.isSignatureValid(verifierProvider);
    }

    /**
     * Enforces pre-signing cryptographic policy validations on an incoming CSR.
     */
    public void validateCsrPolicy(CsrDetails details, PKCS10CertificationRequest csr) throws Exception {
        // 1. Proof-of-Possession Signature Check
        if (!verifyCsrSignature(csr)) {
            throw new IllegalArgumentException("CSR cryptographic signature verification failed: Requester does not possess the corresponding private key.");
        }

        // 2. Cryptographic Algorithm Allow-list Check (Reject weak algorithms)
        String sigAlgOid = csr.getSignatureAlgorithm().getAlgorithm().getId();
        if ("1.2.840.113549.1.1.5".equals(sigAlgOid) || // sha1WithRSAEncryption
            "1.2.840.113549.1.1.4".equals(sigAlgOid) || // md5WithRSAEncryption
            "1.2.840.10045.4.1".equals(sigAlgOid)    || // ecdsa-with-SHA1
            "1.2.840.113549.1.1.2".equals(sigAlgOid) || // md2WithRSAEncryption
            "1.2.840.113549.1.1.3".equals(sigAlgOid)) { // md4WithRSAEncryption
            throw new IllegalArgumentException("Disallowed CSR signature algorithm (OID: " + sigAlgOid + "). Weak algorithms such as SHA-1 and MD5 are prohibited.");
        }

        // 3. Minimum Key Size Limits Check
        PublicKey publicKey = details.getPublicKey();
        if (publicKey instanceof RSAPublicKey rsaKey) {
            int bitLength = rsaKey.getModulus().bitLength();
            if (bitLength < 2048) {
                throw new IllegalArgumentException("RSA key size too small (" + bitLength + " bits). Minimum required key size is 2048 bits.");
            }
        } else if (publicKey instanceof ECPublicKey ecKey) {
            int bitLength = ecKey.getParams().getCurve().getField().getFieldSize();
            if (bitLength < 256) {
                throw new IllegalArgumentException("ECDSA key size too small (" + bitLength + " bits). Minimum required key size is 256 bits.");
            }
        }
    }

    /**
     * Parses a raw PKCS#10 PEM string, validating signature & policy before returning metadata.
     */
    public CsrDetails parseCsr(String csrPem) throws Exception {
        PKCS10CertificationRequest csr;
        try (PEMParser pemParser = new PEMParser(new StringReader(csrPem))) {
            Object parsedObj = pemParser.readObject();
            if (parsedObj instanceof PKCS10CertificationRequest) {
                csr = (PKCS10CertificationRequest) parsedObj;
            } else {
                throw new IllegalArgumentException("Provided PEM content is not a valid PKCS#10 CSR.");
            }
        }

        JcaPKCS10CertificationRequest jcaCsr = new JcaPKCS10CertificationRequest(csr).setProvider("BC");
        String subjectDN = jcaCsr.getSubject().toString();
        PublicKey publicKey = jcaCsr.getPublicKey();
        String sigAlgName = jcaCsr.getSignatureAlgorithm().getAlgorithm().getId();

        List<String> sans = new ArrayList<>();
        Attribute[] attributes = jcaCsr.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);
        if (attributes != null && attributes.length > 0) {
            for (Attribute attr : attributes) {
                Extensions extensions = Extensions.getInstance(attr.getAttrValues().getObjectAt(0));
                Extension sanExt = extensions.getExtension(Extension.subjectAlternativeName);
                if (sanExt != null) {
                    GeneralNames gns = GeneralNames.getInstance(sanExt.getParsedValue());
                    for (GeneralName gn : gns.getNames()) {
                        sans.add(gn.toString());
                    }
                }
            }
        }

        CsrDetails details = new CsrDetails(subjectDN, publicKey, sans, sigAlgName);
        validateCsrPolicy(details, csr);
        return details;
    }


    public static class CsrDetails {
        private final String subjectDN;
        private final PublicKey publicKey;
        private final List<String> sans;
        private final String signatureAlgorithm;

        public CsrDetails(String subjectDN, PublicKey publicKey, List<String> sans, String signatureAlgorithm) {
            this.subjectDN = subjectDN;
            this.publicKey = publicKey;
            this.sans = sans;
            this.signatureAlgorithm = signatureAlgorithm;
        }

        public String getSubjectDN() { return subjectDN; }
        public PublicKey getPublicKey() { return publicKey; }
        public List<String> getSans() { return sans; }
        public String getSignatureAlgorithm() { return signatureAlgorithm; }
    }
}
