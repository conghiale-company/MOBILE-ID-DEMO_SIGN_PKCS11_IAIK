package org.example;

import static iaik.pkcs.pkcs11.Module.SlotRequirement.ALL_SLOTS;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import iaik.pkcs.pkcs11.objects.*;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.RuntimeOperatorException;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.Session;
import iaik.pkcs.pkcs11.Slot;
import iaik.pkcs.pkcs11.Token;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;

/**
 * @author mkl
 */
public class Pkcs11WrapperKeyAndCertificate implements AutoCloseable {
    protected iaik.pkcs.pkcs11.Module pkcs11Module = null;
    protected Slot slot = null;
    protected Session session = null;

    protected RSAPrivateKey rsaPrivateKey = null;
    protected RSAPublicKey rsaPublicKey = null;
    protected Long keyType = null;
    protected String alias = null;
    protected X509Certificate[] chain = null;

    public Pkcs11WrapperKeyAndCertificate(String libraryPath, long slotId) throws IOException, TokenException {
//        Khỏi tạo provider
        pkcs11Module = iaik.pkcs.pkcs11.Module.getInstance(libraryPath);

        try {
            pkcs11Module.initialize(null);

            Slot[] slots = pkcs11Module.getSlotList(ALL_SLOTS);

//            Lấy slot
            for (Slot oneSlot : slots) {
                if (oneSlot.getSlotID() == slotId) {
                    slot = oneSlot;
                }
            }
        } catch (TokenException e) {
            try {
                close();
            } catch (Exception e2) {
                e.addSuppressed(e2);
            }
            throw e;
        } 
    }

//    public Pkcs11WrapperKeyAndCertificate select(String alias, String certLabel, char[] pin) throws TokenException, CertificateException {
//        closeSession();
//
////        Tìm kiếm token - mở session và đăng nhập bằng mã Pin
//        Token token = slot.getToken();
//        session = token.openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RO_SESSION, null, null);
//        session.login(Session.UserType.USER, pin);
//
//        boolean found = false;
//
//
////        Tìm kiếm primary Key
////        Một đối tượng PrivateKey được tạo ra làm mẫu cho việc tìm kiếm.
////        Trong trường hợp này, đang tạo một khóa dùng để ký (Sign).
//        PrivateKey searchTemplate = new PrivateKey();
//        searchTemplate.getSign().setBooleanValue(Boolean.TRUE);
////
////        Sử dụng session để khởi tạo quá trình tìm kiếm bằng cách chuyển mẫu tìm kiếm vào phương thức findObjectsInit()
//        session.findObjectsInit(searchTemplate);
//        List<PrivateKey> privateKeys = new ArrayList<>();
//        try {
//            Object[] matchingKeys;
//            while ((matchingKeys = session.findObjects(1)).length > 0) {
//                PrivateKey privateKey = (PrivateKey) matchingKeys[0];
//                if (alias != null && !alias.isEmpty()) {
//                    if (privateKey.getLabel().isPresent()) { // Nếu nhãn tồn tại (isPresent() trả về true)
//                        if (!Arrays.equals(privateKey.getLabel().getCharArrayValue(), alias.toCharArray()))
//                            continue;
//                    } else if(privateKey.getId().isPresent()) { // Nếu ID của khóa tồn tại (isPresent() trả về true)
//                        if (!new BigInteger(privateKey.getId().getByteArrayValue()).toString().equals(alias))
//                            continue;
//                    } else {
//                        // nothing to compare the alias to; assuming it matches
//                    }
//                }
//                privateKeys.add(privateKey);
//            }
//        } finally {
//            session.findObjectsFinal();
//        }
//
//        for (PrivateKey privateKey : privateKeys) {
//            Long type = privateKey.getKeyType().getLongValue();
//            if (!isValidPrivateKeyType(type))
//                continue;
//
//            String thisAlias;
//            if (privateKey.getLabel().isPresent())
//                thisAlias = new String(privateKey.getLabel().getCharArrayValue());
//            else if (privateKey.getId().isPresent())
//                thisAlias = new BigInteger(privateKey.getId().getByteArrayValue()).toString();
//            else
//                thisAlias = null;
//            if (alias != null && !alias.equals(thisAlias))
//                continue;
//
//            System.out.println("LINE 128: " + thisAlias);
//
//            X509PublicKeyCertificate signatureCertificate;
//            X509PublicKeyCertificate certificateTemplate = new X509PublicKeyCertificate();
//            if (certLabel == null && thisAlias != null && !thisAlias.isEmpty())
//                certLabel = thisAlias;
//            if (certLabel != null)
//                certificateTemplate.getLabel().setCharArrayValue(certLabel.toCharArray());
//
//            System.out.println("LINE 256: " + certificateTemplate.getLabel().getCharArrayValue());
//
//            session.findObjectsInit(certificateTemplate);
//            try {
//                Object[] correspondingCertificates = session.findObjects(2);
//                System.out.println("LINE 142: " + correspondingCertificates.length);
//                if (correspondingCertificates.length != 1)
//                    continue;
//                signatureCertificate = (X509PublicKeyCertificate) correspondingCertificates[0];
//            } finally {
//                session.findObjectsFinal();
//            }
//
//            System.out.println("LINE 151: " + signatureCertificate.getId());
//            List<X509Certificate> certificates = new ArrayList<>();
//            certificates.add(new iaik.x509.X509Certificate(signatureCertificate.getValue().getByteArrayValue()));
//
//            certificateTemplate = new X509PublicKeyCertificate();
//            session.findObjectsInit(certificateTemplate);
//            try {
//                Object[] correspondingCertificates;
//                while ((correspondingCertificates = session.findObjects(1)).length > 0) {
//                    X509PublicKeyCertificate certObject = (X509PublicKeyCertificate) correspondingCertificates[0];
//                    if (certObject.getObjectHandle() != signatureCertificate.getObjectHandle()) {
//                        certificates.add(new iaik.x509.X509Certificate(certObject.getValue().getByteArrayValue()));
//                    }
//                }
//            } finally {
//                session.findObjectsFinal();
//            }
//
//            found = true;
//            this.alias = thisAlias;
//            this.keyType = type;
//            this.privateKey = privateKey;
//            this.chain = certificates.toArray(new X509Certificate[certificates.size()]);
//            break;
//        }
//
//        if (!found) {
//            this.alias = null;
//            this.keyType = null;
//            this.privateKey = null;
//            this.chain = null;
//        }
//
//        return this;
//    }


    public Pkcs11WrapperKeyAndCertificate select(String alias, String certLabel, char[] pin) throws TokenException, CertificateException {
        closeSession();

//        Tìm kiếm token - mở session và đăng nhập bằng mã Pin
        Token token = slot.getToken();
        session = token.openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RO_SESSION, null, null);
        session.login(Session.UserType.USER, pin);

        // Search for the primary key
        RSAPrivateKey  privateKeyTemplate = new RSAPrivateKey ();
        privateKeyTemplate.getToken().setBooleanValue(true);
        privateKeyTemplate.getPrivate().setBooleanValue(true);
        privateKeyTemplate.getSign().setBooleanValue(true);
        session.findObjectsInit(privateKeyTemplate);
        Object[] privateKeys = session.findObjects(1);
        session.findObjectsFinal();
//        PrivateKey privateKey = (PrivateKey) privateKeys[0];
        RSAPrivateKey privateKey = (RSAPrivateKey) privateKeys[0];
        Long type = privateKey.getKeyType().getLongValue();

        // Search for the public key
        PublicKey publicKeyTemplate = new PublicKey();
        publicKeyTemplate.getToken().setBooleanValue(true);
        publicKeyTemplate.getPrivate().setBooleanValue(false);
        publicKeyTemplate.getVerify().setBooleanValue(true);
        session.findObjectsInit(publicKeyTemplate);
        Object[] publicKeys = session.findObjects(1);
        session.findObjectsFinal();
        RSAPublicKey publicKey = (RSAPublicKey) publicKeys[0];

        // Search for the certificate
        X509PublicKeyCertificate certificateTemplate = new X509PublicKeyCertificate();
        certificateTemplate.getToken().setBooleanValue(true);
        session.findObjectsInit(certificateTemplate);
        Object[] certificates = session.findObjects(1);
        session.findObjectsFinal();
        X509PublicKeyCertificate certificate = (X509PublicKeyCertificate) certificates[0];
//        session.logout();

        List<X509Certificate> certificatesList = new ArrayList<>();
        certificatesList.add(new iaik.x509.X509Certificate(certificate.getValue().getByteArrayValue()));

        // Use the retrieved objects as needed
//        System.out.println("Private Key: " + privateKey);
//        System.out.println("Public Key: " + publicKey);
//        System.out.println("Certificate: " + certificate);

        if (privateKey != null && publicKey != null && certificate != null) {
            this.alias = "thisAlias";
            this.keyType =  type;
            this.rsaPrivateKey = privateKey;
            this.rsaPublicKey = publicKey;
            this.chain = certificatesList.toArray(new X509Certificate[certificatesList.size()]);
        } else {
            this.alias = null;
            this.keyType = null;
            this.rsaPrivateKey = null;
            this.rsaPublicKey = null;
            this.chain = null;
        }

        return this;
    }

    public X509Certificate[] getChain() {
        return chain;
    }

    static Collection<Long> SIGNATURE_KEY_TYPES = Arrays.asList(Key.KeyType.DSA, Key.KeyType.EC, Key.KeyType.RSA);
    protected boolean isValidPrivateKeyType(Long type) {
        return SIGNATURE_KEY_TYPES.contains(type);
    }

    @Override
    public void close() throws TokenException {
        closeSession();
        slot = null;
        pkcs11Module.finalize(null);
    }

    protected void closeSession() throws TokenException {
        if (session != null) {
            try {
                session.closeSession();
            } finally {
                session = null;
            }
        }
    }

    public ContentSigner buildContentSigner(String signatureAlgorithm) throws TokenException {
        AlgorithmIdentifier signAlgorithmIdentifier = new DefaultSignatureAlgorithmIdentifierFinder().find(signatureAlgorithm);
        Long mechanism = MECHANISM_BY_ALGORITHM_LOWER.get(signatureAlgorithm.toLowerCase());
        if (mechanism == null)
            throw new IllegalArgumentException(String.format("No applicable mechanism for '%s'", signatureAlgorithm));
        session.signInit(Mechanism.get(mechanism), rsaPrivateKey);

        return new ContentSigner() {
            ByteArrayOutputStream baos = new ByteArrayOutputStream();

            @Override
            public byte[] getSignature() {
                try {
                    byte[] signature = session.sign(baos.toByteArray());
                    // TODO: In case of ECDSA check the format of the returned bytes and transform if necessary
                    return signature;
                } catch (TokenException e) {
                    throw new RuntimeOperatorException(e.getMessage(), e);
                }
            }
            
            @Override
            public OutputStream getOutputStream() {
                return baos;
            }
            
            @Override
            public AlgorithmIdentifier getAlgorithmIdentifier() {
                return signAlgorithmIdentifier;
            }
        };
    }

    static Map<String, Long> MECHANISM_BY_ALGORITHM_LOWER = new HashMap<>();

    static {
        MECHANISM_BY_ALGORITHM_LOWER.put("sha1withdsa", PKCS11Constants.CKM_DSA_SHA1);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha224withdsa", PKCS11Constants.CKM_DSA_SHA224);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha256withdsa", PKCS11Constants.CKM_DSA_SHA256);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha384withdsa", PKCS11Constants.CKM_DSA_SHA384);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha512withdsa", PKCS11Constants.CKM_DSA_SHA512);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha1withecdsa", PKCS11Constants.CKM_ECDSA_SHA1);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha224withecdsa", PKCS11Constants.CKM_ECDSA_SHA224);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha256withecdsa", PKCS11Constants.CKM_ECDSA_SHA256);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha384withecdsa", PKCS11Constants.CKM_ECDSA_SHA384);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha512withecdsa", PKCS11Constants.CKM_ECDSA_SHA512);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha1withplain-ecdsa", PKCS11Constants.CKM_ECDSA_SHA1);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha224withplain-ecdsa", PKCS11Constants.CKM_ECDSA_SHA224);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha256withplain-ecdsa", PKCS11Constants.CKM_ECDSA_SHA256);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha384withplain-ecdsa", PKCS11Constants.CKM_ECDSA_SHA384);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha512withplain-ecdsa", PKCS11Constants.CKM_ECDSA_SHA512);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha1withrsa", PKCS11Constants.CKM_SHA1_RSA_PKCS);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha224withrsa", PKCS11Constants.CKM_SHA224_RSA_PKCS);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha256withrsa", PKCS11Constants.CKM_SHA256_RSA_PKCS);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha384withrsa", PKCS11Constants.CKM_SHA384_RSA_PKCS);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha512withrsa", PKCS11Constants.CKM_SHA512_RSA_PKCS);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha1withrsaandmgf1", PKCS11Constants.CKM_SHA1_RSA_PKCS_PSS);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha224withrsaandmgf1", PKCS11Constants.CKM_SHA224_RSA_PKCS_PSS);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha256withrsaandmgf1", PKCS11Constants.CKM_SHA256_RSA_PKCS_PSS);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha384withrsaandmgf1", PKCS11Constants.CKM_SHA384_RSA_PKCS_PSS);
        MECHANISM_BY_ALGORITHM_LOWER.put("sha512withrsaandmgf1", PKCS11Constants.CKM_SHA512_RSA_PKCS_PSS);
    }
}
