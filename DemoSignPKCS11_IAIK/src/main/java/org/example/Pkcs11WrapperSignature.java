package org.example;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.RSAKeyProvider;
import com.itextpdf.signatures.DigestAlgorithms;
import com.itextpdf.signatures.IExternalSignature;

import iaik.pkcs.pkcs11.Mechanism;
import iaik.pkcs.pkcs11.TokenException;
import iaik.pkcs.pkcs11.objects.Key;
import iaik.pkcs.pkcs11.wrapper.PKCS11Constants;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

//import com.itextpdf.signatures.ISignatureMechanismParams;

/**
 * This {@link IExternalSignature} implementation is based on the
 * <a href="https://jce.iaik.tugraz.at/products/core-crypto-toolkits/pkcs11-wrapper/">
 * IAIK PKCS#11 Wrapper</a>
 * 
 * @author mkl
 */
public class Pkcs11WrapperSignature extends Pkcs11WrapperKeyAndCertificate implements IExternalSignature {
    String signatureAlgorithmName;
    String digestAlgorithmName;

    // Sign Data
    String header = "{\"alg\":\"RS256\"}";
    String payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true}";

    public Pkcs11WrapperSignature(String libraryPath, long slotId) throws IOException, TokenException {
        super(libraryPath, slotId);
    }

    public Pkcs11WrapperSignature select(String alias, String certLabel, char[] pin) throws TokenException, CertificateException {
        super.select(alias, certLabel, pin);
        if (Key.KeyType.RSA == keyType) {
            signatureAlgorithmName = "RSA";
        } else if (Key.KeyType.DSA == keyType) {
            signatureAlgorithmName = "DSA";
        } else if (Key.KeyType.EC == keyType) {
            signatureAlgorithmName = "ECDSA";
        } else {
            signatureAlgorithmName = null;
        }

        return this;
    }

    public Pkcs11WrapperSignature setDigestAlgorithmName(String digestAlgorithmName) {
        this.digestAlgorithmName = DigestAlgorithms.getDigest(DigestAlgorithms.getAllowedDigest(digestAlgorithmName));
        return this;
    }

    @Override
    public String getHashAlgorithm() {
        return digestAlgorithmName;
    }

    @Override
    public String getEncryptionAlgorithm() {
        return signatureAlgorithmName;
    }

    @Override
    public byte[] sign(byte[] message) throws GeneralSecurityException {
        long mechanismId;
        switch(signatureAlgorithmName) {
        case "DSA":
            switch(digestAlgorithmName) {
            case "SHA1":
                mechanismId = PKCS11Constants.CKM_DSA_SHA1;
                break;
            case "SHA224":
                mechanismId = PKCS11Constants.CKM_DSA_SHA224;
                break;
            case "SHA256":
                mechanismId = PKCS11Constants.CKM_DSA_SHA256;
                break;
            case "SHA384":
                mechanismId = PKCS11Constants.CKM_DSA_SHA384;
                break;
            case "SHA512":
                mechanismId = PKCS11Constants.CKM_DSA_SHA512;
                break;
            default:
                throw new InvalidAlgorithmParameterException("Not supported: " + digestAlgorithmName + "with" + signatureAlgorithmName);
            }
        case "ECDSA":
            switch (digestAlgorithmName)
            {
            case "SHA1":
                mechanismId = PKCS11Constants.CKM_ECDSA_SHA1;
                break;
            case "SHA224":
                mechanismId = PKCS11Constants.CKM_ECDSA_SHA224;
                break;
            case "SHA256":
                mechanismId = PKCS11Constants.CKM_ECDSA_SHA256;
                break;
            case "SHA384":
                mechanismId = PKCS11Constants.CKM_ECDSA_SHA384;
                break;
            case "SHA512":
                mechanismId = PKCS11Constants.CKM_ECDSA_SHA512;
                break;
            default:
                throw new InvalidAlgorithmParameterException("Not supported: " + digestAlgorithmName + "with" + signatureAlgorithmName);
            }
            break;
        case "RSA":
            switch (digestAlgorithmName)
            {
            case "SHA1":
                mechanismId = PKCS11Constants.CKM_SHA1_RSA_PKCS;
                break;
            case "SHA224":
                mechanismId = PKCS11Constants.CKM_SHA224_RSA_PKCS;
                break;
            case "SHA256":
                mechanismId = PKCS11Constants.CKM_SHA256_RSA_PKCS;
                break;
            case "SHA384":
                mechanismId = PKCS11Constants.CKM_SHA384_RSA_PKCS;
                break;
            case "SHA512":
                mechanismId = PKCS11Constants.CKM_SHA512_RSA_PKCS;
                break;
            default:
                throw new InvalidAlgorithmParameterException("Not supported: " + digestAlgorithmName + "with" + signatureAlgorithmName);
            }
            break;
        default:
            throw new InvalidAlgorithmParameterException("Not supported: " + digestAlgorithmName + "with" + signatureAlgorithmName);
        }

        Mechanism signatureMechanism = Mechanism.get(mechanismId);
        try {
            session.signInit(signatureMechanism, rsaPrivateKey);
            return session.sign(message);
        } catch (TokenException e) {
            throw new GeneralSecurityException(e);
        } 
    }

//    Create JWT by JWSObject
    public String signDataByJWSObject(String dataPayload) throws Exception {
        // Extract key parameters
        byte[] modulusBytesPrimaryKey = rsaPrivateKey.getModulus().getByteArrayValue();
        byte[] modulusBytesPublicKey = rsaPublicKey.getModulus().getByteArrayValue();

        // Convert byte array to BigInteger for modulus
        BigInteger modulusPrimaryKey = new BigInteger(1, modulusBytesPrimaryKey);
        BigInteger modulusPublicKey = new BigInteger(1, modulusBytesPublicKey);

        RSAKeyProvider provider = new RSAKeyProvider() {
            @Override
            public RSAPublicKey getPublicKeyById(String s) {
                return new RSAPublicKey() {
                    @Override
                    public BigInteger getPublicExponent() {
                        return null;
                    }

                    @Override
                    public String getAlgorithm() {
                        return "RSA";
                    }

                    @Override
                    public String getFormat() {
                        return "PKCS#11";
                    }

                    @Override
                    public byte[] getEncoded() {
                        return null;
                    }

                    @Override
                    public BigInteger getModulus() {
                        return modulusPublicKey;
                    }
                };
            }

            @Override
            public RSAPrivateKey getPrivateKey() {
                return new RSAPrivateKey() {
                    @Override
                    public BigInteger getPrivateExponent() {
                        return null;
                    }

                    @Override
                    public String getAlgorithm() {
                        return "RSA";
                    }

                    @Override
                    public String getFormat() {
                        return "PKCS#11";
                    }

                    @Override
                    public byte[] getEncoded() {
                        return null;
                    }

                    @Override
                    public BigInteger getModulus() {
                        return modulusPrimaryKey;
                    }
                };
            }

            @Override
            public String getPrivateKeyId() {
                return "MID_28102002";
            }
        };

        Algorithm algorithm = Algorithm.RSA256(provider);

        return createSignature(convertToJavaRSAPrivateKey(rsaPrivateKey));

//        Map<String, Object> claims = new HashMap<>();
//        claims.put("sub", "1234567890");
//        claims.put("name", "John Doe");
//        claims.put("admin", true);

//        return Jwts.builder()
//                .setClaims(claims)
//                .signWith(SignatureAlgorithm.RS256, provider.getPrivateKey())
////                .signWith(SignatureAlgorithm.RS256, new PrivateKey() {
////                    @Override
////                    public String getAlgorithm() {
////                        return "RSA";
////                    }
////
////                    @Override
////                    public String getFormat() {
////                        return "PKCS#11";
////                    }
////
////                    @Override
////                    public byte[] getEncoded() {
////                        return new byte[0];
////                    }
////                })
//                .compact();

//        return JWT.create()
//                .withPayload(claims)
////                .withIssuer("auth0")
////                .withSubject("UID=CMND:12345678, CN=Lê Công Nghĩa, ST=Bình Thuận, C=VN")
////                .withClaim("name", "Bob")
//                .sign(algorithm);
    }

//    Tạo chữ ký số (signature) từ dữ liệu (payload) (Hash and Sign trong 1 bước)
    private String createSignature(PrivateKey privateKey) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        String dataToSign = base64UrlEncode(header) + "." + base64UrlEncode(payload);
        Signature signature = Signature.getInstance("SHA256withRSA", "BC");
        signature.initSign(privateKey);
        signature.update(dataToSign.getBytes("UTF-8"));
        byte[] signatureBytes = signature.sign();
        return Base64.getUrlEncoder().encodeToString(signatureBytes);
    }

    public static RSAPrivateKey convertToJavaRSAPrivateKey(iaik.pkcs.pkcs11.objects.RSAPrivateKey iaikPrivateKey) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Lấy các thành phần của khóa RSA từ RSAPrivateKey của IAIK
        BigInteger modulus = new BigInteger(1, iaikPrivateKey.getModulus().getByteArrayValue());
        byte[] privateExponentBytes = iaikPrivateKey.getPrivateExponent().getByteArrayValue();

        // Kiểm tra xem privateExponentBytes có giá trị null hay không
        BigInteger privateExponent;
        if (privateExponentBytes == null) {
            // Nếu privateExponentBytes là null, sử dụng một giá trị mặc định
            privateExponent = BigInteger.valueOf(65537); // Ví dụ: sử dụng Exponent là 65537
        } else {
            privateExponent = new BigInteger(1, privateExponentBytes);
        }

        // Tạo một đối tượng RSAPrivateKeySpec
        RSAPrivateKeySpec privateKeySpec = new RSAPrivateKeySpec(modulus, privateExponent);

        // Sử dụng KeyFactory để chuyển đổi RSAPrivateKeySpec thành đối tượng java.security.interfaces.RSAPrivateKey
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return (java.security.interfaces.RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);
    }

    public String base64UrlEncode(String input) {
        return Base64.getUrlEncoder().encodeToString(input.getBytes())
                .replaceAll("=", "");
    }
}
