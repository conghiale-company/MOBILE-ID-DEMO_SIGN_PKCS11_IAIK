package org.example;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;

import java.security.*;
import java.util.Base64;

/**
 * Hello world!
 *
 */
// Tham khảo: https://s.net.vn/223u &&& https://s.net.vn/24rk
public class App 
{
    private static String header = "{\"alg\":\"RS256\"}";
    private static String payload = "{\"sub\":\"1234567890\",\"name\":\"John Doe\",\"admin\":true}";

    private static String config = "--name = BeID\n"
        + "library = \"c:/Program Files (x86)/Belgium Identity Card/FireFox Plugin Manifests/beid_ff_pkcs11_64.dll\"\n"
        + "slot = 0\n";
    private static String alias = "nolabel";
    private static char[] pin = "12345678".toCharArray();

    public static void main( String[] args ) throws Exception {

        BouncyCastleProvider provider = new BouncyCastleProvider();
        Security.addProvider(provider);

        System.out.println("SIGNATURE_02: " + createSignature());
    }

    private static KeyPair generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", "BC");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

    private static String createSignature() throws Exception {
//        Hash the data using SHA-256
        String dataToHash = base64UrlEncode(header) + "." + base64UrlEncode(payload);
        byte[] hashedBytes = hashDataWithsha256(dataToHash.getBytes("UTF-8"));
        byte[] paddingHashBytes = padding(hashedBytes);

        Pkcs11WrapperSignature signature = new Pkcs11WrapperSignature("C:/Windows/System32/eps2003csp11.dll", 1)
                .select(alias,"" , pin).setDigestAlgorithmName("SHA256");
        return Base64.getUrlEncoder().encodeToString(signature.sign(paddingHashBytes));

//        String jwtToken = signature.signDataByJWSObject(payload);
//        System.out.println("LINE 49: - SIGNATURE USE JWT BY JWS: " + jwtToken.substring(jwtToken.lastIndexOf(".") + 1));
//        return "";
//        String jwtToken2 = signature.createJWTAndSign();
//        System.out.println("LINE 52: - SIGNATURE USE JWT BY Jwts: " + jwtToken.substring(jwtToken.lastIndexOf(".") + 1));

 //        Pkcs11WrapperKeyAndCertificate pkcs11WrapperKeyAndCertificate = new Pkcs11WrapperKeyAndCertificate(
//                "C:/Windows/System32/eps2003csp11.dll", 1).select(alias,"" , pin);
//
//        ContentSigner signer = pkcs11WrapperKeyAndCertificate.buildContentSigner("SHA256WITHRSA");
//        signer.getOutputStream().write(paddingHashBytes);
//        return Base64.getUrlEncoder().encodeToString(signer.getSignature());

////        the PKCS#11 provider
////        IAIKPkcs11 pkcs11Provider = new IAIKPkcs11();
//
////        Tìm kiếm token trong HSM
//        Slot[] slots = pkcs11Provider.getSlotList(true);
//        Token token = slots[0].getToken();
//
////        Open session với HSM
//        Session session = token.openSession(Token.SessionType.SERIAL_SESSION, Token.SessionReadWriteBehavior.RW_SESSION, null, null);
//
////        Tạo cặp khóa RSA
//        Mechanism mechanism = Mechanism.get(PKCS11Constants.CKM_RSA_PKCS_KEY_PAIR_GEN);
//        RSAPublicKey rsaPublicKeyTemplate = new RSAPublicKey();
//        RSAPrivateKey rsaPrivateKeyTemplate = new RSAPrivateKey();
//
////        set the general attributes for the public key
//        rsaPublicKeyTemplate.getModulusBits().setLongValue(new Long(2048));
//        byte[] publicExponentBytes = {0x01, 0x00, 0x01}; // 2^16 + 1
//        rsaPublicKeyTemplate.getPublicExponent().setByteArrayValue(publicExponentBytes);
//        rsaPublicKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
//        byte[] id = new byte[20];
//        new Random().nextBytes(id);
//        rsaPublicKeyTemplate.getId().setByteArrayValue(id);
//        //rsaPublicKeyTemplate.getLabel().setCharArrayValue(args[2].toCharArray());
//
//        rsaPrivateKeyTemplate.getSensitive().setBooleanValue(Boolean.TRUE);
//        rsaPrivateKeyTemplate.getToken().setBooleanValue(Boolean.TRUE);
//        rsaPrivateKeyTemplate.getPrivate().setBooleanValue(Boolean.TRUE);
//        rsaPrivateKeyTemplate.getId().setByteArrayValue(id);
//        //byte[] subject = args[1].getBytes();
//        //rsaPrivateKeyTemplate.getSubject().setByteArrayValue(subject);
//        //rsaPrivateKeyTemplate.getLabel().setCharArrayValue(args[2].toCharArray());
//
////        if we have no information we assume these attributes
//        rsaPrivateKeyTemplate.getSign().setBooleanValue(Boolean.TRUE);
//        rsaPrivateKeyTemplate.getDecrypt().setBooleanValue(Boolean.TRUE);
//
//        rsaPublicKeyTemplate.getVerify().setBooleanValue(Boolean.TRUE);
//        rsaPublicKeyTemplate.getEncrypt().setBooleanValue(Boolean.TRUE);
//
////        netscape does not set these attribute, so we do no either
//        rsaPublicKeyTemplate.getKeyType().setPresent(false);
//        rsaPublicKeyTemplate.getObjectClass().setPresent(false);
//
//        rsaPrivateKeyTemplate.getKeyType().setPresent(false);
//        rsaPrivateKeyTemplate.getObjectClass().setPresent(false);
//
//        iaik.pkcs.pkcs11.objects.KeyPair keyPair = session.generateKeyPair(mechanism, rsaPublicKeyTemplate, rsaPrivateKeyTemplate);
//
//        // Lấy khóa riêng tư từ cặp khóa
//        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivateKey();
//        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublicKey();
//
//        // Ký số dữ liệu bằng khóa riêng tư
//        session.signInit(Mechanism.get(PKCS11Constants.CKM_RSA_PKCS), privateKey);
//        byte[] signature = session.sign(paddingHashBytes);
//
//        // In ra chữ ký số
//        System.out.println("Signature: " + new String(signature));
//
//        // Đóng session
//        session.closeSession();

//        return Base64.getUrlEncoder().encodeToString(signature.sign(paddingHashBytes));
    }

//    Encode the signature as Base64 URL-safe string
    public static String base64UrlEncode(String input) {
        return Base64.getUrlEncoder().encodeToString(input.getBytes())
                .replaceAll("=", "");
    }

//    Method to compute SHA-256 hash
    public static byte[] hashDataWithsha256(byte[] data) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(data);
    }

//    PADDING
    public static byte[] padding(byte[] hashBytes) throws Exception {
        //PREPARE PADDING
        byte[] padding = null;
        padding = new byte[] { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20 };

        //ADD PADDING & HASH TO RESULTING ARRAY
        byte[] paddingHash = new byte[padding.length + hashBytes.length];
        System.arraycopy(padding, 0, paddingHash, 0, padding.length);
        System.arraycopy(hashBytes, 0, paddingHash, padding.length, hashBytes.length);

        //RETURN HASH
        return paddingHash;
    }
}
