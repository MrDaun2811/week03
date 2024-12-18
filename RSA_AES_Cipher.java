/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package week03;
import java.nio.charset.StandardCharsets;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
/**
 *
 * @author levan
 */
public class RSA_AES_Cipher {
    private PublicKey publickey;
    private PrivateKey privatekey;
       public RSA_AES_Cipher() throws Exception 
       {
// Generate RSA key pair
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize (2048); // Key size 2048 bits
            KeyPair keyPair = keyGen.generateKeyPair();
            this.publickey =keyPair.getPublic();
            this.privatekey = keyPair.getPrivate();
       }
             public byte[] encrypt (String plainText) throws Exception 
           {
            SecretKey secretKey = generateAESKey ();
            byte[] encryptedSymmetrickey = rsaEncrypt (secretKey.getEncoded());
            Cipher aesCipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedData = aesCipher
            .doFinal (plainText.getBytes (StandardCharsets.UTF_8));
            byte[] combined = new byte [encryptedSymmetrickey.length + encryptedData.length];
            System.arraycopy ( encryptedSymmetrickey , 0,
            combined, 0, encryptedSymmetrickey.length);
            System.arraycopy (encryptedData, 0,
            combined, encryptedSymmetrickey.length, encryptedData.length);
            return combined;
            
           }
             public String decrypt (byte[] combined) throws Exception {
                int symmetricKeyLength = 256;
                byte[] encryptedSymmetricKey = new byte [symmetricKeyLength]; 
                byte[] encryptedData = new byte [combined.length-symmetricKeyLength];
                System.arraycopy(combined, 0, encryptedSymmetricKey, 0, symmetricKeyLength);
                System.arraycopy(combined, symmetricKeyLength, encryptedData, 0, encryptedData.length);
                byte[] decryptedSymmetrickey = rsaDecrypt (encryptedSymmetricKey);
                SecretKey secretKey= new SecretKeySpec (decryptedSymmetrickey, "AES");
                Cipher aesCipher= Cipher.getInstance("AES/ECB/PKCS5Padding");
                aesCipher.init(Cipher.DECRYPT_MODE, secretKey );
                byte[] decryptedData = aesCipher.doFinal (encryptedData);
                return new String (decryptedData, StandardCharsets.UTF_8);
}
             
             
   private SecretKey generateAESKey() throws NoSuchAlgorithmException {
   KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init (128); // Using AES 128
    return keyGen.generateKey();
}


    private byte[] rsaEncrypt (byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publickey);
        return cipher.doFinal(data);
        }
    private byte[] rsaDecrypt (byte[] encryptedData) throws Exception {
        Cipher cipher=  Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privatekey);
        return cipher.doFinal (encryptedData);
        }
     public PublicKey getPublicKey() {
        return publickey;
        }
     public PrivateKey getPrivateKey() {
        return privatekey;
        }
    
}