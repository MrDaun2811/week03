/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package week03;
import java.security.*;
import java.security.spec.*;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.IESParameterSpec;
import java.security.spec.ECGenParameterSpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
/**
 *
 * @author levan
 */
public class ECCCipher {
            private static final String EC_ALGORITHM = "EC"; 
            private static final String ECC_CIPHER_ALGORITHM = "ECIES";
             static{
                     Security.addProvider(new BouncyCastleProvider());
                    }
             public KeyPair generateKeyPair () throws NoSuchAlgorithmException, 
                    InvalidAlgorithmParameterException, NoSuchProviderException { 
                    KeyPairGenerator keyPairGenerator =
                            KeyPairGenerator. getInstance(EC_ALGORITHM, "BC"); 
                    ECGenParameterSpec ecSpec = new ECGenParameterSpec ("secp256r1"); 
                    keyPairGenerator.initialize(ecSpec, new SecureRandom ());
                    return keyPairGenerator.generateKeyPair();

            }
             public byte[] encrypt (String plaintext, PublicKey publicKey) throws Exception 
             {
                    Cipher cipher = Cipher.getInstance(ECC_CIPHER_ALGORITHM, "BC");

                    byte[] nonce= new byte[16]; // Sử dụng nonce ngẫu nhiên

                    SecureRandom random =new SecureRandom();

                    random.nextBytes (nonce);

                    IESParameterSpec params = new IESParameterSpec (nonce,nonce, 128);

                    cipher.init(Cipher.ENCRYPT_MODE, publicKey, params);

                    return cipher.doFinal (plaintext.getBytes());

              }

                    public String decrypt (byte[] ciphertext, PrivateKey privateKey) throws Exception 
                    {

                    Cipher cipher = Cipher.getInstance(ECC_CIPHER_ALGORITHM, "BC");

                    byte[] nonce= new byte[16]; // sử dụng nonce ngẫu nhiên

                    SecureRandom random = new SecureRandom();

                    random.nextBytes(nonce);

                    IESParameterSpec params = new IESParameterSpec(nonce,nonce ,123);

                    cipher.init(Cipher.DECRYPT_MODE, privateKey, params);

                    byte[] decryptedBytes = cipher.doFinal (ciphertext);

                    return new String(decryptedBytes);
                    
                    }
                    
                   public static PublicKey loadPublicKey(byte[] keyBytes) throws Exception 
                   {

                        KeyFactory keyFactory = KeyFactory.getInstance(EC_ALGORITHM, "BC");
                        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec (keyBytes);

                        return keyFactory.generatePublic (publicKeySpec);

                     }

                        public static PrivateKey loadPrivateKey(byte[] keyBytes) throws Exception 
                     {

                        KeyFactory keyFactory = KeyFactory.getInstance(EC_ALGORITHM, "BC");

                        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);

                        return keyFactory.generatePrivate (privateKeySpec);
                        
                    }

}


    

