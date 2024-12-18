/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/GUIForms/JFrame.java to edit this template
 */
package week03;

import java.io.File;

import java.io.FileWriter;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;

import javax.swing.*;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import java.security. PrivateKey;

import java.security. PublicKey;

import java.util.Base64;

import java.util.logging.Level;

import java.util.logging.Logger;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
/**
 *
 * @author levan
 */
public class frm_ECC2 extends javax.swing.JFrame {
        
    private ECCCipher ecc;

    private PublicKey publicKey;

    private PrivateKey privateKey;
    /**
     * Creates new form frm_ECC2
     */
    public frm_ECC2() {
        initComponents();
        initComponents();
        ecc = new ECCCipher();
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * This method is called from within the constructor to initialize the form.
     * WARNING: Do NOT modify this code. The content of this method is always
     * regenerated by the Form Editor.
     */
    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();
        jLabel3 = new javax.swing.JLabel();
        jLabel4 = new javax.swing.JLabel();
        jLabel5 = new javax.swing.JLabel();
        generate = new javax.swing.JButton();
        load = new javax.swing.JButton();
        encrypt = new javax.swing.JButton();
        decrypt = new javax.swing.JButton();
        jScrollPane1 = new javax.swing.JScrollPane();
        txt_plaintext = new javax.swing.JTextArea();
        jScrollPane2 = new javax.swing.JScrollPane();
        txt_publickey = new javax.swing.JTextArea();
        jScrollPane3 = new javax.swing.JScrollPane();
        txt_privatekey = new javax.swing.JTextArea();
        jScrollPane4 = new javax.swing.JScrollPane();
        txt_ciphertext = new javax.swing.JTextArea();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);

        jLabel1.setText("ECC demo");

        jLabel2.setText("Pliantext");

        jLabel3.setText("Publickey");

        jLabel4.setText("Privatekey");

        jLabel5.setText("Ciphertext");

        generate.setText("gener");
        generate.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                generateActionPerformed(evt);
            }
        });

        load.setText("loadK");
        load.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                loadActionPerformed(evt);
            }
        });

        encrypt.setText("encrypt");
        encrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                encryptActionPerformed(evt);
            }
        });

        decrypt.setText("decrypt");
        decrypt.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                decryptActionPerformed(evt);
            }
        });

        txt_plaintext.setColumns(20);
        txt_plaintext.setRows(5);
        jScrollPane1.setViewportView(txt_plaintext);

        txt_publickey.setColumns(20);
        txt_publickey.setRows(5);
        jScrollPane2.setViewportView(txt_publickey);

        txt_privatekey.setColumns(20);
        txt_privatekey.setRows(5);
        jScrollPane3.setViewportView(txt_privatekey);

        txt_ciphertext.setColumns(20);
        txt_ciphertext.setRows(5);
        jScrollPane4.setViewportView(txt_ciphertext);

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(28, 28, 28)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.TRAILING, false)
                        .addComponent(jLabel3, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, 56, Short.MAX_VALUE)
                        .addComponent(jLabel2, javax.swing.GroupLayout.Alignment.LEADING, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                    .addComponent(jLabel4, javax.swing.GroupLayout.PREFERRED_SIZE, 47, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addComponent(jLabel5))
                .addGap(29, 29, 29)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 110, Short.MAX_VALUE)
                        .addComponent(encrypt))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(generate))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(load))
                    .addGroup(layout.createSequentialGroup()
                        .addComponent(jScrollPane4, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                        .addComponent(decrypt)))
                .addGap(17, 17, 17))
            .addGroup(layout.createSequentialGroup()
                .addGap(215, 215, 215)
                .addComponent(jLabel1, javax.swing.GroupLayout.PREFERRED_SIZE, 151, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(157, 157, 157)
                .addComponent(jLabel3)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                .addComponent(jLabel5)
                .addGap(41, 41, 41))
            .addGroup(layout.createSequentialGroup()
                .addGap(14, 14, 14)
                .addComponent(jLabel1)
                .addGap(34, 34, 34)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                        .addComponent(jLabel2)
                        .addComponent(generate))
                    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 48, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(29, 29, 29)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(load)
                    .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 44, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addGap(29, 29, 29)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
                    .addComponent(jLabel4)
                    .addComponent(encrypt)
                    .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 48, javax.swing.GroupLayout.PREFERRED_SIZE))
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, 37, Short.MAX_VALUE)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jScrollPane4, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
                    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
                        .addComponent(decrypt)
                        .addGap(35, 35, 35))))
        );

        pack();
    }// </editor-fold>//GEN-END:initComponents

    private void generateActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_generateActionPerformed
        // TODO add your handling code here:
        try {
                   KeyPair keyPair = ecc.generateKeyPair();
                   publicKey = keyPair.getPublic();

                    privateKey = keyPair.getPrivate();
                    txt_publickey.setText(Base64.getEncoder()

                            .encodeToString(publicKey.getEncoded()));
                    txt_privatekey.setText (Base64.getEncoder()

                            .encodeToString (privateKey.getEncoded()));

// Save public key to file

                JFileChooser publicKeyChooser = new JFileChooser();

                publicKeyChooser.setDialogTitle ("Save Public Key File");

                int publicKeyChooserResult = publicKeyChooser.showSaveDialog(this);

               if (publicKeyChooserResult == JFileChooser.APPROVE_OPTION) {

                    File publicKeyFile = publicKeyChooser.getSelectedFile();

                try (FileWriter writer = new FileWriter (publicKeyFile.getAbsolutePath())) {

                    writer.write(Base64.getEncoder()

                    .encodeToString(publicKey.getEncoded()));

                        JOptionPane.showMessageDialog(this,

                "Public Key saved to file successfully.",

                "Success", JOptionPane. INFORMATION_MESSAGE );

            } catch 
                    (IOException ex) {

                JOptionPane.showMessageDialog(this,

            "Error saving Public Key file: " + ex.getMessage(),

            "Error", JOptionPane.ERROR_MESSAGE);
            }
               }


            
        } catch (Exception ex) {
            Logger.getLogger(frm_ECC2.class.getName()).log(Level.SEVERE,null,ex);
            JOptionPane.showMessageDialog(this, 
                    "Error generating ECC key pair: "+ex.getMessage(),
                    "ERror",JOptionPane.ERROR_MESSAGE );
        } 
         
    }//GEN-LAST:event_generateActionPerformed

    private void loadActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_loadActionPerformed
        // TODO add your handling code here:
        try {
// Load public key from file
                JFileChooser publicKeyChooser = new JFileChooser();
                publicKeyChooser.setDialogTitle ("Load Public Key File");
                int publicKeyChooserResult = publicKeyChooser.showOpenDialog(this);
                if (publicKeyChooserResult == JFileChooser.APPROVE_OPTION) {
                File publicKeyFile = publicKeyChooser.getSelectedFile();
                byte[] publicKeyBytes = Base64.getDecoder().decode(
                new String(java.nio.file.Files.readAllBytes (publicKeyFile.toPath())));
                publicKey = ECCCipher.loadPublicKey (publicKeyBytes);
                txt_publickey.setText (Base64.getEncoder()
                .encodeToString(publicKey.getEncoded()));
                }
                // Load private key from file
                JFileChooser privateKeyChooser = new JFileChooser();
                privateKeyChooser.setDialogTitle ("Load Private Key File");
                int privateKeyChooserResult = privateKeyChooser.showOpenDialog(this);
                if (privateKeyChooserResult == JFileChooser.APPROVE_OPTION) {
                File privateKeyFile = privateKeyChooser.getSelectedFile();
                byte[] privateKeyBytes = Base64.getDecoder().decode(
                new String(java.nio.file.Files.readAllBytes (privateKeyFile.toPath())));
                privateKey = ECCCipher.loadPrivateKey (privateKeyBytes);
                txt_privatekey.setText (Base64.getEncoder()
                .encodeToString (privateKey.getEncoded()));
                }
                } catch (Exception ex) {
                Logger.getLogger(frm_ECC2.class.getName()).log(Level.SEVERE, null, ex);
                JOptionPane.showMessageDialog(this, "Error loading keys: " + ex.getMessage(),
                "Error", JOptionPane.ERROR_MESSAGE);
                }
    }//GEN-LAST:event_loadActionPerformed

    private void encryptActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_encryptActionPerformed
        // TODO add your handling code here:
         try {

                String plaintext = txt_plaintext.getText ();

                byte[] ciphertext =  ecc.encrypt (plaintext, publicKey);

                txt_ciphertext.setText(Base64.getEncoder().encodeToString(ciphertext));

                } catch (Exception ex) {

                Logger.getLogger(frm_ECC2.class.getName()).log (Level.SEVERE, null, ex);

                JOptionPane.showMessageDialog(this, "Error encrypting:" + ex.getMessage(),

                "Error", JOptionPane. ERROR_MESSAGE);

}
    }//GEN-LAST:event_encryptActionPerformed

    private void decryptActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_decryptActionPerformed
        // TODO add your handling code here:
         try {
                String plaintext = txt_plaintext.getText();
                byte[] ciphertext = ecc.encrypt (plaintext, publicKey);
                txt_ciphertext.setText (Base64.getEncoder().encodeToString (ciphertext));
                } catch (Exception ex) {
                Logger.getLogger(frm_ECC2.class.getName()).log (Level.SEVERE, null, ex);
                JOptionPane.showMessageDialog(this, "Error encrypting: " + ex.getMessage(),
                "Error", JOptionPane. ERROR_MESSAGE);
                }
    }//GEN-LAST:event_decryptActionPerformed

    /**
     * @param args the command line arguments
     */
    public static void main(String args[]) {
        /* Set the Nimbus look and feel */
        //<editor-fold defaultstate="collapsed" desc=" Look and feel setting code (optional) ">
        /* If Nimbus (introduced in Java SE 6) is not available, stay with the default look and feel.
         * For details see http://download.oracle.com/javase/tutorial/uiswing/lookandfeel/plaf.html 
         */
        try {
            for (javax.swing.UIManager.LookAndFeelInfo info : javax.swing.UIManager.getInstalledLookAndFeels()) {
                if ("Nimbus".equals(info.getName())) {
                    javax.swing.UIManager.setLookAndFeel(info.getClassName());
                    break;
                }
            }
        } catch (ClassNotFoundException ex) {
            java.util.logging.Logger.getLogger(frm_ECC2.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (InstantiationException ex) {
            java.util.logging.Logger.getLogger(frm_ECC2.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (IllegalAccessException ex) {
            java.util.logging.Logger.getLogger(frm_ECC2.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        } catch (javax.swing.UnsupportedLookAndFeelException ex) {
            java.util.logging.Logger.getLogger(frm_ECC2.class.getName()).log(java.util.logging.Level.SEVERE, null, ex);
        }
        //</editor-fold>

        /* Create and display the form */
        java.awt.EventQueue.invokeLater(new Runnable() {
            public void run() {
                new frm_ECC2().setVisible(true);
            }
        });
    }

    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JButton decrypt;
    private javax.swing.JButton encrypt;
    private javax.swing.JButton generate;
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JLabel jLabel3;
    private javax.swing.JLabel jLabel4;
    private javax.swing.JLabel jLabel5;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JScrollPane jScrollPane3;
    private javax.swing.JScrollPane jScrollPane4;
    private javax.swing.JButton load;
    private javax.swing.JTextArea txt_ciphertext;
    private javax.swing.JTextArea txt_plaintext;
    private javax.swing.JTextArea txt_privatekey;
    private javax.swing.JTextArea txt_publickey;
    // End of variables declaration//GEN-END:variables
}
