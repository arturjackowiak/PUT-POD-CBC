import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.time.LocalDateTime;

public class CipherFunctions {

    private static String encryptionFilename = "encrypted" + LocalDateTime.now().getNano() + ".txt";
    private static String decryptionFilename = "decrypted" + LocalDateTime.now().getNano() + ".txt";

    private static byte[] encryptWithECB(String text, Key key) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        return cipher.doFinal(text.getBytes());
    }

    private static String decryptWithECB(byte[] text, Key key)
            throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "SunJCE");
        cipher.init(Cipher.DECRYPT_MODE, key);

        return new String(cipher.doFinal(text));
    }

    private static byte[] encryptWithCBC(String text, Key key, String paramIv) throws Exception{

        IvParameterSpec iv = new IvParameterSpec(paramIv.getBytes("UTF-8"));
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        return cipher.doFinal(text.getBytes());
    }

    private static String decryptWithCBC(byte[] text, Key key, String paramIv)
            throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException,
            InvalidAlgorithmParameterException {

        IvParameterSpec iv = new IvParameterSpec(paramIv.getBytes("UTF-8"));
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        return new String(cipher.doFinal(text));
    }

    private static byte[] encryptWithCTR(String text, Key key, String paramIv) throws Exception {

        IvParameterSpec iv = new IvParameterSpec(paramIv.getBytes("UTF-8"));
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        return cipher.doFinal(text.getBytes());
    }

    private static String decryptWithCTR(byte[] text, Key key, String paramIv) throws Exception {

        IvParameterSpec iv = new IvParameterSpec(paramIv.getBytes("UTF-8"));
        Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        return new String(cipher.doFinal(text));
    }

    private static byte[] encryptWithCFB(String text, Key key, String paramIv) throws Exception {

        IvParameterSpec iv = new IvParameterSpec(paramIv.getBytes("UTF-8"));
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        return cipher.doFinal(text.getBytes());
    }

    private static String decryptWithCFB(byte[] text, Key key, String paramIv) throws Exception {

        IvParameterSpec iv = new IvParameterSpec(paramIv.getBytes("UTF-8"));
        Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        return new String(cipher.doFinal(text));
    }

    private static byte[] encryptWithOFB(String text, Key key, String paramIv) throws Exception {

        IvParameterSpec iv = new IvParameterSpec(paramIv.getBytes("UTF-8"));
        Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        return cipher.doFinal(text.getBytes());
    }

    private static String decryptWithOFB(byte[] text, Key key, String paramIv) throws Exception {

        IvParameterSpec iv = new IvParameterSpec(paramIv.getBytes("UTF-8"));
        Cipher cipher = Cipher.getInstance("AES/OFB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        return new String(cipher.doFinal(text));
    }

    static void performECB(String text, Key key) throws IOException {
        System.out.println("Encrypting using ECB");

        long start = System.nanoTime();
        byte[] cryptogram = null;
        try {
            cryptogram = encryptWithECB(text, key);
        } catch (Exception e) {
            e.printStackTrace();
        }
        long finish = System.nanoTime();
        System.out.println("Encrypting using ECB time elapsed = " + (finish - start)/1000000000);

        System.out.println("Decrypting using ECB");
        start = System.nanoTime();
        String decryptedText = "";
        try {
            decryptedText = decryptWithECB(cryptogram, key);
        } catch (Exception e) {
            e.printStackTrace();
        }
        finish = System.nanoTime();
        System.out.println("Decrypting using ECB time elapsed = " + (finish - start)/1000000000);

        System.out.println("Writing to files");
        //Files.write(Paths.get("ECB" + encryptionFilename), cryptogram);
        //Files.write(Paths.get("ECB" + decryptionFilename), decryptedText.getBytes());
    }

    static void performCBC(String text, Key key) throws IOException {
        System.out.println("Encrypting using CBC");
        String initVector = "encryptionIntVec";

        long start = System.nanoTime();
        byte[] cryptogram = null;
        try {
            cryptogram = encryptWithCBC(text, key, initVector);
        } catch (Exception e) {
            e.printStackTrace();
        }
        long finish = System.nanoTime();
        System.out.println("Encrypting using CBC time elapsed = " + (finish - start)/1000000000);

        System.out.println("Decrypting using CBC");
        start = System.nanoTime();
        String decryptedText = "";
        try {
            decryptedText = decryptWithCBC(cryptogram, key, initVector);
        } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException
                | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
        }
        finish = System.nanoTime();
        System.out.println("Decrypting using CBC time elapsed = " + (finish - start)/1000000000);

        System.out.println("Writing to files");
        //Files.write(Paths.get("CBC" + encryptionFilename), cryptogram);
        //Files.write(Paths.get("CBC" + decryptionFilename), decryptedText.getBytes());
    }

    static void performCTR(String text, Key key) throws IOException {
        System.out.println("Encrypting using CTR");
        String initVector = "encryptionIntVec";

        long start = System.nanoTime();
        byte[] cryptogram = null;
        try {
            cryptogram = encryptWithCTR(text, key, initVector);
        } catch (Exception e) {
            e.printStackTrace();
        }
        long finish = System.nanoTime();
        System.out.println("Encrypting using CTR time elapsed = " + (finish - start)/1000000000);

        System.out.println("Decrypting using CTR");
        start = System.nanoTime();
        String decryptedText = "";
        try {
            decryptedText = decryptWithCTR(cryptogram, key, initVector);
        } catch (Exception e) {
            e.printStackTrace();
        }
        finish = System.nanoTime();
        System.out.println("Decrypting using CTR time elapsed = " + (finish - start)/1000000000);

        System.out.println("Writing to files");
        // Files.write(Paths.get("CTR" + encryptionFilename), cryptogram);
        //Files.write(Paths.get("CTR" + decryptionFilename), decryptedText.getBytes());
    }

    static void performCFB(String text, Key key) throws IOException {
        System.out.println("Encrypting using CFB");
        String initVector = "encryptionIntVec";

        long start = System.nanoTime();
        byte[] cryptogram = null;
        try {
            cryptogram = encryptWithCFB(text, key, initVector);
        } catch (Exception e) {
            e.printStackTrace();
        }
        long finish = System.nanoTime();
        System.out.println("Encrypting using CFB time elapsed = " + (finish - start)/1000000000);

        System.out.println("Decrypting using CFB");
        start = System.nanoTime();
        String decryptedText = "";
        try {
            decryptedText = decryptWithCFB(cryptogram, key, initVector);
        } catch (Exception e) {
            e.printStackTrace();
        }
        finish = System.nanoTime();
        System.out.println("Decrypting using CFB time elapsed = " + (finish - start)/1000000000);

        System.out.println("Writing to files");
        //Files.write(Paths.get("CFB" + encryptionFilename), cryptogram);
        //Files.write(Paths.get("CFB" + decryptionFilename), decryptedText.getBytes());
    }

    static void performOFB(String text, Key key) throws IOException {
        System.out.println("Encrypting using OFB");
        String initVector = "encryptionIntVec";

        long start = System.nanoTime();
        byte[] cryptogram = null;
        try {
            cryptogram = encryptWithOFB(text, key, initVector);
        } catch (Exception e) {
            e.printStackTrace();
        }
        long finish = System.nanoTime();
        System.out.println("Encrypting using OFB time elapsed = " + (finish - start)/1000000000);

        System.out.println("Decrypting using OFB");
        start = System.nanoTime();
        String decryptedText = "";
        try {
            decryptedText = decryptWithOFB(cryptogram, key, initVector);
        } catch (Exception e) {
            e.printStackTrace();
        }
        finish = System.nanoTime();
        System.out.println("Decrypting using OFB time elapsed = " + (finish - start)/1000000000);

        System.out.println("Writing to files");
        //Files.write(Paths.get("OFB" + encryptionFilename), cryptogram);
        //Files.write(Paths.get("OFB" + decryptionFilename), decryptedText.getBytes());
    }

    static void performNewCBC(String text, Key key) throws IOException {
        System.out.println("Encrypting using OFB");
        String initVector = "encryptionIntVec";

        long start = System.nanoTime();
        byte[] cryptogram = null;
        try {
            cryptogram = CBC.encrypt(text.getBytes(), key, initVector);
        } catch (Exception e) {
            e.printStackTrace();
        }

        long finish = System.nanoTime();
        System.out.println("Encrypting using OFB time elapsed = " + (finish - start));

        System.out.println("Decrypting using OFB");
        start = System.nanoTime();
        byte[] decryptedText = null;
        try {
            decryptedText = CBC.decrypt(cryptogram, key, initVector);
        } catch (Exception e) {
            e.printStackTrace();
        }
        finish = System.nanoTime();
        System.out.println("Decrypting using OFB time elapsed = " + (finish - start));

        System.out.println("Writing to files");
        //Files.write(Paths.get("OFB" + encryptionFilename), cryptogram);
        //Files.write(Paths.get("OFB" + decryptionFilename), decryptedText);
    }



}
