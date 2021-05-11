import java.security.Key;
import javax.crypto.Cipher;

public class CBC {

    private static final int BLOCK_LENGTH = 16;

    private static byte[] encryptWithECB(byte[] text, Key key) throws Exception {

        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", "SunJCE");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] result = cipher.doFinal(text);

        return result;
    }

    private static byte[] decryptWithECB(byte[] text, Key key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", "SunJCE");
        cipher.init(Cipher.DECRYPT_MODE, key);

        return cipher.doFinal(text);
    }

    public static byte xor(byte x, byte y) {
        int xInt = (int) x;
        int yInt = (int) y;

        int result = xInt^yInt;
        return (byte)(0xff & result);
    }

    public static byte[] xor(byte[] x, byte[] y) {
        byte[] result = new byte[x.length];
        for (int i = 0; i < x.length; i++) {
            result[i] = xor(x[i], y[i]);
        }

        return result;
    }

    private static byte[] getBlock(int startIndex, byte[] bytes) {
        byte[] result = new byte[BLOCK_LENGTH];

        for (int i = 0; i + startIndex < bytes.length && i < BLOCK_LENGTH; i++) {
            result[i] = bytes[startIndex + i];
        }

        return result;
    }

    private static byte[] padding(byte[] text) {
        int modulo = text.length % BLOCK_LENGTH;

        if(modulo == 0) return text;

        int missingLength = BLOCK_LENGTH - modulo;
        int resultLength = text.length + missingLength;
        byte[] result = new byte[resultLength];

        for (int i = 0; i < text.length; i++) {
            result[i] = text[i];
        }

        for (int i = text.length; i < resultLength; i++) {
            result[i] = 0x00;
        }

        return result;
    }

    public static byte[] encrypt(byte[] text, Key key, String initVector) throws Exception {
        byte[] lastBlock = initVector.getBytes();
        text = padding(text);
        lastBlock = padding(lastBlock);
        byte[] result = new byte[text.length];

        for (int i = 0; i < text.length; i+=BLOCK_LENGTH) {
            byte[] block = getBlock(i, text);
            byte[] toEncrypt = xor(block, lastBlock);
            lastBlock = encryptWithECB(toEncrypt, key);

            for (int j = i; j < i + BLOCK_LENGTH; j++) {
                result[j] = lastBlock[j-i];
            }

        }

        System.out.println("Zaszyfrowane przez CTR: "+ result);
        return result;
    }

    public static byte[] decrypt(byte[] cryptogram, Key key, String initVector) throws Exception {
        byte[] lastBlock = initVector.getBytes();
        cryptogram = padding(cryptogram);
        lastBlock = padding(lastBlock);
        byte[] result = new byte[cryptogram.length];

        for (int i = 0; i < cryptogram.length; i+=BLOCK_LENGTH) {
            byte[] block = getBlock(i, cryptogram);
            byte[] decrypted = decryptWithECB(block, key);
            decrypted = xor(decrypted, lastBlock);
            lastBlock = block;

            for (int j = i; j < i + BLOCK_LENGTH; j++) {
                result[j] = decrypted[j-i];
            }

        }

        System.out.println("Odszyfrowane przez CTR: "+ result);
        return result;
    }
}