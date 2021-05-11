import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.io.UnsupportedEncodingException;
import java.security.*;
import java.util.Base64;

public class Tests {


    static void Test(int counter, String text, Key key, String initVector) throws Exception
    {
        byte[] cryptogram = null;
        try {
            cryptogram = encryptWithCBC(text, key, initVector);
        } catch (Exception e) {
            e.printStackTrace();
        }
        byte[] newCryptogram = cryptogram;
        for (int i=0;i<counter;i++) newCryptogram[i] = 0;
        var changed = Base64.getEncoder().encodeToString(newCryptogram);
        String decryptedText = decryptWithCBC(cryptogram, key, initVector);
        System.out.println(counter+" = "+ decryptedText+"\n");
    }

    private static byte[] encryptWithCBC(String text, Key key, String paramIv) throws Exception{
        IvParameterSpec iv = new IvParameterSpec(paramIv.getBytes("UTF-8"));
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);

        return cipher.doFinal(text.getBytes());
    }

    private static String decryptWithCBC(byte[] text, Key key, String paramIv) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(paramIv.getBytes("UTF-8"));
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);

        return new String(cipher.doFinal(text));
    }
}


