import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.stream.Collectors;
import javax.crypto.KeyGenerator;



public class CipherMain {

    //private static String encryptionFilename = "encrypted" + LocalDateTime.now().getNano() + ".txt";
    //private static String decryptionFilename = "decrypted" + LocalDateTime.now().getNano() + ".txt";

    public static void main(String[] args) throws Exception {

        Key key = null;

        try {
            key = KeyGenerator.getInstance("AES").generateKey();
        } catch (NoSuchAlgorithmException e1) {
            e1.printStackTrace();
        }

        String inputFilename = "1MBFile.txt";
        System.out.println("Reading from file " + inputFilename);
        List<String> lines = Files.readAllLines(Paths.get(inputFilename), StandardCharsets.UTF_8);
        String text = lines.stream().map(Object::toString).collect(Collectors.joining());
        CipherFunctions.performECB(text, key);
        CipherFunctions.performCBC(text, key);
        CipherFunctions.performCTR(text, key);
        CipherFunctions.performCFB(text, key);
        CipherFunctions.performOFB(text, key);
        CipherFunctions.performNewCBC(text, key);

        inputFilename = "100MBFile.txt";
        System.out.println("Reading from file " + inputFilename);
        lines = Files.readAllLines(Paths.get(inputFilename), StandardCharsets.UTF_8);
        text = lines.stream().map(Object::toString).collect(Collectors.joining());
        CipherFunctions.performECB(text, key);
        CipherFunctions.performCBC(text, key);
        CipherFunctions.performCTR(text, key);
        CipherFunctions.performCFB(text, key);
        CipherFunctions.performOFB(text, key);
        CipherFunctions.performNewCBC(text, key);

        inputFilename = "250MBFile.txt";
        System.out.println("Reading from file " + inputFilename);
        lines = Files.readAllLines(Paths.get(inputFilename), StandardCharsets.UTF_8);
        text = lines.stream().map(Object::toString).collect(Collectors.joining());
        CipherFunctions.performECB(text, key);
        CipherFunctions.performCBC(text, key);
        CipherFunctions.performCTR(text, key);
        CipherFunctions.performCFB(text, key);
        CipherFunctions.performOFB(text, key);
        CipherFunctions.performNewCBC(text, key);

        String initVector = "encryptionIntVec";
        String textToTest = "His palms are sweaty, knees weak, arms are heavy";
        Tests.Test(0, textToTest,key,initVector);
        Tests.Test(1, textToTest,key,initVector);
        Tests.Test(5, textToTest,key,initVector);
        Tests.Test(10, textToTest,key,initVector);
        Tests.Test(15, textToTest,key,initVector);

    }
}