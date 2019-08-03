import org.apache.commons.pool2.impl.GenericObjectPool;
import org.apache.commons.pool2.impl.GenericObjectPoolConfig;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Strings;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.Security;

public class AESUtil {

    private static final String ALGORITHM = "AES/CBC/PKCS7Padding";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final IvParameterSpec DEFAULT_IV = new IvParameterSpec(Strings.toUTF8ByteArray("4C39BE859684057F"));

    public byte[] encrypt(byte[] data, SecretKey key) {
        return encrypt(data, key, DEFAULT_IV);
    }

    public byte[] encrypt(byte[] data, SecretKey key, IvParameterSpec ivSpec) {
        return doCrypto(Cipher.ENCRYPT_MODE, data, key, ivSpec);
    }

    public byte[] decrypt(byte[] data, SecretKey key) {
        return decrypt(data, key, DEFAULT_IV);
    }

    public byte[] decrypt(byte[] data, SecretKey key, IvParameterSpec ivSpec) {
        return doCrypto(Cipher.DECRYPT_MODE, data, key, ivSpec);
    }

    private byte[] doCrypto(int cipherMode, byte[] data, SecretKey key, IvParameterSpec ivSpec) {
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(cipherMode, key, ivSpec);
            return cipher.doFinal(data);
        } catch (Exception e) {
            System.out.println("AESUtil {} failed: {}" + (cipherMode == Cipher.ENCRYPT_MODE ? "encrypt" : "decrypt"));
            return null;
        }
    }
}
