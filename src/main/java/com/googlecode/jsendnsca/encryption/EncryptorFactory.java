package com.googlecode.jsendnsca.encryption;

import org.bouncycastle.crypto.engines.*;

/**
 * Factory to create an {@link Encryptor} from an {@link Encryption}.
 *
 * @author max.schwaab@gmail.com
 */
public class EncryptorFactory {

    private EncryptorFactory() {}

    public static Encryptor createEncryptor(final Encryption encryption) {
        if(encryption == null) {
            throw new IllegalArgumentException("Argument [encryption] must not be null");
        }

        final Encryptor encryptor;

        switch(encryption) {
            case NONE:
                encryptor = new NullEncryptor();
                break;
            case XOR:
                encryptor = new XorEncryptor();
                break;
            case DES:
                encryptor = new BouncyCastleEncryptor(new DESEngine(), 8);
                break;
            case TRIPLE_DES:
                encryptor = new BouncyCastleEncryptor(new DESedeEngine(), 24);
                break;
            case CAST128:
                encryptor = new BouncyCastleEncryptor(new CAST5Engine(), 16);
                break;
            case XTEA:
                encryptor = new BouncyCastleEncryptor(new XTEAEngine(), 16);
                break;
            case BLOWFISH:
                encryptor = new BouncyCastleEncryptor(new BlowfishEngine(), 56);
                break;
            case TWOFISH:
                encryptor = new BouncyCastleEncryptor(new TwofishEngine(), 32);
                break;
            case RIJNDAEL128:
                encryptor = new BouncyCastleEncryptor(new RijndaelEngine(128), 32);
                break;
            case RIJNDAEL192:
                encryptor = new BouncyCastleEncryptor(new RijndaelEngine(192), 32);
                break;
            case RIJNDAEL256:
                encryptor = new BouncyCastleEncryptor(new RijndaelEngine(256), 32);
                break;
            case SERPENT:
                encryptor = new BouncyCastleEncryptor(new SerpentEngine(), 32);
                break;
            default:
                throw new IllegalArgumentException("Unsupported encryption [" + encryption + "]");
        }

        return encryptor;
    }

    static class NullEncryptor implements Encryptor {

        @Override
        public void encrypt(final byte[] passiveCheckBytes, final byte[] initVector, final String password) {
//            Do nothing
        }

    }

}
