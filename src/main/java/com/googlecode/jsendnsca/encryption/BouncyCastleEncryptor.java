package com.googlecode.jsendnsca.encryption;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.modes.CFBBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import static java.lang.System.arraycopy;

/**
 * {@link Encryptor} based on Bouncy Castle {@link BlockCipher}.
 *
 * @author max.schwaab@gmail.com
 */
class BouncyCastleEncryptor implements Encryptor {

    private static final String ASCII_CHARSET = "US-ASCII";

    private final BlockCipher cipherEngine;
    private final int keyBytesLength;

    BouncyCastleEncryptor(final BlockCipher cipherEngine, final int keyBytesLength) {
        this.cipherEngine = cipherEngine;
        this.keyBytesLength = keyBytesLength;
    }

    @Override
    public void encrypt(final byte[] passiveCheckBytes, final byte[] initVectorBytes, final String password) {
        final PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CFBBlockCipher(cipherEngine, 8), new PKCS7Padding());
        final int passiveCheckBytesLength = passiveCheckBytes.length;
        final byte[] key = new byte[keyBytesLength];
        final byte[] iv = new byte[keyBytesLength];

        try {
            final byte[] passwordBytes = password.getBytes(ASCII_CHARSET);

            arraycopy(passwordBytes, 0, key, 0, Math.min(keyBytesLength, passwordBytes.length));
            arraycopy(initVectorBytes, 0, iv, 0, Math.min(keyBytesLength, initVectorBytes.length));

            cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));

            final byte[] cipherText = new byte[cipher.getOutputSize(passiveCheckBytesLength)];

            int cipherLength = cipher.processBytes(passiveCheckBytes, 0, passiveCheckBytesLength, cipherText, 0);
            cipherLength = cipherLength + cipher.doFinal(cipherText, cipherLength);

            final int bytesToCopy = Math.min(passiveCheckBytesLength, cipherLength);
            arraycopy(cipherText, 0, passiveCheckBytes, 0, bytesToCopy);
        } catch (Exception exception) {
            throw new RuntimeException(exception);
        }
    }

}
