package com.googlecode.jsendnsca.encryption;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.RijndaelEngine;
import org.hamcrest.FeatureMatcher;
import org.hamcrest.Matcher;

import java.lang.reflect.Field;

import static org.hamcrest.Matchers.is;

/**
 * Matcher collection to test {@link BouncyCastleEncryptor}s.
 *
 * @author max.schwaab@gmail.com
 */
public class BouncyCastleEncryptorMatchers {

    @SuppressWarnings("unchecked")
    public static Matcher<BouncyCastleEncryptor> cipherEngine(final Matcher matcher) {
        return new FeatureMatcher<BouncyCastleEncryptor, BlockCipher>(matcher, "cipherEngine", "cipherEngine") {

            @Override
            protected BlockCipher featureValueOf(final BouncyCastleEncryptor encryptor) {
                try {
                    final Field cipherEngine = encryptor.getClass().getDeclaredField("cipherEngine");

                    cipherEngine.setAccessible(true);

                    return (BlockCipher) cipherEngine.get(encryptor);
                } catch(final ReflectiveOperationException exception) {
                    throw new RuntimeException(exception);
                }
            }

        };
    }

    public static Matcher<BouncyCastleEncryptor> keyBytesLengthIs(final int keyBytesLength) {
        return new FeatureMatcher<BouncyCastleEncryptor, Integer>(is(keyBytesLength), "keyBytesLength", "keyBytesLength") {
            @Override
            protected Integer featureValueOf(final BouncyCastleEncryptor encryptor) {
                try {
                    final Field cipherEngine = encryptor.getClass().getDeclaredField("keyBytesLength");

                    cipherEngine.setAccessible(true);

                    return (Integer) cipherEngine.get(encryptor);
                } catch(final ReflectiveOperationException exception) {
                    throw new RuntimeException(exception);
                }
            }
        };
    }

    public static Matcher<RijndaelEngine> blockBitsIs(final int blockBits) {
        return new FeatureMatcher<RijndaelEngine, Integer>(is(blockBits), "blockBits", "blockBits") {
            @Override
            protected Integer featureValueOf(final RijndaelEngine rijndaelEngine) {
                try {
                    final Field bc = rijndaelEngine.getClass().getDeclaredField("BC");

                    bc.setAccessible(true);

                    final Integer bcValue = (Integer) bc.get(rijndaelEngine);
                    final Integer blockBitsValue;
                    switch(bcValue) {
                        case 32:
                            blockBitsValue = 128;
                            break;
                        case 48:
                            blockBitsValue = 192;
                            break;
                        case 64:
                            blockBitsValue = 256;
                            break;
                        default:
                            throw new IllegalArgumentException("Unsupported blockBits size [" + blockBits + "]");
                    }

                    return blockBitsValue;
                } catch(final ReflectiveOperationException exception) {
                    throw new RuntimeException(exception);
                }
            }
        };
    }

}
