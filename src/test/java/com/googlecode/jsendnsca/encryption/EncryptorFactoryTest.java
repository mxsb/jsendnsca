package com.googlecode.jsendnsca.encryption;

import org.bouncycastle.crypto.engines.*;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static com.googlecode.jsendnsca.encryption.BouncyCastleEncryptorMatchers.*;
import static com.googlecode.jsendnsca.encryption.Encryption.*;
import static com.googlecode.jsendnsca.encryption.EncryptorFactory.NullEncryptor;
import static com.googlecode.jsendnsca.encryption.EncryptorFactory.createEncryptor;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertThat;
import static org.junit.rules.ExpectedException.none;

public class EncryptorFactoryTest {

    @Rule
    public ExpectedException expectedException = none();

    @Test
    public void should_throw_on_null_argument() throws Exception {
        expectedException.expect(IllegalArgumentException.class);
        expectedException.expectMessage("Argument [encryption] must not be null");

        createEncryptor(null);
    }

    @Test
    public void should_not_throw_on_supported_encryption_values() throws Exception {
        for(final Encryption encryption : Encryption.values()) {
           createEncryptor(encryption);
        }
    }

    @Test
    public void should_create_NONE_encryptor() throws Exception {
        assertThat(createEncryptor(NONE), instanceOf(NullEncryptor.class));
    }

    @Test
    public void should_create_XOR_encryptor() throws Exception {
        assertThat(createEncryptor(XOR), instanceOf(XorEncryptor.class));
    }

    @Test
    public void should_create_DES_encryptor() throws Exception {
        assertThat((BouncyCastleEncryptor) createEncryptor(DES), allOf(
                cipherEngine(instanceOf(DESEngine.class)),
                keyBytesLengthIs(8)
        ));
    }

    @Test
    public void should_create_TRIPLE_DES_encryptor() throws Exception {
        assertThat((BouncyCastleEncryptor) createEncryptor(TRIPLE_DES), allOf(
                cipherEngine(instanceOf(DESedeEngine.class)),
                keyBytesLengthIs(24)
        ));
    }

    @Test
    public void should_create_CAST128_encryptor() throws Exception {
        assertThat((BouncyCastleEncryptor) createEncryptor(CAST128), allOf(
                cipherEngine(instanceOf(CAST5Engine.class)),
                keyBytesLengthIs(16)
        ));
    }

    @Test
    public void should_create_XTEA_encryptor() throws Exception {
        assertThat((BouncyCastleEncryptor) createEncryptor(XTEA), allOf(
                cipherEngine(instanceOf(XTEAEngine.class)),
                keyBytesLengthIs(16)
        ));
    }

    @Test
    public void should_create_BLOWFISH_encryptor() throws Exception {
        assertThat((BouncyCastleEncryptor) createEncryptor(BLOWFISH), allOf(
                cipherEngine(instanceOf(BlowfishEngine.class)),
                keyBytesLengthIs(56)
        ));
    }

    @Test
    public void should_create_TWOFISH_encryptor() throws Exception {
        assertThat((BouncyCastleEncryptor) createEncryptor(TWOFISH), allOf(
                cipherEngine(instanceOf(TwofishEngine.class)),
                keyBytesLengthIs(32)
        ));
    }

    @Test
    public void should_create_RIJNDAEL128_encryptor() throws Exception {
        assertThat((BouncyCastleEncryptor) createEncryptor(RIJNDAEL128), allOf(
                cipherEngine(instanceOf(RijndaelEngine.class)),
                cipherEngine(blockBitsIs(128)),
                keyBytesLengthIs(32)
        ));
    }

    @Test
    public void should_create_RIJNDAEL192_encryptor() throws Exception {
        assertThat((BouncyCastleEncryptor) createEncryptor(RIJNDAEL192), allOf(
                cipherEngine(instanceOf(RijndaelEngine.class)),
                cipherEngine(blockBitsIs(192)),
                keyBytesLengthIs(32)
        ));
    }

    @Test
    public void should_create_RIJNDAEL256_encryptor() throws Exception {
        assertThat((BouncyCastleEncryptor) createEncryptor(RIJNDAEL256), allOf(
                cipherEngine(instanceOf(RijndaelEngine.class)),
                cipherEngine(blockBitsIs(256)),
                keyBytesLengthIs(32)
        ));
    }

    @Test
    public void should_create_SERPENT_encryptor() throws Exception {
        assertThat((BouncyCastleEncryptor) createEncryptor(SERPENT), allOf(
                cipherEngine(instanceOf(SerpentEngine.class)),
                keyBytesLengthIs(32)
        ));
    }

}