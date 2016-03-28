package com.googlecode.jsendnsca.mocks;

public class XorDecryptor implements Decryptor {

    private static final int INITIALISATION_VECTOR_SIZE = 128;

    @Override
    public void decrypt(final byte[] passiveCheckBytes, final byte[] initVector, final String password) {
        if (password != null) {
            byte[] myPasswordBytes = password.getBytes();

            for (int y = 0, x = 0; y < passiveCheckBytes.length; y++, x++) {
                if (x >= myPasswordBytes.length) {
                    x = 0;
                }
                passiveCheckBytes[y] ^= myPasswordBytes[x];
            }
        }
        for (int y = 0, x = 0; y < passiveCheckBytes.length; y++, x++) {
            if (x >= INITIALISATION_VECTOR_SIZE) {
                x = 0;
            }
            passiveCheckBytes[y] ^= initVector[x];
        }
    }

}
