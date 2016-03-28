package com.googlecode.jsendnsca.mocks;

public interface Decryptor {

    void decrypt(byte[] passiveCheckBytes, byte[] initVector, String password);

}
