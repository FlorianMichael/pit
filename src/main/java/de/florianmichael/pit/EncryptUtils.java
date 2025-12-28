/*
 * This file is part of pit - https://github.com/FlorianMichael/pit
 * Copyright (C) 2025-2026 FlorianMichael/EnZaXD <git@florianmichael.de> and contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package de.florianmichael.pit;

import java.io.ByteArrayOutputStream;
import java.security.SecureRandom;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import static de.florianmichael.pit.KeyUtils.deriveKey;

/**
 * Content encryption and decryption. Interactions with encrypted files are {@link FileUtils} methods.
 */
public final class EncryptUtils {

    public static final int SALT_LENGTH = 16;

    /**
     * Decrypts a file that was encrypted with the specified password.
     *
     * @param bytes    the encrypted file as a byte array
     * @param password the password used for decryption
     * @return the decrypted file content as a byte array
     * @throws Exception if an error occurs during decryption
     */
    public static byte[] decryptBytes(final byte[] bytes, final String password) throws Exception {
        if (bytes.length < SALT_LENGTH + 16) {
            throw new IllegalArgumentException("Encrypted entry is too short to be valid.");
        }

        final byte[] salt = Arrays.copyOfRange(bytes, 0, SALT_LENGTH);
        final byte[] iv = Arrays.copyOfRange(bytes, SALT_LENGTH, SALT_LENGTH + 16);
        final byte[] encryptedData = Arrays.copyOfRange(bytes, SALT_LENGTH + 16, bytes.length);

        final SecretKey key = deriveKey(password, salt);
        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(encryptedData);
    }

    /**
     * Encrypts a byte array using AES encryption with a derived key from the given password.
     *
     * @param bytes    the byte array to encrypt
     * @param password the password to derive the encryption key
     * @return the encrypted byte array, which includes the salt and IV prepended to the encrypted data
     * @throws Exception if an error occurs during encryption
     */
    public static byte[] encryptBytes(final byte[] bytes, final String password) throws Exception {
        final byte[] salt = new byte[SALT_LENGTH];
        final byte[] iv = new byte[16];
        new SecureRandom().nextBytes(salt);
        new SecureRandom().nextBytes(iv);

        final SecretKey key = deriveKey(password, salt);
        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        final byte[] encryptedData = cipher.doFinal(bytes);

        final ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(salt);
        stream.write(iv);
        stream.write(encryptedData);

        return stream.toByteArray();
    }

}
