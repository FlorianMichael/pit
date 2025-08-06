/*
 * This file is part of pit - https://github.com/FlorianMichael/pit
 * Copyright (C) 2025 FlorianMichael/EnZaXD <florian.michael07@gmail.com> and contributors
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
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import static de.florianmichael.pit.KeyUtils.deriveKey;

public final class FileUtils {

    public static final int SALT_LENGTH = 16;

    /**
     * Encrypts a vault containing multiple files into a single encrypted ZIP file.
     *
     * @param files    a map of file names to their byte content
     * @param output   the output file where the encrypted vault will be saved
     * @param password the password used for encryption
     * @throws Exception if an error occurs during encryption
     */
    public static void encryptVault(final Map<String, byte[]> files, final File output, final String password) throws Exception {
        final byte[] salt = new byte[SALT_LENGTH];
        final byte[] iv = new byte[16];
        new SecureRandom().nextBytes(salt);
        new SecureRandom().nextBytes(iv);

        final SecretKey key = deriveKey(password, salt);
        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));

        try (final FileOutputStream fos = new FileOutputStream(output)) {
            fos.write(salt);
            fos.write(iv);

            try (final CipherOutputStream cos = new CipherOutputStream(fos, cipher);
                 final ZipOutputStream zos = new ZipOutputStream(cos)) {

                for (final Map.Entry<String, byte[]> entry : files.entrySet()) {
                    writeEncryptedZipEntry(zos, entry.getKey(), entry.getValue(), password);
                }
            }
        }
    }

    /**
     * Decrypts a vault from an encrypted ZIP file and returns the files as a map.
     *
     * @param file     the encrypted vault file
     * @param password the password used for decryption
     * @return a map of file names to their decrypted byte content
     * @throws Exception if an error occurs during decryption
     */
    public static Map<String, byte[]> decryptVault(final File file, final String password) throws Exception {
        try (final FileInputStream fis = new FileInputStream(file)) {
            final byte[] salt = fis.readNBytes(SALT_LENGTH);
            final byte[] iv = fis.readNBytes(16);

            final SecretKey key = deriveKey(password, salt);
            final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

            try (final CipherInputStream cis = new CipherInputStream(fis, cipher);
                 final ZipInputStream zis = new ZipInputStream(cis)) {

                final Map<String, byte[]> result = new HashMap<>();
                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    if (entry.isDirectory()) {
                        continue;
                    }

                    final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                    zis.transferTo(buffer);
                    result.put(entry.getName(), decryptBytes(buffer.toByteArray(), password));
                }

                return result;
            }
        }
    }

    /**
     * Decrypts a specific entry from an encrypted vault file.
     *
     * @param vaultFile the encrypted vault file
     * @param entryName the name of the entry to decrypt
     * @param password  the password used for decryption
     * @return the decrypted content of the entry as a byte array
     * @throws Exception if an error occurs during decryption or if the entry is not found
     */
    public static byte[] decryptEntry(final File vaultFile, final String entryName, final String password) throws Exception {
        try (final FileInputStream fis = new FileInputStream(vaultFile)) {
            final byte[] salt = fis.readNBytes(SALT_LENGTH);
            final byte[] iv = fis.readNBytes(16);

            final SecretKey key = deriveKey(password, salt);
            final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

            try (final CipherInputStream cis = new CipherInputStream(fis, cipher);
                 final ZipInputStream zis = new ZipInputStream(cis)) {

                ZipEntry entry;
                while ((entry = zis.getNextEntry()) != null) {
                    if (entry.isDirectory()) {
                        continue;
                    }

                    if (!entry.getName().equals(entryName)) {
                        continue;
                    }

                    final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                    zis.transferTo(buffer);
                    return decryptBytes(buffer.toByteArray(), password);
                }
            }
        }

        throw new IOException("Entry not found or not a file: " + entryName);
    }

    /**
     * Writes an encrypted entry to a ZIP output stream.
     *
     * @param zos      the ZipOutputStream to write to
     * @param name     the name of the entry in the ZIP file
     * @param content  the content of the entry as a byte array
     * @param password the password used for encryption
     * @throws Exception if an error occurs during encryption or writing
     */
    public static void writeEncryptedZipEntry(final ZipOutputStream zos, String name, final byte[] content, final String password) throws Exception {
        final byte[] salt = new byte[SALT_LENGTH];
        final byte[] iv = new byte[16];
        new SecureRandom().nextBytes(salt);
        new SecureRandom().nextBytes(iv);

        final SecretKey key = deriveKey(password, salt);
        final Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        final byte[] encryptedData = cipher.doFinal(content);

        final ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(salt);
        stream.write(iv);
        stream.write(encryptedData);

        final ZipEntry zipEntry = new ZipEntry(name);
        zos.putNextEntry(zipEntry);
        zos.write(stream.toByteArray());
        zos.closeEntry();
    }

    /**
     * Decrypts a file that was encrypted with the specified password.
     *
     * @param bytes    the encrypted file as a byte array
     * @param password the password used for decryption
     * @return the decrypted file content as a byte array
     * @throws Exception if an error occurs during decryption
     */
    private static byte[] decryptBytes(final byte[] bytes, final String password) throws Exception {
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
     * Adds a new entry to the archive, overriding any existing entry with the same name.
     *
     * @param archive   the archive file to modify
     * @param entryName the name of the entry to add
     * @param content   the content of the entry as a byte array
     * @param password  the password used for encryption
     * @throws Exception if an error occurs during processing
     */
    public static void addEntry(File archive, String entryName, byte[] content, String password) throws Exception {
        processArchiveEntryModification(archive, password, (zis, zos) -> {
            Set<String> written = new HashSet<>();
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.getName().equals(entryName)) {
                    continue; // override
                }

                copyZipEntry(zis, zos, entry);
                written.add(entry.getName());
            }

            if (!written.contains(entryName)) {
                writeEncryptedZipEntry(zos, entryName, content, password);
            }
        });
    }

    /**
     * Removes an entry from the archive by skipping it during the copy process.
     *
     * @param archive   the archive file to modify
     * @param entryName the name of the entry to remove
     * @param password  the password used for encryption
     * @throws Exception if an error occurs during processing
     */
    public static void removeEntry(final File archive, final String entryName, final String password) throws Exception {
        processArchiveEntryModification(archive, password, (zis, zos) -> {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.getName().equals(entryName)) {
                    continue; // skip it
                }

                copyZipEntry(zis, zos, entry);
            }
        });
    }

    /**
     * Renames an entry in the archive by copying its content to a new entry with the new name
     *
     * @param archive  the archive file to modify
     * @param oldName  the name of the entry to rename
     * @param newName  the new name for the entry
     * @param password the password used for encryption
     * @throws Exception if an error occurs during processing
     */
    public static void renameEntry(final File archive, final String oldName, final String newName, final String password) throws Exception {
        processArchiveEntryModification(archive, password, (zis, zos) -> {
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.getName().equals(oldName)) {
                    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                    zis.transferTo(buffer);
                    byte[] decrypted = decryptBytes(buffer.toByteArray(), password);
                    writeEncryptedZipEntry(zos, newName, decrypted, password);
                } else {
                    copyZipEntry(zis, zos, entry);
                }
            }
        });
    }

    /**
     * Edits an entry in the archive by replacing its content with new content.
     *
     * @param archive    the archive file to modify
     * @param entryName  the name of the entry to edit
     * @param newContent the new content to write to the entry
     * @param password   the password used for encryption
     * @throws Exception if an error occurs during processing
     */
    public static void editEntry(final File archive, final String entryName, final byte[] newContent, final String password) throws Exception {
        processArchiveEntryModification(archive, password, (zis, zos) -> {
            boolean found = false;
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {
                if (entry.getName().equals(entryName)) {
                    ByteArrayOutputStream buffer = new ByteArrayOutputStream();
                    zis.transferTo(buffer);
                    writeEncryptedZipEntry(zos, entryName, newContent, password);
                    found = true;
                } else {
                    copyZipEntry(zis, zos, entry);
                }
            }
            if (!found) {
                throw new IOException("Entry to edit not found: " + entryName);
            }
        });
    }

    /**
     * Processes an archive entry modification by reading the existing entries,
     * applying the specified modifier, and writing the modified entries to a new archive.
     *
     * @param archive  the archive file to modify
     * @param password the password used for encryption/decryption
     * @param modifier the modifier that applies changes to the entries
     * @throws Exception if an error occurs during processing
     */
    private static void processArchiveEntryModification(final File archive, final String password, final ArchiveModifier modifier) throws Exception {
        final File tempOutput = File.createTempFile("vault_modified", ".pit");

        try (
            final FileInputStream fis = new FileInputStream(archive);
            final FileOutputStream fos = new FileOutputStream(tempOutput)
        ) {
            final byte[] salt = fis.readNBytes(SALT_LENGTH);
            final byte[] iv = fis.readNBytes(16);

            final SecretKey key = deriveKey(password, salt);
            final Cipher decryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            decryptCipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));

            final Cipher encryptCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            final byte[] newSalt = new byte[SALT_LENGTH];
            final byte[] newIv = new byte[16];
            new SecureRandom().nextBytes(newSalt);
            new SecureRandom().nextBytes(newIv);
            final SecretKey newKey = deriveKey(password, newSalt);
            encryptCipher.init(Cipher.ENCRYPT_MODE, newKey, new IvParameterSpec(newIv));

            fos.write(newSalt);
            fos.write(newIv);

            try (
                final CipherInputStream cis = new CipherInputStream(fis, decryptCipher);
                final ZipInputStream zis = new ZipInputStream(cis);
                final CipherOutputStream cos = new CipherOutputStream(fos, encryptCipher);
                final ZipOutputStream zos = new ZipOutputStream(cos)
            ) {
                modifier.apply(zis, zos);
            }
        }

        Files.move(tempOutput.toPath(), archive.toPath(), java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }

    private static void copyZipEntry(ZipInputStream zis, ZipOutputStream zos, ZipEntry entry) throws IOException {
        zos.putNextEntry(new ZipEntry(entry.getName()));
        zis.transferTo(zos);
        zos.closeEntry();
    }

    @FunctionalInterface
    private interface ArchiveModifier {

        void apply(final ZipInputStream zis, final ZipOutputStream zos) throws Exception;

    }

}
